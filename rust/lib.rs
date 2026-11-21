use std::collections::BTreeMap;
use std::sync::OnceLock;

use omnibuf_core::field0::SchemaMeta as CoreSchemaMeta;
use omnibuf_core::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_EXTENDED, WIRE_FIXED32,
    WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32, WIRE_SFIXED64, WIRE_STRING,
    WIRE_SUB_MSG, WIRE_UINT, decode_varint, fast_skip_value, parse_array_header, parse_map_header,
    read_len_slice, skip_value, validate_utf8,
};
use pyo3::exceptions::PyValueError;
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PySequence, PyString, PyType};

mod blind;
mod codec;
mod opaque;

use blind::{decode_blind_json_py, decode_blind_py};
use codec::{
    CompiledCodec, marshal_dataclass_py, register_dataclass_codec_py, set_dataclass_resolver_py,
    unmarshal_dataclass_py,
};
use opaque::{
    OpaqueView, opaque_get_bool_py, opaque_get_bytes_py, opaque_get_fixed32_py,
    opaque_get_fixed64_py, opaque_get_float32_py, opaque_get_float64_py, opaque_get_sfixed32_py,
    opaque_get_sfixed64_py, opaque_get_sint32_py, opaque_get_sint64_py, opaque_get_string_py,
    opaque_get_submsg_slice_py, opaque_get_uint32_py, opaque_get_uint64_py,
};

pub(crate) const DEFAULT_MAX_ELEMENTS: usize = 4_194_304;

static ENCODE_ERR_CLS: OnceLock<Py<PyType>> = OnceLock::new();
static DECODE_ERR_CLS: OnceLock<Py<PyType>> = OnceLock::new();

#[cold]
#[inline(never)]
pub fn encode_err(py: Python<'_>, msg: impl Into<String>) -> PyErr {
    let text = msg.into();
    if let Some(cls) = ENCODE_ERR_CLS.get()
        && let Ok(inst) = cls.bind(py).call1((&text,))
    {
        return PyErr::from_value(inst);
    }
    PyValueError::new_err(text)
}

#[cold]
#[inline(never)]
pub fn decode_err(py: Python<'_>, msg: impl Into<String>) -> PyErr {
    let text = msg.into();
    if let Some(cls) = DECODE_ERR_CLS.get()
        && let Ok(inst) = cls.bind(py).call1((&text,))
    {
        return PyErr::from_value(inst);
    }
    PyValueError::new_err(text)
}

pub(crate) struct DecodeBudget {
    pub remaining: usize,
    pub limit: usize,
}

impl DecodeBudget {
    #[inline]
    pub fn new(py: Python<'_>, max_elements: isize) -> PyResult<Self> {
        if max_elements < 0 {
            return Err(decode_err(
                py,
                format!("omnibuf: max_elements must be non-negative, got {max_elements}"),
            ));
        }
        let limit = max_elements as usize;
        Ok(Self {
            remaining: limit,
            limit,
        })
    }

    #[inline]
    pub fn default_budget() -> Self {
        Self {
            remaining: DEFAULT_MAX_ELEMENTS,
            limit: DEFAULT_MAX_ELEMENTS,
        }
    }

    #[inline]
    pub fn consume(&mut self, py: Python<'_>, count: usize) -> PyResult<()> {
        if count > self.remaining {
            return Err(decode_err(
                py,
                format!(
                    "omnibuf: container element count exceeds max_elements budget ({})",
                    self.limit
                ),
            ));
        }
        self.remaining -= count;
        Ok(())
    }
}

#[inline]
pub(crate) fn extract_max_elements(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
) -> PyResult<DecodeBudget> {
    if unsafe { ffi::PyBool_Check(obj.as_ptr()) != 0 } {
        return Err(decode_err(
            py,
            "omnibuf: max_elements expected int, got bool",
        ));
    }
    let val: isize = obj
        .extract()
        .map_err(|e| decode_err(py, format!("omnibuf: invalid max_elements: {e}")))?;
    DecodeBudget::new(py, val)
}

/// Safe leaf view over `bytes` (zero-copy) or any buffer-protocol object (`PyObject_GetBuffer`
/// with `PyBUF_SIMPLE`, pinning `bytearray` exports via `ob_exports` until `Drop`).
///
/// Only hold `LeafBytes` across pure Rust operations that do not invoke arbitrary Python callbacks
/// capable of mutating the underlying buffer in-place.
pub(crate) struct LeafBytes<'py> {
    ptr: *const u8,
    len: usize,
    view: Option<ffi::Py_buffer>,
    _owner: Option<Py<PyAny>>,
    _marker: std::marker::PhantomData<&'py [u8]>,
}

impl<'py> LeafBytes<'py> {
    #[inline]
    pub(crate) fn extract(py: Python<'py>, obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        let obj_ptr = obj.as_ptr();
        unsafe {
            if ffi::PyBytes_CheckExact(obj_ptr) != 0 {
                let len = ffi::PyBytes_Size(obj_ptr) as usize;
                let ptr = if len == 0 {
                    std::ptr::NonNull::<u8>::dangling().as_ptr()
                } else {
                    ffi::PyBytes_AS_STRING(obj_ptr).cast::<u8>()
                };
                return Ok(Self {
                    ptr,
                    len,
                    view: None,
                    _owner: Some(obj.clone().unbind()),
                    _marker: std::marker::PhantomData,
                });
            }

            let mut buf = std::mem::MaybeUninit::<ffi::Py_buffer>::zeroed();
            if ffi::PyObject_GetBuffer(obj_ptr, buf.as_mut_ptr(), ffi::PyBUF_SIMPLE) != 0 {
                return Err(PyErr::fetch(py));
            }
            let buf = buf.assume_init();
            let len = buf.len as usize;
            let ptr = if len == 0 || buf.buf.is_null() {
                std::ptr::NonNull::<u8>::dangling().as_ptr()
            } else {
                buf.buf.cast::<u8>()
            };
            Ok(Self {
                ptr,
                len,
                view: Some(buf),
                _owner: None,
                _marker: std::marker::PhantomData,
            })
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for LeafBytes<'_> {
    #[inline]
    fn drop(&mut self) {
        if let Some(ref mut view) = self.view {
            unsafe {
                ffi::PyBuffer_Release(view);
            }
        }
    }
}

/// Safe input buffer for operations that may invoke arbitrary Python code (`__init__`,
/// `default_factory`, `enum_cls`, `__setattr__`, sequence/mapping iteration).
///
/// Zero-copy for immutable exact `bytes`; snapshots `bytearray`/`memoryview` upfront and
/// releases the `Py_buffer` export immediately so Python code can freely mutate or resize
/// the caller's buffer without UAF or mid-parse data races.
pub(crate) enum InputBytes<'py> {
    Borrowed(LeafBytes<'py>),
    Owned(Vec<u8>),
}

impl<'py> InputBytes<'py> {
    #[inline]
    pub(crate) fn extract(py: Python<'py>, obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        let leaf = LeafBytes::extract(py, obj)?;
        if leaf.view.is_none() {
            return Ok(Self::Borrowed(leaf));
        }
        let vec = leaf.as_slice().to_vec();
        drop(leaf);
        Ok(Self::Owned(vec))
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s.as_slice(),
            Self::Owned(v) => v.as_slice(),
        }
    }
}

/// Immutable `PyBytes`-pinned byte range used by `OpaqueView` and `zero_copy_bytes` decoding.
///
/// Zero-copy for `bytes` and contiguous 1D read-only `memoryview`s backed by `bytes`; snapshots
/// mutable buffers once into an immutable `PyBytes` object so views and sub-views never copy again.
pub(crate) struct ByteSliceOwner {
    pub owner: Py<PyBytes>,
    pub start: usize,
    pub end: usize,
}

impl ByteSliceOwner {
    #[inline]
    pub fn from_py_any(py: Python<'_>, raw: &Bound<'_, PyAny>) -> PyResult<Self> {
        let raw_ptr = raw.as_ptr();
        unsafe {
            if ffi::PyBytes_CheckExact(raw_ptr) != 0 {
                let len = ffi::PyBytes_Size(raw_ptr) as usize;
                let pb = raw.cast_unchecked::<PyBytes>().clone().unbind();
                return Ok(Self {
                    owner: pb,
                    start: 0,
                    end: len,
                });
            }
            if ffi::PyMemoryView_Check(raw_ptr) != 0
                && let Ok(base_any) = raw.getattr("obj")
                && ffi::PyBytes_CheckExact(base_any.as_ptr()) != 0
            {
                let mut view = std::mem::zeroed::<ffi::Py_buffer>();
                if ffi::PyObject_GetBuffer(raw_ptr, &mut view, ffi::PyBUF_STRIDES) == 0 {
                    let ok_layout = view.readonly != 0
                        && view.ndim <= 1
                        && view.itemsize == 1
                        && (view.ndim == 0 || view.strides.is_null() || *view.strides == 1);
                    let sub_len = view.len.max(0) as usize;
                    let buf_ptr = view.buf;
                    ffi::PyBuffer_Release(&mut view);
                    if ok_layout {
                        let base_obj = base_any.as_ptr();
                        let base_len = ffi::PyBytes_Size(base_obj) as usize;
                        if sub_len == 0 {
                            let pb = base_any.cast_unchecked::<PyBytes>().clone().unbind();
                            return Ok(Self {
                                owner: pb,
                                start: 0,
                                end: 0,
                            });
                        }
                        if !buf_ptr.is_null() && base_len >= sub_len {
                            let base_addr = ffi::PyBytes_AS_STRING(base_obj).cast::<u8>() as usize;
                            let buf_addr = buf_ptr.cast::<u8>() as usize;
                            let offset = buf_addr.wrapping_sub(base_addr);
                            if offset <= base_len - sub_len {
                                let pb = base_any.cast_unchecked::<PyBytes>().clone().unbind();
                                return Ok(Self {
                                    owner: pb,
                                    start: offset,
                                    end: offset + sub_len,
                                });
                            }
                        }
                    }
                } else {
                    ffi::PyErr_Clear();
                }
            }
        }
        let borrowed = LeafBytes::extract(py, raw)?;
        let py_bytes = PyBytes::new(py, borrowed.as_slice());
        let len = borrowed.as_slice().len();
        drop(borrowed);
        Ok(Self {
            owner: py_bytes.unbind(),
            start: 0,
            end: len,
        })
    }

    #[inline]
    pub fn from_vec(py: Python<'_>, vec: &[u8]) -> Self {
        let pb = PyBytes::new(py, vec);
        Self {
            owner: pb.unbind(),
            start: 0,
            end: vec.len(),
        }
    }

    #[inline]
    pub fn as_slice<'a>(&'a self, py: Python<'a>) -> &'a [u8] {
        &self.owner.as_bytes(py)[self.start..self.end]
    }

    #[inline]
    pub fn subslice(&self, py: Python<'_>, rel_start: usize, rel_end: usize) -> Self {
        Self {
            owner: self.owner.clone_ref(py),
            start: self.start + rel_start,
            end: self.start + rel_end,
        }
    }

    #[inline]
    pub fn to_py_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let full = self.owner.bind(py);
        if self.start == 0 && self.end == full.as_bytes().len() {
            full.clone()
        } else {
            PyBytes::new(py, &full.as_bytes()[self.start..self.end])
        }
    }

    #[inline]
    pub fn to_readonly_memoryview<'py>(
        &self,
        py: Python<'py>,
        rel_start: usize,
        rel_end: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        create_readonly_memoryview_slice(
            py,
            self.owner.bind(py),
            self.start + rel_start,
            self.start + rel_end,
        )
    }
}

#[inline]
pub(crate) fn create_readonly_memoryview_slice<'py>(
    py: Python<'py>,
    owner: &Bound<'py, PyBytes>,
    start: usize,
    end: usize,
) -> PyResult<Bound<'py, PyAny>> {
    unsafe {
        let mv_ptr = ffi::PyMemoryView_FromObject(owner.as_ptr());
        let mv = Bound::from_owned_ptr_or_err(py, mv_ptr)?;
        if start == 0 && end == owner.as_bytes().len() {
            return Ok(mv);
        }
        let sliced_ptr = ffi::PySequence_GetSlice(
            mv.as_ptr(),
            start as ffi::Py_ssize_t,
            end as ffi::Py_ssize_t,
        );
        Bound::from_owned_ptr_or_err(py, sliced_ptr)
    }
}

pub(crate) fn merge_core_schema_meta(base: &mut CoreSchemaMeta, overlay: CoreSchemaMeta) {
    if !overlay.type_name.is_empty() {
        base.type_name = overlay.type_name;
    }
    for (k, v) in overlay.fields {
        base.fields.insert(k, v);
    }
    for (k, child) in overlay.children {
        if let Some(existing) = base.children.get_mut(&k) {
            merge_core_schema_meta(existing, child);
        } else {
            base.children.insert(k, child);
        }
    }
}

pub(crate) fn decode_schema_meta_slice(
    body: &[u8],
    depth: usize,
) -> Result<CoreSchemaMeta, String> {
    if depth > MAX_NESTING_DEPTH {
        return Err(format!(
            "omnibuf: SchemaMeta nesting depth {depth} exceeds {MAX_NESTING_DEPTH}"
        ));
    }
    let mut meta = CoreSchemaMeta::default();
    let mut pos = 0usize;
    let n = body.len();

    while pos < n {
        let (tag, tn) = decode_varint(&body[pos..])
            .ok_or_else(|| format!("omnibuf: invalid tag in SchemaMeta at byte {pos}"))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err("omnibuf: invalid field number in SchemaMeta".to_owned());
        }
        pos += tn;
        let fnum = (tag >> 4) as u32;
        let wt = (tag & 0x0F) as u8;

        match fnum {
            0 => return Err("omnibuf: nested Field #0 forbidden inside SchemaMeta".to_owned()),
            1 => {
                if wt != WIRE_STRING {
                    return Err(format!(
                        "omnibuf: SchemaMeta field #1 (type_name) must be WireString, got {wt}"
                    ));
                }
                let (s_bytes, next_pos) =
                    read_len_slice(body, pos, 0).map_err(|e| e.to_string())?;
                let s = validate_utf8(s_bytes).map_err(|e| e.to_string())?;
                meta.type_name = s.to_owned();
                pos = next_pos;
            }
            2 => {
                if wt != WIRE_MAP {
                    return Err(format!(
                        "omnibuf: SchemaMeta field #2 (fields) must be WireMap, got {wt}"
                    ));
                }
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(format!(
                        "omnibuf: SchemaMeta fields map depth {} exceeds {MAX_NESTING_DEPTH}",
                        depth + 1
                    ));
                }
                let (m_body, next_pos) = read_len_slice(body, pos, 3).map_err(|e| e.to_string())?;
                let (key_wt, val_wt, count, mut p) = parse_map_header(m_body)
                    .ok_or_else(|| "omnibuf: invalid SchemaMeta fields map header".to_owned())?;
                if key_wt != WIRE_UINT || val_wt != WIRE_STRING {
                    return Err("omnibuf: invalid SchemaMeta fields map types".to_owned());
                }
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&m_body[p..]).ok_or_else(|| {
                        format!("omnibuf: truncated SchemaMeta field key at byte {p}")
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(format!("omnibuf: invalid SchemaMeta field number {k64}"));
                    }
                    p += kn;
                    let (v_bytes, np) = read_len_slice(m_body, p, 0).map_err(|e| e.to_string())?;
                    let v_str = validate_utf8(v_bytes).map_err(|e| e.to_string())?;
                    meta.fields.insert(k64 as u32, v_str.to_owned());
                    p = np;
                }
                if p != m_body.len() {
                    return Err("omnibuf: trailing bytes in SchemaMeta fields map".to_owned());
                }
                pos = next_pos;
            }
            3 => {
                if wt != WIRE_MAP {
                    return Err(format!(
                        "omnibuf: SchemaMeta field #3 (children) must be WireMap, got {wt}"
                    ));
                }
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(format!(
                        "omnibuf: SchemaMeta children map depth {} exceeds {MAX_NESTING_DEPTH}",
                        depth + 1
                    ));
                }
                let (m_body, next_pos) = read_len_slice(body, pos, 3).map_err(|e| e.to_string())?;
                let (key_wt, val_wt, count, mut p) = parse_map_header(m_body)
                    .ok_or_else(|| "omnibuf: invalid SchemaMeta children map header".to_owned())?;
                if key_wt != WIRE_UINT || val_wt != WIRE_SUB_MSG {
                    return Err("omnibuf: invalid SchemaMeta children map types".to_owned());
                }
                let mut local_children: BTreeMap<u32, CoreSchemaMeta> = BTreeMap::new();
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&m_body[p..]).ok_or_else(|| {
                        format!("omnibuf: truncated SchemaMeta child key at byte {p}")
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(format!(
                            "omnibuf: invalid SchemaMeta child field number {k64}"
                        ));
                    }
                    p += kn;
                    let (c_bytes, np) = read_len_slice(m_body, p, 0).map_err(|e| e.to_string())?;
                    let child_meta = decode_schema_meta_slice(c_bytes, depth + 2)?;
                    local_children.insert(k64 as u32, child_meta);
                    p = np;
                }
                if p != m_body.len() {
                    return Err("omnibuf: trailing bytes in SchemaMeta children map".to_owned());
                }
                for (k32, child_meta) in local_children {
                    if let Some(existing) = meta.children.get_mut(&k32) {
                        merge_core_schema_meta(existing, child_meta);
                    } else {
                        meta.children.insert(k32, child_meta);
                    }
                }
                pos = next_pos;
            }
            _ => {
                pos = validate_value_no_py(body, pos, wt, depth, true)?;
            }
        }
    }
    Ok(meta)
}

#[inline]
pub(crate) fn validate_field0_slice(
    data: &[u8],
    pos: usize,
    depth: usize,
) -> Result<usize, String> {
    if depth + 1 > MAX_NESTING_DEPTH {
        return Err(format!(
            "omnibuf: Field #0 nesting depth {} exceeds {MAX_NESTING_DEPTH}",
            depth + 1
        ));
    }
    let (body, next_pos) = read_len_slice(data, pos, 0).map_err(|e| e.to_string())?;
    let _ = decode_schema_meta_slice(body, depth + 1)?;
    Ok(next_pos)
}

pub(crate) fn read_field0_checked(packet: &[u8]) -> Result<Option<CoreSchemaMeta>, String> {
    let mut merged: Option<CoreSchemaMeta> = None;
    let mut pos = 0usize;
    let n = packet.len();

    while pos < n {
        let (tag, tn) = decode_varint(&packet[pos..])
            .ok_or_else(|| format!("omnibuf: invalid or truncated tag at byte {pos}"))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err("omnibuf: field number exceeds maximum 29-bit limit".to_owned());
        }
        pos += tn;
        let fnum = (tag >> 4) as u32;
        let wt = (tag & 0x0F) as u8;

        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(format!(
                    "omnibuf: Field #0 requires WireSubMsg (12), got {wt}"
                ));
            }
            let (body, next_pos) = read_len_slice(packet, pos, 0).map_err(|e| e.to_string())?;
            let meta = decode_schema_meta_slice(body, 1)?;
            if let Some(ref mut base) = merged {
                merge_core_schema_meta(base, meta);
            } else {
                merged = Some(meta);
            }
            pos = next_pos;
        } else {
            pos = match wt {
                WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED => {
                    skip_value(packet, pos, wt).map_err(|e| e.to_string())?
                }
                _ => fast_skip_value(packet, pos, wt).ok_or_else(|| {
                    format!("omnibuf: truncated or invalid wire type {wt} at byte {pos}")
                })?,
            };
        }
    }
    Ok(merged)
}

fn validate_container_entry_impl(
    py: Option<Python<'_>>,
    body: &[u8],
    p: usize,
    wt: u8,
    depth: usize,
    check_utf8: bool,
) -> PyResult<usize> {
    if wt == WIRE_BOOL_FALSE {
        let b = *body.get(p).ok_or_else(|| {
            if let Some(py) = py {
                decode_err(py, "omnibuf: truncated bool in container")
            } else {
                PyValueError::new_err("omnibuf: truncated bool in container")
            }
        })?;
        if b > 1 {
            return Err(if let Some(py) = py {
                decode_err(py, "omnibuf: invalid bool byte in container")
            } else {
                PyValueError::new_err("omnibuf: invalid bool byte in container")
            });
        }
        return Ok(p + 1);
    }
    validate_value_py_impl(py, body, p, wt, depth, check_utf8)
}

#[inline]
fn mk_dec_err(py: Option<Python<'_>>, msg: impl Into<String>) -> PyErr {
    if let Some(py) = py {
        decode_err(py, msg)
    } else {
        PyValueError::new_err(msg.into())
    }
}

fn validate_array_body_impl(
    py: Option<Python<'_>>,
    body: &[u8],
    mut p: usize,
    elem_wt: u8,
    count: usize,
    depth: usize,
    check_utf8: bool,
) -> PyResult<()> {
    let rem = body.len() - p;
    match elem_wt {
        WIRE_BOOL_FALSE => {
            if rem != count {
                return Err(mk_dec_err(py, "omnibuf: invalid bool array byte length"));
            }
            for &b in &body[p..p + count] {
                if b > 1 {
                    return Err(mk_dec_err(py, "omnibuf: invalid bool byte in array"));
                }
            }
            return Ok(());
        }
        WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 => {
            if Some(rem) != count.checked_mul(4) {
                return Err(mk_dec_err(py, "omnibuf: invalid 32-bit array byte length"));
            }
            return Ok(());
        }
        WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64 => {
            if Some(rem) != count.checked_mul(8) {
                return Err(mk_dec_err(py, "omnibuf: invalid 64-bit array byte length"));
            }
            return Ok(());
        }
        _ => {}
    }
    for i in 0..count {
        if (i & 0xFFF) == 0xFFF
            && let Some(py_tok) = py
        {
            py_tok.check_signals()?;
        }
        p = validate_container_entry_impl(py, body, p, elem_wt, depth, check_utf8)?;
    }
    if p != body.len() {
        return Err(mk_dec_err(py, "omnibuf: trailing bytes in WireArray"));
    }
    Ok(())
}

fn validate_value_py_impl(
    py: Option<Python<'_>>,
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
    check_utf8: bool,
) -> PyResult<usize> {
    if depth > MAX_NESTING_DEPTH {
        return Err(mk_dec_err(
            py,
            format!("omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"),
        ));
    }
    if pos > data.len() {
        return Err(mk_dec_err(
            py,
            format!("omnibuf: position {pos} out of bounds"),
        ));
    }
    match wire_type {
        WIRE_STRING => {
            let (s_bytes, end) =
                read_len_slice(data, pos, 0).map_err(|e| mk_dec_err(py, e.to_string()))?;
            if check_utf8 {
                validate_utf8(s_bytes).map_err(|e| mk_dec_err(py, e.to_string()))?;
            }
            Ok(end)
        }
        WIRE_SUB_MSG => {
            let (body, end) =
                read_len_slice(data, pos, 0).map_err(|e| mk_dec_err(py, e.to_string()))?;
            validate_message_py_impl(py, body, depth + 1, check_utf8)?;
            Ok(end)
        }
        WIRE_ARRAY => {
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(mk_dec_err(
                    py,
                    format!(
                        "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                        depth + 1
                    ),
                ));
            }
            let (body, end) =
                read_len_slice(data, pos, 2).map_err(|e| mk_dec_err(py, e.to_string()))?;
            let (elem_wt, count, start_p) = parse_array_header(body).ok_or_else(|| {
                mk_dec_err(
                    py,
                    format!("omnibuf: invalid WireArray header at byte {pos}"),
                )
            })?;
            validate_array_body_impl(py, body, start_p, elem_wt, count, depth + 1, check_utf8)?;
            Ok(end)
        }
        WIRE_MAP => {
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(mk_dec_err(
                    py,
                    format!(
                        "omnibuf: map nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                        depth + 1
                    ),
                ));
            }
            let (body, end) =
                read_len_slice(data, pos, 3).map_err(|e| mk_dec_err(py, e.to_string()))?;
            let (key_wt, val_wt, count, mut p) = parse_map_header(body).ok_or_else(|| {
                mk_dec_err(py, format!("omnibuf: invalid WireMap header at byte {pos}"))
            })?;
            for i in 0..count {
                if (i & 0xFFF) == 0xFFF
                    && let Some(py_tok) = py
                {
                    py_tok.check_signals()?;
                }
                p = validate_container_entry_impl(py, body, p, key_wt, depth + 1, check_utf8)?;
                p = validate_container_entry_impl(py, body, p, val_wt, depth + 1, check_utf8)?;
            }
            if p != body.len() {
                return Err(mk_dec_err(py, "omnibuf: trailing bytes in WireMap"));
            }
            Ok(end)
        }
        WIRE_EXTENDED => {
            let (_, end) =
                read_len_slice(data, pos, 1).map_err(|e| mk_dec_err(py, e.to_string()))?;
            Ok(end)
        }
        _ => fast_skip_value(data, pos, wire_type).ok_or_else(|| {
            mk_dec_err(
                py,
                format!("omnibuf: truncated or invalid wire type {wire_type} at byte {pos}"),
            )
        }),
    }
}

fn validate_message_py_impl(
    py: Option<Python<'_>>,
    data: &[u8],
    depth: usize,
    check_utf8: bool,
) -> PyResult<()> {
    if depth > MAX_NESTING_DEPTH {
        return Err(mk_dec_err(
            py,
            format!("omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"),
        ));
    }
    let mut pos = 0usize;
    let n = data.len();
    let mut step = 0usize;
    while pos < n {
        step += 1;
        if (step & 0xFFF) == 0
            && let Some(py_tok) = py
        {
            py_tok.check_signals()?;
        }
        let (tag, tn) = decode_varint(&data[pos..]).ok_or_else(|| {
            mk_dec_err(
                py,
                format!("omnibuf: invalid or truncated tag at byte {pos}"),
            )
        })?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(mk_dec_err(
                py,
                "omnibuf: field number exceeds maximum 29-bit limit",
            ));
        }
        pos += tn;
        let fnum = tag >> 4;
        let wt = (tag & 0x0F) as u8;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(mk_dec_err(
                    py,
                    format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                ));
            }
            pos = validate_field0_slice(data, pos, depth).map_err(|m| mk_dec_err(py, m))?;
        } else {
            pos = validate_value_py_impl(py, data, pos, wt, depth, check_utf8)?;
        }
    }
    Ok(())
}

fn validate_value_no_py(
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
    check_utf8: bool,
) -> Result<usize, String> {
    if depth > MAX_NESTING_DEPTH {
        return Err(format!(
            "omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"
        ));
    }
    if pos > data.len() {
        return Err(format!("omnibuf: position {pos} out of bounds"));
    }
    match wire_type {
        WIRE_STRING => {
            let (s_bytes, end) = read_len_slice(data, pos, 0).map_err(|e| e.to_string())?;
            if check_utf8 {
                validate_utf8(s_bytes).map_err(|e| e.to_string())?;
            }
            Ok(end)
        }
        WIRE_SUB_MSG => {
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(format!(
                    "omnibuf: nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                    depth + 1
                ));
            }
            let (body, end) = read_len_slice(data, pos, 0).map_err(|e| e.to_string())?;
            let mut p = 0usize;
            while p < body.len() {
                let (tag, tn) = decode_varint(&body[p..])
                    .ok_or_else(|| format!("omnibuf: invalid tag at byte {p}"))?;
                if (tag >> 4) > MAX_FIELD_NUMBER {
                    return Err("omnibuf: field number exceeds maximum 29-bit limit".to_owned());
                }
                p += tn;
                let fnum = tag >> 4;
                let wt = (tag & 0x0F) as u8;
                if fnum == 0 {
                    if wt != WIRE_SUB_MSG {
                        return Err(format!(
                            "omnibuf: Field #0 requires WireSubMsg (12), got {wt}"
                        ));
                    }
                    p = validate_field0_slice(body, p, depth + 1)?;
                } else {
                    p = validate_value_no_py(body, p, wt, depth + 1, check_utf8)?;
                }
            }
            Ok(end)
        }
        WIRE_ARRAY => {
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(format!(
                    "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                    depth + 1
                ));
            }
            let (body, end) = read_len_slice(data, pos, 2).map_err(|e| e.to_string())?;
            let (elem_wt, count, mut p) = parse_array_header(body)
                .ok_or_else(|| format!("omnibuf: invalid WireArray header at byte {pos}"))?;
            let rem = body.len() - p;
            match elem_wt {
                WIRE_BOOL_FALSE => {
                    if rem != count || body[p..p + count].iter().any(|&b| b > 1) {
                        return Err("omnibuf: invalid bool array".to_owned());
                    }
                    return Ok(end);
                }
                WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 => {
                    if Some(rem) != count.checked_mul(4) {
                        return Err("omnibuf: invalid 32-bit array byte length".to_owned());
                    }
                    return Ok(end);
                }
                WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64 => {
                    if Some(rem) != count.checked_mul(8) {
                        return Err("omnibuf: invalid 64-bit array byte length".to_owned());
                    }
                    return Ok(end);
                }
                _ => {}
            }
            for _ in 0..count {
                p = validate_value_no_py(body, p, elem_wt, depth + 1, check_utf8)?;
            }
            if p != body.len() {
                return Err("omnibuf: trailing bytes in WireArray".to_owned());
            }
            Ok(end)
        }
        WIRE_MAP => {
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(format!(
                    "omnibuf: map nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                    depth + 1
                ));
            }
            let (body, end) = read_len_slice(data, pos, 3).map_err(|e| e.to_string())?;
            let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                .ok_or_else(|| format!("omnibuf: invalid WireMap header at byte {pos}"))?;
            for _ in 0..count {
                p = if key_wt == WIRE_BOOL_FALSE {
                    let b = *body
                        .get(p)
                        .ok_or_else(|| "omnibuf: truncated bool in WireMap".to_owned())?;
                    if b > 1 {
                        return Err("omnibuf: invalid bool in WireMap".to_owned());
                    }
                    p + 1
                } else {
                    validate_value_no_py(body, p, key_wt, depth + 1, check_utf8)?
                };
                p = if val_wt == WIRE_BOOL_FALSE {
                    let b = *body
                        .get(p)
                        .ok_or_else(|| "omnibuf: truncated bool in WireMap".to_owned())?;
                    if b > 1 {
                        return Err("omnibuf: invalid bool in WireMap".to_owned());
                    }
                    p + 1
                } else {
                    validate_value_no_py(body, p, val_wt, depth + 1, check_utf8)?
                };
            }
            if p != body.len() {
                return Err("omnibuf: trailing bytes in WireMap".to_owned());
            }
            Ok(end)
        }
        WIRE_EXTENDED => {
            let (_, end) = read_len_slice(data, pos, 1).map_err(|e| e.to_string())?;
            Ok(end)
        }
        _ => fast_skip_value(data, pos, wire_type).ok_or_else(|| {
            format!("omnibuf: truncated or invalid wire type {wire_type} at byte {pos}")
        }),
    }
}

/// Validates an unreferenced/unknown field value per Spec section 7 (`WIRE_STRING` skipped by byte
/// length, containers recursively checked up to `MAX_NESTING_DEPTH`, `WIRE_EXTENDED` >= 1 byte).
#[inline]
pub(crate) fn validate_unknown_value(
    py: Python<'_>,
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
) -> PyResult<usize> {
    validate_value_py_impl(Some(py), data, pos, wire_type, depth, false)
}

/// Validates a field value strictly (including `WIRE_STRING` UTF-8 validation).
#[inline]
pub(crate) fn validate_strict_value(
    py: Python<'_>,
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
) -> PyResult<usize> {
    validate_value_py_impl(Some(py), data, pos, wire_type, depth, true)
}

/// Validates an entire OmniBuf message buffer strictly (including `WIRE_STRING` UTF-8).
#[inline]
pub(crate) fn validate_message_slice(py: Python<'_>, data: &[u8], depth: usize) -> PyResult<()> {
    validate_message_py_impl(Some(py), data, depth, true)
}

fn core_schema_meta_to_py<'py>(
    py: Python<'py>,
    meta: &CoreSchemaMeta,
    schema_meta_cls: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let fields_dict = PyDict::new(py);
    for (&fnum, name) in &meta.fields {
        fields_dict.set_item(fnum, PyString::new(py, name))?;
    }
    let children_dict = PyDict::new(py);
    for (&fnum, child) in &meta.children {
        let child_py = core_schema_meta_to_py(py, child, schema_meta_cls)?;
        children_dict.set_item(fnum, child_py)?;
    }
    schema_meta_cls.call1((
        PyString::new(py, &meta.type_name),
        fields_dict,
        children_dict,
    ))
}

#[pyfunction]
fn init_exceptions(encode_cls: Bound<'_, PyType>, decode_cls: Bound<'_, PyType>) {
    let _ = ENCODE_ERR_CLS.set(encode_cls.unbind());
    let _ = DECODE_ERR_CLS.set(decode_cls.unbind());
}

#[pyfunction]
fn validate_message_py(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<()> {
    let borrowed = LeafBytes::extract(py, data)?;
    validate_message_slice(py, borrowed.as_slice(), 0)
}

#[pyfunction]
fn has_field0_py(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<bool> {
    let borrowed = LeafBytes::extract(py, data)?;
    let parsed = read_field0_checked(borrowed.as_slice()).map_err(|m| decode_err(py, m))?;
    Ok(parsed.is_some())
}

#[pyfunction]
fn read_field0_py<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyAny>,
    schema_meta_cls: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let parsed = {
        let borrowed = LeafBytes::extract(py, data)?;
        read_field0_checked(borrowed.as_slice()).map_err(|m| decode_err(py, m))?
    };
    match parsed {
        Some(meta) => core_schema_meta_to_py(py, &meta, schema_meta_cls),
        None => Ok(py.None().into_bound(py)),
    }
}

#[pyfunction]
#[pyo3(signature = (dst_prefix, src_packet, replacements))]
fn splice_fields_py<'py>(
    py: Python<'py>,
    dst_prefix: Option<&Bound<'py, PyAny>>,
    src_packet: &Bound<'py, PyAny>,
    replacements: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = if let Some(prefix_obj) = dst_prefix {
        let p_bytes = LeafBytes::extract(py, prefix_obj)?;
        let s = p_bytes.as_slice();
        let mut v = Vec::with_capacity(s.len() + 256);
        v.extend_from_slice(s);
        v
    } else {
        Vec::new()
    };

    let src_input = InputBytes::extract(py, src_packet)?;
    let src = src_input.as_slice();

    let seq = replacements.cast::<PySequence>()?;
    let rep_len = seq.len()?;

    if rep_len == 0 {
        validate_message_slice(py, src, 0)?;
        out.extend_from_slice(src);
        return Ok(PyBytes::new(py, &out));
    }

    let mut rep_index: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::with_capacity(rep_len);
    let mut rep_payloads: Vec<Vec<u8>> = Vec::with_capacity(rep_len);

    for i in 0..rep_len {
        let item = seq.get_item(i)?;
        let fnum_obj = item.getattr("field_num")?;
        if unsafe { ffi::PyBool_Check(fnum_obj.as_ptr()) != 0 } {
            return Err(encode_err(py, "omnibuf: invalid bool splice field number"));
        }
        let fnum_i64: i64 = fnum_obj
            .extract()
            .map_err(|_| encode_err(py, "omnibuf: invalid splice field number"))?;
        if fnum_i64 <= 0 || fnum_i64 > MAX_FIELD_NUMBER as i64 {
            return Err(encode_err(
                py,
                format!("omnibuf: invalid splice field number {fnum_i64}"),
            ));
        }
        let fnum = fnum_i64 as u32;
        let enc_attr = item.getattr("encoded_field")?;
        let enc_leaf = LeafBytes::extract(py, &enc_attr)?;
        let payload = enc_leaf.as_slice().to_vec();
        drop(enc_leaf);

        if let Some(&existing_idx) = rep_index.get(&fnum) {
            rep_payloads[existing_idx] = payload;
        } else {
            let idx = rep_payloads.len();
            rep_index.insert(fnum, idx);
            rep_payloads.push(payload);
        }
    }

    let n = src.len();
    let mut spans: Vec<(Option<usize>, usize, usize)> = Vec::with_capacity(16);
    let mut last_occurrence: Vec<Option<usize>> = vec![None; rep_payloads.len()];
    let mut pos = 0usize;

    while pos < n {
        let field_start = pos;
        let (tag, tn) = decode_varint(&src[pos..]).ok_or_else(|| {
            decode_err(
                py,
                format!("omnibuf: invalid tag during splice at byte {pos}"),
            )
        })?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(decode_err(
                py,
                format!("omnibuf: invalid tag during splice at byte {pos}"),
            ));
        }
        pos += tn;
        let fnum = (tag >> 4) as u32;
        let wt = (tag & 0x0F) as u8;
        let next_pos = if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(decode_err(
                    py,
                    format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                ));
            }
            validate_field0_slice(src, pos, 0).map_err(|m| decode_err(py, m))?
        } else {
            validate_strict_value(py, src, pos, wt, 0)?
        };
        let span_idx = spans.len();
        let rep_idx = rep_index.get(&fnum).copied();
        spans.push((rep_idx, field_start, next_pos));
        if let Some(ri) = rep_idx {
            last_occurrence[ri] = Some(span_idx);
        }
        pos = next_pos;
    }

    out.reserve(n + 64);
    let mut emitted = vec![false; rep_payloads.len()];
    let mut copy_start = 0usize;

    for (idx, &(rep_idx_opt, f_start, f_end)) in spans.iter().enumerate() {
        let Some(rep_idx) = rep_idx_opt else {
            continue;
        };
        if copy_start < f_start {
            out.extend_from_slice(&src[copy_start..f_start]);
        }
        if last_occurrence[rep_idx] == Some(idx) {
            let encoded = &rep_payloads[rep_idx];
            if !encoded.is_empty() {
                out.extend_from_slice(encoded);
            }
            emitted[rep_idx] = true;
        }
        copy_start = f_end;
    }

    if copy_start < n {
        out.extend_from_slice(&src[copy_start..n]);
    }

    for (rep_idx, was_emitted) in emitted.into_iter().enumerate() {
        if !was_emitted {
            let encoded = &rep_payloads[rep_idx];
            if !encoded.is_empty() {
                out.extend_from_slice(encoded);
            }
        }
    }

    Ok(PyBytes::new(py, &out))
}

#[pymodule]
fn _omnibuf_ext(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CompiledCodec>()?;
    m.add_class::<OpaqueView>()?;
    m.add_function(wrap_pyfunction!(init_exceptions, m)?)?;
    m.add_function(wrap_pyfunction!(validate_message_py, m)?)?;
    m.add_function(wrap_pyfunction!(has_field0_py, m)?)?;
    m.add_function(wrap_pyfunction!(read_field0_py, m)?)?;
    m.add_function(wrap_pyfunction!(splice_fields_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_blind_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_blind_json_py, m)?)?;
    m.add_function(wrap_pyfunction!(register_dataclass_codec_py, m)?)?;
    m.add_function(wrap_pyfunction!(set_dataclass_resolver_py, m)?)?;
    m.add_function(wrap_pyfunction!(marshal_dataclass_py, m)?)?;
    m.add_function(wrap_pyfunction!(unmarshal_dataclass_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_uint32_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_uint64_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_sint32_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_sint64_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_bool_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_fixed32_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_sfixed32_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_fixed64_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_sfixed64_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_float32_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_float64_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_string_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_bytes_py, m)?)?;
    m.add_function(wrap_pyfunction!(opaque_get_submsg_slice_py, m)?)?;
    Ok(())
}
