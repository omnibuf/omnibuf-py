use std::sync::OnceLock;

use omnibuf_core::field0::{
    SchemaMeta as CoreSchemaMeta, read_field0_schema_meta, validate_field0,
};
use omnibuf_core::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_EXTENDED, WIRE_FIXED32,
    WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32, WIRE_SFIXED64, WIRE_SUB_MSG,
    decode_varint, fast_skip_value, parse_array_header, parse_map_header, read_len_slice,
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

/// Safe leaf view over `bytes` (zero-copy) or any buffer-protocol object (`PyObject_GetBuffer`
/// with `PyBUF_SIMPLE`, pinning `bytearray` exports via `ob_exports` until `Drop`).
///
/// Only hold `LeafBytes` across pure Rust operations that do not invoke arbitrary Python callbacks
/// capable of mutating the underlying buffer in-place.
pub(crate) struct LeafBytes<'py> {
    ptr: *const u8,
    len: usize,
    view: Option<ffi::Py_buffer>,
    _marker: std::marker::PhantomData<&'py [u8]>,
}

impl<'py> LeafBytes<'py> {
    #[inline]
    pub(crate) fn extract(py: Python<'py>, obj_ptr: *mut ffi::PyObject) -> PyResult<Self> {
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
    Borrowed(&'py [u8]),
    Owned(Vec<u8>),
}

impl<'py> InputBytes<'py> {
    #[inline]
    pub(crate) fn extract(py: Python<'py>, obj_ptr: *mut ffi::PyObject) -> PyResult<Self> {
        unsafe {
            if ffi::PyBytes_CheckExact(obj_ptr) != 0 {
                let len = ffi::PyBytes_Size(obj_ptr) as usize;
                let slice = if len == 0 {
                    &[]
                } else {
                    std::slice::from_raw_parts(ffi::PyBytes_AS_STRING(obj_ptr).cast::<u8>(), len)
                };
                return Ok(Self::Borrowed(slice));
            }
        }
        let leaf = LeafBytes::extract(py, obj_ptr)?;
        let vec = leaf.as_slice().to_vec();
        drop(leaf);
        Ok(Self::Owned(vec))
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s,
            Self::Owned(v) => v.as_slice(),
        }
    }
}

fn validate_container_entry_slice(
    body: &[u8],
    p: usize,
    wt: u8,
    depth: usize,
) -> Result<usize, String> {
    if wt == WIRE_BOOL_FALSE {
        let b = *body
            .get(p)
            .ok_or_else(|| "omnibuf: truncated bool in container".to_owned())?;
        if b > 1 {
            return Err("omnibuf: invalid bool byte in container".to_owned());
        }
        return Ok(p + 1);
    }
    validate_unknown_value(body, p, wt, depth)
}

fn validate_array_body_slice(
    body: &[u8],
    mut p: usize,
    elem_wt: u8,
    count: usize,
    depth: usize,
) -> Result<(), String> {
    let rem = body.len() - p;
    match elem_wt {
        WIRE_BOOL_FALSE => {
            if rem != count {
                return Err("omnibuf: invalid bool array byte length".to_owned());
            }
            for &b in &body[p..p + count] {
                if b > 1 {
                    return Err("omnibuf: invalid bool byte in array".to_owned());
                }
            }
            return Ok(());
        }
        WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 => {
            if Some(rem) != count.checked_mul(4) {
                return Err("omnibuf: invalid 32-bit array byte length".to_owned());
            }
            return Ok(());
        }
        WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64 => {
            if Some(rem) != count.checked_mul(8) {
                return Err("omnibuf: invalid 64-bit array byte length".to_owned());
            }
            return Ok(());
        }
        _ => {}
    }
    for _ in 0..count {
        p = validate_container_entry_slice(body, p, elem_wt, depth)?;
    }
    if p != body.len() {
        return Err("omnibuf: trailing bytes in WireArray".to_owned());
    }
    Ok(())
}

/// Validates an unreferenced/unknown field value per Spec §7 (`WIRE_STRING` skipped by byte length,
/// containers recursively checked up to `MAX_NESTING_DEPTH`, `WIRE_EXTENDED` accepting `0x00..=0xFF`).
pub(crate) fn validate_unknown_value(
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
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
        WIRE_SUB_MSG => {
            let (body, end) = read_len_slice(data, pos, 0).map_err(|e| e.to_string())?;
            validate_message_slice(body, depth + 1)?;
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
            let (elem_wt, count, start_p) = parse_array_header(body)
                .ok_or_else(|| format!("omnibuf: invalid WireArray header at byte {pos}"))?;
            validate_array_body_slice(body, start_p, elem_wt, count, depth + 1)?;
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
                p = validate_container_entry_slice(body, p, key_wt, depth + 1)?;
                p = validate_container_entry_slice(body, p, val_wt, depth + 1)?;
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

pub(crate) fn validate_message_slice(data: &[u8], depth: usize) -> Result<(), String> {
    if depth > MAX_NESTING_DEPTH {
        return Err(format!(
            "omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"
        ));
    }
    let mut pos = 0usize;
    let n = data.len();
    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..])
            .ok_or_else(|| format!("omnibuf: invalid or truncated tag at byte {pos}"))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err("omnibuf: field number exceeds maximum 29-bit limit".to_owned());
        }
        pos += tn;
        let fnum = tag >> 4;
        let wt = (tag & 0x0F) as u8;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(format!(
                    "omnibuf: Field #0 requires WireSubMsg (12), got {wt}"
                ));
            }
            pos = validate_field0(data, pos, depth).map_err(|e| e.to_string())?;
        } else {
            pos = validate_unknown_value(data, pos, wt, depth)?;
        }
    }
    Ok(())
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
    let borrowed = LeafBytes::extract(py, data.as_ptr())?;
    validate_message_slice(borrowed.as_slice(), 0).map_err(|m| decode_err(py, m))
}

#[pyfunction]
fn has_field0_py(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<bool> {
    let borrowed = LeafBytes::extract(py, data.as_ptr())?;
    Ok(read_field0_schema_meta(borrowed.as_slice()).is_some())
}

#[pyfunction]
fn read_field0_py<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyAny>,
    schema_meta_cls: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let parsed = {
        let borrowed = LeafBytes::extract(py, data.as_ptr())?;
        read_field0_schema_meta(borrowed.as_slice())
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
        let p_bytes = LeafBytes::extract(py, prefix_obj.as_ptr())?;
        let s = p_bytes.as_slice();
        let mut v = Vec::with_capacity(s.len() + 256);
        v.extend_from_slice(s);
        v
    } else {
        Vec::new()
    };

    let src_input = InputBytes::extract(py, src_packet.as_ptr())?;
    let src = src_input.as_slice();

    let seq = replacements.cast::<PySequence>()?;
    let rep_len = seq.len()?;

    if rep_len == 0 {
        validate_message_slice(src, 0).map_err(|m| decode_err(py, m))?;
        out.extend_from_slice(src);
        return Ok(PyBytes::new(py, &out));
    }

    let mut ordered_nums: Vec<u32> = Vec::with_capacity(rep_len);
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
        let enc_leaf = LeafBytes::extract(py, enc_attr.as_ptr())?;
        let payload = enc_leaf.as_slice().to_vec();
        drop(enc_leaf);

        if let Some(existing_idx) = ordered_nums.iter().position(|&n| n == fnum) {
            rep_payloads[existing_idx] = payload;
        } else {
            ordered_nums.push(fnum);
            rep_payloads.push(payload);
        }
    }

    let n = src.len();
    let mut spans: Vec<(u32, usize, usize)> = Vec::with_capacity(16);
    let mut last_occurrence: Vec<Option<usize>> = vec![None; ordered_nums.len()];
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
            validate_field0(src, pos, 0).map_err(|e| decode_err(py, e.to_string()))?
        } else {
            validate_unknown_value(src, pos, wt, 0).map_err(|m| decode_err(py, m))?
        };
        let span_idx = spans.len();
        spans.push((fnum, field_start, next_pos));
        if let Some(rep_idx) = ordered_nums.iter().position(|&target| target == fnum) {
            last_occurrence[rep_idx] = Some(span_idx);
        }
        pos = next_pos;
    }

    out.reserve(n + 64);
    let mut emitted = vec![false; ordered_nums.len()];
    let mut copy_start = 0usize;

    for (idx, &(fnum, f_start, f_end)) in spans.iter().enumerate() {
        let Some(rep_idx) = ordered_nums.iter().position(|&target| target == fnum) else {
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
