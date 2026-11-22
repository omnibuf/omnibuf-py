use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use omnibuf_core::field0::SchemaMeta as CoreSchemaMeta;
use omnibuf_core::wire::{
    Decoder, Encoder, MAX_NESTING_DEPTH, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_SUB_MSG, append_tag,
    append_varint, backpatch_container_len, decode_varint, decode_zigzag, encode_zigzag,
    parse_array_header, parse_map_header, read_len_slice, read_str_slice, validate_utf8,
};
use pyo3::exceptions::{PyAttributeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyBytes, PyDict, PyFloat, PyList, PySequence, PyString, PyTuple, PyType,
};

use crate::{
    ByteSliceOwner, DecodeBudget, InputBytes, LeafBytes, decode_err, encode_err,
    extract_max_elements, validate_field0_slice, validate_unknown_value,
};

thread_local! {
    static TLS_ENCODER: RefCell<Encoder> = RefCell::new(Encoder::new(4096));
    // Stores Copy `(cls_ptr, codec_obj_ptr, epoch)` tuples for GIL-protected lookup.
    // Entries carry no owning Python reference and are invalidated whenever
    // `DATACLASS_CODECS` evicts an entry by advancing `DATACLASS_CACHE_EPOCH`.
    static TLS_DC_CACHE: Cell<[(usize, usize, u64); 4]> = const { Cell::new([(0, 0, 0); 4]) };
}

const HAS_GIL: bool = core::mem::size_of::<ffi::PyObject>() == 2 * core::mem::size_of::<usize>();

static DATACLASS_CODECS: Mutex<Vec<(Py<PyType>, Py<CompiledCodec>)>> = Mutex::new(Vec::new());
static DATACLASS_CACHE_EPOCH: AtomicU64 = AtomicU64::new(1);
static DATACLASS_RESOLVER: OnceLock<Py<PyAny>> = OnceLock::new();

#[inline(always)]
fn decode_varint_fast(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let rem = data.len() - pos;
    unsafe {
        let ptr = data.as_ptr().add(pos);
        let b0 = *ptr;
        if (b0 & 1) != 0 {
            return Some((u64::from(b0 >> 1), 1));
        }
        if (b0 & 2) != 0 {
            if rem < 2 {
                return None;
            }
            let raw = core::ptr::read_unaligned(ptr.cast::<u16>());
            return Some((u64::from(u16::from_le(raw) >> 2), 2));
        }
        if (b0 & 4) != 0 {
            if rem < 4 {
                return None;
            }
            let raw = core::ptr::read_unaligned(ptr.cast::<u32>());
            return Some((u64::from(u32::from_le(raw) >> 3), 4));
        }
        if b0 == 0 {
            if rem < 9 {
                return None;
            }
            let raw = core::ptr::read_unaligned(ptr.add(1).cast::<u64>());
            return Some((u64::from_le(raw), 9));
        }
        None
    }
}

#[inline(always)]
fn read_len_slice_fast(
    data: &[u8],
    pos: usize,
    min_len: usize,
) -> Result<(&[u8], usize), &'static str> {
    let (len_u64, w) = decode_varint_fast(data, pos).ok_or("omnibuf: invalid length varint")?;
    let start = pos + w;
    let len = usize::try_from(len_u64).map_err(|_| "omnibuf: length overflow")?;
    if len < min_len {
        return Err("omnibuf: container length below minimum");
    }
    let end = start.checked_add(len).ok_or("omnibuf: length overflow")?;
    if end > data.len() {
        return Err("omnibuf: unexpected EOF reading length-prefixed value");
    }
    Ok((unsafe { data.get_unchecked(start..end) }, end))
}

#[inline(always)]
fn parse_array_header_fast(body: &[u8]) -> Option<(u8, usize, usize)> {
    let elem_wt = *body.first()?;
    if elem_wt >= 0x0F {
        // Defer to core parser for exact wire-type validation if needed
        return parse_array_header(body);
    }
    // Validate allowed array element wire types (all except WireBoolTrue=3, WireExtended=15, or >15)
    if elem_wt == WIRE_BOOL_TRUE {
        return None;
    }
    let (count_u64, w) = decode_varint_fast(body, 1)?;
    let count = usize::try_from(count_u64).ok()?;
    Some((elem_wt, count, 1 + w))
}

#[inline(always)]
unsafe fn py_str_from_utf8_fast(
    py: Python<'_>,
    bytes: &[u8],
    empty_str: *mut ffi::PyObject,
) -> PyResult<*mut ffi::PyObject> {
    let len = bytes.len();
    unsafe {
        if len == 0 {
            ffi::Py_INCREF(empty_str);
            return Ok(empty_str);
        }
        if len == 1 && *bytes.get_unchecked(0) < 0x80 {
            let ptr =
                ffi::PyUnicode_FromStringAndSize(bytes.as_ptr().cast::<std::os::raw::c_char>(), 1);
            if ptr.is_null() {
                return Err(PyErr::fetch(py));
            }
            return Ok(ptr);
        }
        if bytes.is_ascii() {
            let ptr = ffi::PyUnicode_New(len as ffi::Py_ssize_t, 127);
            if ptr.is_null() {
                return Err(PyErr::fetch(py));
            }
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                ptr.cast::<ffi::PyASCIIObject>().add(1).cast::<u8>(),
                len,
            );
            return Ok(ptr);
        }
        validate_utf8(bytes).map_err(|e| decode_err(py, e.to_string()))?;
        let ptr = ffi::PyUnicode_FromStringAndSize(
            bytes.as_ptr().cast::<std::os::raw::c_char>(),
            len as ffi::Py_ssize_t,
        );
        if ptr.is_null() {
            return Err(PyErr::fetch(py));
        }
        Ok(ptr)
    }
}

#[inline(always)]
unsafe fn py_long_from_u32(py: Python<'_>, v: u32) -> PyResult<*mut ffi::PyObject> {
    unsafe {
        let ptr = if std::mem::size_of::<std::os::raw::c_long>() >= 8 {
            ffi::PyLong_FromLong(v as std::os::raw::c_long)
        } else {
            ffi::PyLong_FromUnsignedLong(v as std::os::raw::c_ulong)
        };
        if ptr.is_null() {
            Err(PyErr::fetch(py))
        } else {
            Ok(ptr)
        }
    }
}

#[inline(always)]
unsafe fn py_long_from_i32(py: Python<'_>, v: i32) -> PyResult<*mut ffi::PyObject> {
    unsafe {
        let ptr = ffi::PyLong_FromLong(v as std::os::raw::c_long);
        if ptr.is_null() {
            Err(PyErr::fetch(py))
        } else {
            Ok(ptr)
        }
    }
}

#[inline(always)]
unsafe fn py_long_from_u64(py: Python<'_>, v: u64) -> PyResult<*mut ffi::PyObject> {
    unsafe {
        let ptr = if std::mem::size_of::<std::os::raw::c_long>() >= 8 && v <= i64::MAX as u64 {
            ffi::PyLong_FromLong(v as std::os::raw::c_long)
        } else {
            ffi::PyLong_FromUnsignedLongLong(v)
        };
        if ptr.is_null() {
            Err(PyErr::fetch(py))
        } else {
            Ok(ptr)
        }
    }
}

#[inline(always)]
unsafe fn py_long_from_i64(py: Python<'_>, v: i64) -> PyResult<*mut ffi::PyObject> {
    unsafe {
        let ptr = if std::mem::size_of::<std::os::raw::c_long>() >= 8 {
            ffi::PyLong_FromLong(v as std::os::raw::c_long)
        } else {
            ffi::PyLong_FromLongLong(v)
        };
        if ptr.is_null() {
            Err(PyErr::fetch(py))
        } else {
            Ok(ptr)
        }
    }
}

#[inline(always)]
unsafe fn py_float_from_f64(py: Python<'_>, v: f64) -> PyResult<*mut ffi::PyObject> {
    unsafe {
        let ptr = ffi::PyFloat_FromDouble(v);
        if ptr.is_null() {
            Err(PyErr::fetch(py))
        } else {
            Ok(ptr)
        }
    }
}

#[inline(always)]
unsafe fn put_varint_inline(ptr: *mut u8, v: u64) -> usize {
    unsafe {
        if v <= 127 {
            *ptr = ((v as u8) << 1) | 1;
            1
        } else if v <= 16_383 {
            let u = (((v as u16) << 2) | 2).to_le();
            core::ptr::write_unaligned(ptr.cast::<u16>(), u);
            2
        } else if v <= 536_870_911 {
            let u = (((v as u32) << 3) | 4).to_le();
            core::ptr::write_unaligned(ptr.cast::<u32>(), u);
            4
        } else {
            *ptr = 0x00;
            core::ptr::write_unaligned(ptr.add(1).cast::<u64>(), v.to_le());
            9
        }
    }
}

#[inline(always)]
unsafe fn slot_submsg_min_wire_size(
    cls_ptr: *mut ffi::PyTypeObject,
    inner: &CodecInner,
    obj_ptr: *mut ffi::PyObject,
) -> usize {
    unsafe {
        if obj_ptr.is_null() || !inner.fast_slot_encode || ffi::Py_IS_TYPE(obj_ptr, cls_ptr) == 0 {
            return 0;
        }
        let mut sz = inner.min_wire_reserve;
        for fp in &inner.fields {
            if let FieldPlanKind::Scalar { kind, .. } = &fp.kind {
                match kind {
                    ScalarKind::String | ScalarKind::StrAsBytes => {
                        let vp = *obj_ptr
                            .byte_add(fp.slot_offset)
                            .cast::<*mut ffi::PyObject>();
                        if !vp.is_null() && ffi::PyUnicode_CheckExact(vp) != 0 {
                            sz = sz.saturating_add(ffi::PyUnicode_GET_LENGTH(vp) as usize);
                        }
                    }
                    ScalarKind::Bytes | ScalarKind::BytesAsStr => {
                        let vp = *obj_ptr
                            .byte_add(fp.slot_offset)
                            .cast::<*mut ffi::PyObject>();
                        if !vp.is_null() && ffi::PyBytes_CheckExact(vp) != 0 {
                            sz = sz.saturating_add(ffi::PyBytes_Size(vp) as usize);
                        }
                    }
                    _ => {}
                }
            }
        }
        sz
    }
}

#[inline(always)]
fn backpatch_container_fast(dst: &mut Vec<u8>, len_pos: usize) {
    let sub_len = dst.len() - (len_pos + 2);
    if sub_len <= 16_383 {
        let u = (((sub_len as u16) << 2) | 2).to_le();
        unsafe {
            core::ptr::write_unaligned(dst.as_mut_ptr().add(len_pos).cast::<u16>(), u);
        }
    } else {
        backpatch_container_len(dst, len_pos);
    }
}

#[inline(always)]
fn backpatch_container_len4(dst: &mut Vec<u8>, len_pos: usize) {
    let sub_len = dst.len() - (len_pos + 4);
    if sub_len <= 536_870_911 {
        let u = (((sub_len as u32) << 3) | 4).to_le();
        unsafe {
            core::ptr::write_unaligned(dst.as_mut_ptr().add(len_pos).cast::<u32>(), u);
        }
    } else {
        let old_len = dst.len();
        dst.resize(old_len + 5, 0);
        dst.copy_within(len_pos + 4..old_len, len_pos + 9);
        dst[len_pos] = 0x00;
        dst[len_pos + 1..len_pos + 9].copy_from_slice(&(sub_len as u64).to_le_bytes());
    }
}

#[inline(always)]
fn write_raw_tag_and_len4_placeholder(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8) -> usize {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(13);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        let len_pos = len + tlen;
        core::ptr::write_unaligned(ptr.add(tlen).cast::<u32>(), 0);
        dst.set_len(len_pos + 4);
        len_pos
    }
}

#[inline(always)]
fn scalar_elem_min_wire_bytes(kind: ScalarKind) -> usize {
    match kind {
        ScalarKind::Bool
        | ScalarKind::Uint32
        | ScalarKind::Uint64
        | ScalarKind::Sint32
        | ScalarKind::Sint64
        | ScalarKind::Enum
        | ScalarKind::String
        | ScalarKind::StrAsBytes
        | ScalarKind::Bytes
        | ScalarKind::BytesAsStr => 1,
        ScalarKind::Fixed32 | ScalarKind::Sfixed32 | ScalarKind::Float32 => 4,
        ScalarKind::Fixed64 | ScalarKind::Sfixed64 | ScalarKind::Float64 => 8,
    }
}

#[inline(always)]
fn write_raw_tag(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8) {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(9);
    unsafe {
        let len = dst.len();
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), dst.as_mut_ptr().add(len), 9);
        dst.set_len(len + tlen);
    }
}

#[inline(always)]
fn write_raw_tag_and_len_placeholder(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8) -> usize {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(11);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        let len_pos = len + tlen;
        core::ptr::write_unaligned(ptr.add(tlen).cast::<u16>(), 0);
        dst.set_len(len_pos + 2);
        len_pos
    }
}

#[inline(always)]
fn write_raw_tagged_varint(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8, v: u64) {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(18);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        let vn = put_varint_inline(ptr.add(tlen), v);
        dst.set_len(len + tlen + vn);
    }
}

#[inline(always)]
fn write_raw_tagged_fixed4(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8, val: [u8; 4]) {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(13);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        core::ptr::copy_nonoverlapping(val.as_ptr(), ptr.add(tlen), 4);
        dst.set_len(len + tlen + 4);
    }
}

#[inline(always)]
fn write_raw_tagged_fixed8(dst: &mut Vec<u8>, tag_bytes: [u8; 9], tag_len: u8, val: [u8; 8]) {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(17);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        core::ptr::copy_nonoverlapping(val.as_ptr(), ptr.add(tlen), 8);
        dst.set_len(len + tlen + 8);
    }
}

// SAFETY: src_ptr must remain valid for blen bytes and must not alias dst.
#[inline(always)]
unsafe fn write_raw_tagged_bytes(
    dst: &mut Vec<u8>,
    tag_bytes: [u8; 9],
    tag_len: u8,
    src_ptr: *const u8,
    blen: usize,
) {
    let tlen = usize::from(tag_len).min(9);
    dst.reserve(blen.checked_add(18).expect("omnibuf: buffer size overflow"));
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), ptr, 9);
        let vn = put_varint_inline(ptr.add(tlen), blen as u64);
        if blen > 0 {
            core::ptr::copy_nonoverlapping(src_ptr, ptr.add(tlen + vn), blen);
        }
        dst.set_len(len + tlen + vn + blen);
    }
}

#[inline(always)]
unsafe fn write_raw_bytes_elem(dst: &mut Vec<u8>, src_ptr: *const u8, blen: usize) {
    dst.reserve(blen.checked_add(9).expect("omnibuf: buffer size overflow"));
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        let vn = put_varint_inline(ptr, blen as u64);
        if blen > 0 {
            core::ptr::copy_nonoverlapping(src_ptr, ptr.add(vn), blen);
        }
        dst.set_len(len + vn + blen);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarKind {
    Bool = 0,
    Uint32 = 1,
    Uint64 = 2,
    Sint32 = 3,
    Sint64 = 4,
    Enum = 5,
    Fixed32 = 6,
    Sfixed32 = 7,
    Fixed64 = 8,
    Sfixed64 = 9,
    Float32 = 10,
    Float64 = 11,
    String = 12,
    StrAsBytes = 13,
    Bytes = 14,
    BytesAsStr = 15,
}

impl ScalarKind {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "bool" => Some(Self::Bool),
            "uint32" => Some(Self::Uint32),
            "uint64" => Some(Self::Uint64),
            "sint32" => Some(Self::Sint32),
            "sint64" => Some(Self::Sint64),
            "enum" => Some(Self::Enum),
            "fixed32" => Some(Self::Fixed32),
            "sfixed32" => Some(Self::Sfixed32),
            "fixed64" => Some(Self::Fixed64),
            "sfixed64" => Some(Self::Sfixed64),
            "float32" => Some(Self::Float32),
            "float64" => Some(Self::Float64),
            "string" => Some(Self::String),
            "str_as_bytes" => Some(Self::StrAsBytes),
            "bytes" => Some(Self::Bytes),
            "bytes_as_str" => Some(Self::BytesAsStr),
            _ => None,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Bool),
            1 => Some(Self::Uint32),
            2 => Some(Self::Uint64),
            3 => Some(Self::Sint32),
            4 => Some(Self::Sint64),
            5 => Some(Self::Enum),
            6 => Some(Self::Fixed32),
            7 => Some(Self::Sfixed32),
            8 => Some(Self::Fixed64),
            9 => Some(Self::Sfixed64),
            10 => Some(Self::Float32),
            11 => Some(Self::Float64),
            12 => Some(Self::String),
            13 => Some(Self::StrAsBytes),
            14 => Some(Self::Bytes),
            15 => Some(Self::BytesAsStr),
            _ => None,
        }
    }
}

/// Returns `true` iff reading `ptr` as `kind` uses pure CPython struct access without executing
/// any Python dunder methods (`__index__`, `__int__`, `__float__`, `__bool__`, `__buffer__`).
#[inline]
unsafe fn is_exact_primitive(kind: ScalarKind, ptr: *mut ffi::PyObject) -> bool {
    unsafe {
        match kind {
            ScalarKind::Bool => ptr == ffi::Py_True() || ptr == ffi::Py_False(),
            ScalarKind::Uint32
            | ScalarKind::Uint64
            | ScalarKind::Sint32
            | ScalarKind::Sint64
            | ScalarKind::Enum
            | ScalarKind::Fixed32
            | ScalarKind::Sfixed32
            | ScalarKind::Fixed64
            | ScalarKind::Sfixed64 => ffi::PyLong_CheckExact(ptr) != 0,
            ScalarKind::Float32 | ScalarKind::Float64 => {
                ffi::PyFloat_CheckExact(ptr) != 0 || ffi::PyLong_CheckExact(ptr) != 0
            }
            ScalarKind::String | ScalarKind::StrAsBytes => ffi::PyUnicode_CheckExact(ptr) != 0,
            ScalarKind::Bytes | ScalarKind::BytesAsStr => ffi::PyBytes_CheckExact(ptr) != 0,
        }
    }
}

struct SlotBinding {
    descr: Py<PyAny>,
    get_fn: ffi::descrgetfunc,
    set_fn: ffi::descrsetfunc,
    cls_ptr: *mut ffi::PyObject,
    direct_offset: Option<usize>,
    direct_writable: bool,
}

// SAFETY: All Python pointer operations happen only while holding a `Python<'_>` token,
// and `descr` + the parent `CompiledCodec::cls` keep both Python objects alive.
unsafe impl Send for SlotBinding {}
unsafe impl Sync for SlotBinding {}

enum FieldAccess {
    Slot(SlotBinding),
    Attr(Py<PyString>),
}

impl FieldAccess {
    #[inline]
    fn get<'py>(
        &self,
        py: Python<'py>,
        obj_ptr: *mut ffi::PyObject,
    ) -> PyResult<Bound<'py, PyAny>> {
        unsafe {
            match self {
                Self::Slot(sb) => {
                    if let Some(offset) = sb.direct_offset
                        && ffi::Py_IS_TYPE(obj_ptr, sb.cls_ptr.cast::<ffi::PyTypeObject>()) != 0
                    {
                        let slot_val = *obj_ptr.byte_add(offset).cast::<*mut ffi::PyObject>();
                        if !slot_val.is_null() {
                            ffi::Py_INCREF(slot_val);
                            return Ok(Bound::from_owned_ptr(py, slot_val));
                        }
                    }
                    let ptr = (sb.get_fn)(sb.descr.as_ptr(), obj_ptr, sb.cls_ptr);
                    Bound::from_owned_ptr_or_err(py, ptr)
                }
                Self::Attr(attr) => {
                    let ptr = ffi::PyObject_GetAttr(obj_ptr, attr.as_ptr());
                    Bound::from_owned_ptr_or_err(py, ptr)
                }
            }
        }
    }

    #[inline]
    fn get_optional<'py>(
        &self,
        py: Python<'py>,
        obj_ptr: *mut ffi::PyObject,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        unsafe {
            match self {
                Self::Slot(sb) => {
                    if let Some(offset) = sb.direct_offset
                        && ffi::Py_IS_TYPE(obj_ptr, sb.cls_ptr.cast::<ffi::PyTypeObject>()) != 0
                    {
                        let slot_val = *obj_ptr.byte_add(offset).cast::<*mut ffi::PyObject>();
                        if slot_val.is_null() || slot_val == ffi::Py_None() {
                            return Ok(None);
                        }
                        ffi::Py_INCREF(slot_val);
                        return Ok(Some(Bound::from_owned_ptr(py, slot_val)));
                    }
                    let ptr = (sb.get_fn)(sb.descr.as_ptr(), obj_ptr, sb.cls_ptr);
                    if ptr.is_null() {
                        let err = PyErr::fetch(py);
                        if err.is_instance_of::<PyAttributeError>(py) {
                            return Ok(None);
                        }
                        return Err(err);
                    }
                    if ptr == ffi::Py_None() {
                        ffi::Py_DECREF(ptr);
                        return Ok(None);
                    }
                    Ok(Some(Bound::from_owned_ptr(py, ptr)))
                }
                Self::Attr(attr) => {
                    let ptr = ffi::PyObject_GetAttr(obj_ptr, attr.as_ptr());
                    if ptr.is_null() {
                        let err = PyErr::fetch(py);
                        if err.is_instance_of::<PyAttributeError>(py) {
                            return Ok(None);
                        }
                        return Err(err);
                    }
                    if ptr == ffi::Py_None() {
                        ffi::Py_DECREF(ptr);
                        return Ok(None);
                    }
                    Ok(Some(Bound::from_owned_ptr(py, ptr)))
                }
            }
        }
    }

    #[inline]
    fn set(
        &self,
        py: Python<'_>,
        obj_ptr: *mut ffi::PyObject,
        val_ptr: *mut ffi::PyObject,
    ) -> PyResult<()> {
        unsafe {
            if let Self::Slot(sb) = self
                && sb.direct_writable
                && let Some(offset) = sb.direct_offset
                && !val_ptr.is_null()
                && ffi::Py_IS_TYPE(obj_ptr, sb.cls_ptr.cast::<ffi::PyTypeObject>()) != 0
            {
                let slot = obj_ptr.byte_add(offset).cast::<*mut ffi::PyObject>();
                ffi::Py_INCREF(val_ptr);
                let old = *slot;
                *slot = val_ptr;
                ffi::Py_XDECREF(old);
                return Ok(());
            }
            let rc = match self {
                Self::Slot(sb) => (sb.set_fn)(sb.descr.as_ptr(), obj_ptr, val_ptr),
                Self::Attr(attr) => ffi::PyObject_SetAttr(obj_ptr, attr.as_ptr(), val_ptr),
            };
            if rc != 0 {
                Err(PyErr::fetch(py))
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    fn set_owned<'py>(
        &self,
        py: Python<'py>,
        obj_ptr: *mut ffi::PyObject,
        val_obj: Bound<'py, PyAny>,
    ) -> PyResult<()> {
        unsafe {
            if let Self::Slot(sb) = self
                && sb.direct_writable
                && let Some(offset) = sb.direct_offset
                && ffi::Py_IS_TYPE(obj_ptr, sb.cls_ptr.cast::<ffi::PyTypeObject>()) != 0
            {
                let raw_val = val_obj.into_ptr();
                let slot = obj_ptr.byte_add(offset).cast::<*mut ffi::PyObject>();
                let old = *slot;
                *slot = raw_val;
                ffi::Py_XDECREF(old);
                return Ok(());
            }
            self.set(py, obj_ptr, val_obj.as_ptr())
        }
    }
}

enum MapValPlan {
    Scalar {
        kind: ScalarKind,
        enum_cls: Option<Py<PyAny>>,
    },
    SubMsg(Py<CompiledCodec>),
}

enum FieldPlanKind {
    Scalar {
        kind: ScalarKind,
        enum_cls: Option<Py<PyAny>>,
    },
    SubMsg {
        codec: Py<CompiledCodec>,
    },
    ArrayScalar {
        elem_kind: ScalarKind,
        elem_wt: u8,
        enum_cls: Option<Py<PyAny>>,
    },
    ArraySubMsg {
        codec: Py<CompiledCodec>,
    },
    Map {
        key_kind: ScalarKind,
        key_wt: u8,
        val_wt: u8,
        val_plan: MapValPlan,
    },
}

enum DefaultPlan {
    Const(Py<PyAny>),
    EmptyList,
    EmptyDict,
    SubMsg(Py<CompiledCodec>),
    Factory(Py<PyAny>),
    PbpySkip,
}

struct FieldPlan {
    index: usize,
    field_num: u32,
    attr_str: Py<PyString>,
    wire_name: String,
    access: FieldAccess,
    slot_offset: usize,
    wire_type: u8,
    tag_bytes: [u8; 9],
    tag_len: u8,
    tag_false_bytes: [u8; 9],
    tag_false_len: u8,
    tag_true_bytes: [u8; 9],
    tag_true_len: u8,
    skip_if_none: bool,
    pbpy_presence: bool,
    omitempty: bool,
    oneof_siblings: Box<[usize]>,
    kind: FieldPlanKind,
    default_plan: DefaultPlan,
}

impl FieldPlan {
    #[inline(always)]
    fn write_tag_to(&self, dst: &mut Vec<u8>) {
        write_raw_tag(dst, self.tag_bytes, self.tag_len);
    }

    #[inline(always)]
    fn write_bool_tag_to(&self, dst: &mut Vec<u8>, is_true: bool) {
        if is_true {
            write_raw_tag(dst, self.tag_true_bytes, self.tag_true_len);
        } else {
            write_raw_tag(dst, self.tag_false_bytes, self.tag_false_len);
        }
    }

    fn make_default<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.default_plan {
            DefaultPlan::Const(obj) => Ok(Some(obj.bind(py).clone())),
            DefaultPlan::EmptyList => Ok(Some(PyList::empty(py).into_any())),
            DefaultPlan::EmptyDict => Ok(Some(PyDict::new(py).into_any())),
            DefaultPlan::SubMsg(sub) => Ok(Some(sub.get().alloc_default_instance(py)?)),
            DefaultPlan::Factory(fac) => Ok(Some(fac.bind(py).call0()?)),
            DefaultPlan::PbpySkip => Ok(None),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FastKind {
    Bool = 0,
    Uint32 = 1,
    Uint64 = 2,
    Sint32 = 3,
    Sint64 = 4,
    Enum = 5,
    Fixed32 = 6,
    Sfixed32 = 7,
    Fixed64 = 8,
    Sfixed64 = 9,
    Float32 = 10,
    Float64 = 11,
    String = 12,
    Bytes = 13,
    BytesAsStr = 14,
    SubMsg = 15,
    ArrayScalar = 16,
    ArraySubMsg = 17,
    Map = 18,
}

#[derive(Clone, Copy)]
struct FastDecodeField {
    slot_offset: u16,
    kind: FastKind,
    wire_type: u8,
    elem_kind: ScalarKind,
    elem_wt: u8,
    has_enum_cls: bool,
    sub_codec: *const CompiledCodec,
    sub_inner: *const CodecInner,
}

// SAFETY: `sub_codec` points to a `CompiledCodec` owned by `CodecInner::fields` and is only
// dereferenced while holding a `Python<'_>` GIL token.
unsafe impl Send for FastDecodeField {}
unsafe impl Sync for FastDecodeField {}

struct CodecInner {
    fields: Vec<FieldPlan>,
    fast_decode_fields: Vec<FastDecodeField>,
    fast_tag_map: [u8; 128],
    dense_by_num: Vec<u16>,
    field0_wire: Vec<u8>,
    fast_alloc: bool,
    fast_slot_encode: bool,
    fast_slot_decode: bool,
    tp_alloc: Option<ffi::allocfunc>,
    empty_str: Py<PyString>,
    min_wire_reserve: usize,
    all_seen_mask_64: u64,
    has_field_intern: Py<PyString>,
    clear_field_intern: Py<PyString>,
}

// SAFETY: `tp_alloc` is a CPython function pointer only invoked while holding `Python<'_>`.
unsafe impl Send for CodecInner {}
unsafe impl Sync for CodecInner {}

#[pyclass(frozen)]
pub struct CompiledCodec {
    cls: Py<PyType>,
    type_name: String,
    req_fast_alloc: bool,
    pbpy_mode: bool,
    inner: OnceLock<CodecInner>,
    recursive: OnceLock<bool>,
}

fn encode_tag_inline(fnum: u32, wt: u8) -> ([u8; 9], u8) {
    let mut v = Vec::with_capacity(5);
    append_tag(&mut v, fnum, wt);
    let mut arr = [0u8; 9];
    let len = v.len();
    arr[..len].copy_from_slice(&v);
    (arr, len as u8)
}

#[inline]
pub(crate) fn extract_enum_i64(
    py: Python<'_>,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<i64> {
    unsafe {
        if ffi::PyBool_Check(ptr) != 0 {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} expected enum/int, got bool"),
            ));
        }
        if ffi::PyLong_Check(ptr) != 0 {
            return extract_i64(py, ptr, field_name);
        }
        let borrowed = Borrowed::from_ptr(py, ptr);
        if let Ok(val_attr) = borrowed.getattr("value")
            && ffi::PyBool_Check(val_attr.as_ptr()) == 0
            && ffi::PyLong_Check(val_attr.as_ptr()) != 0
        {
            return extract_i64(py, val_attr.as_ptr(), field_name);
        }
        Err(encode_err(
            py,
            format!("omnibuf: field {field_name} invalid enum value"),
        ))
    }
}

#[inline]
pub(crate) fn extract_i64(
    py: Python<'_>,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<i64> {
    unsafe {
        if ffi::PyLong_CheckExact(ptr) != 0 {
            let mut overflow: std::os::raw::c_int = 0;
            let v = ffi::PyLong_AsLongLongAndOverflow(ptr, &mut overflow);
            if overflow != 0 {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} integer out of range"),
                ));
            }
            return Ok(v);
        }
        if ffi::PyBool_Check(ptr) != 0 {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} expected int, got bool"),
            ));
        }
        if ptr == ffi::Py_None() {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} cannot be None"),
            ));
        }
        let mut overflow: std::os::raw::c_int = 0;
        let v = ffi::PyLong_AsLongLongAndOverflow(ptr, &mut overflow);
        if overflow != 0 {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} integer out of range"),
            ));
        }
        if v == -1 && !ffi::PyErr_Occurred().is_null() {
            let err = PyErr::fetch(py);
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} invalid int: {err}"),
            ));
        }
        Ok(v)
    }
}

#[inline]
pub(crate) fn extract_u64(
    py: Python<'_>,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<u64> {
    unsafe {
        if ffi::PyLong_CheckExact(ptr) != 0 {
            let mut overflow: std::os::raw::c_int = 0;
            let v = ffi::PyLong_AsLongLongAndOverflow(ptr, &mut overflow);
            if overflow == 0 {
                if v >= 0 {
                    return Ok(v as u64);
                }
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} uint64 out of range"),
                ));
            }
            if overflow > 0 {
                let u = ffi::PyLong_AsUnsignedLongLong(ptr);
                if u == u64::MAX && !ffi::PyErr_Occurred().is_null() {
                    ffi::PyErr_Clear();
                    return Err(encode_err(
                        py,
                        format!("omnibuf: field {field_name} uint64 out of range"),
                    ));
                }
                return Ok(u);
            }
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} uint64 out of range"),
            ));
        }
        if ffi::PyBool_Check(ptr) != 0 {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} expected int, got bool"),
            ));
        }
        if ptr == ffi::Py_None() {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} cannot be None"),
            ));
        }
        let v = ffi::PyLong_AsUnsignedLongLong(ptr);
        if v == u64::MAX && !ffi::PyErr_Occurred().is_null() {
            ffi::PyErr_Clear();
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} uint64 out of range"),
            ));
        }
        Ok(v)
    }
}

#[inline]
pub(crate) fn extract_f64(
    py: Python<'_>,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<f64> {
    unsafe {
        if ffi::PyFloat_CheckExact(ptr) != 0 {
            return Ok(ffi::PyFloat_AS_DOUBLE(ptr));
        }
        if ffi::PyBool_Check(ptr) != 0 {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} expected float, got bool"),
            ));
        }
        if ptr == ffi::Py_None() {
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} cannot be None"),
            ));
        }
        let v = ffi::PyFloat_AsDouble(ptr);
        if v == -1.0 && !ffi::PyErr_Occurred().is_null() {
            let err = PyErr::fetch(py);
            return Err(encode_err(
                py,
                format!("omnibuf: field {field_name} invalid float: {err}"),
            ));
        }
        Ok(v)
    }
}

#[inline]
pub(crate) fn extract_bool(py: Python<'_>, ptr: *mut ffi::PyObject) -> PyResult<bool> {
    unsafe {
        if ptr == ffi::Py_True() {
            return Ok(true);
        }
        if ptr == ffi::Py_False() {
            return Ok(false);
        }
        if ptr == ffi::Py_None() {
            return Err(encode_err(py, "omnibuf: bool value cannot be None"));
        }
        Err(encode_err(py, "omnibuf: bool field expected bool"))
    }
}

#[inline]
pub(crate) fn write_scalar_payload(
    py: Python<'_>,
    dst: &mut Vec<u8>,
    kind: ScalarKind,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<()> {
    match kind {
        ScalarKind::Bool => {
            dst.push(u8::from(extract_bool(py, ptr)?));
        }
        ScalarKind::Uint32 => {
            let v = extract_i64(py, ptr, field_name)?;
            if (v as u64) > u64::from(u32::MAX) {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} uint32 {v} out of range"),
                ));
            }
            append_varint(dst, v as u64);
        }
        ScalarKind::Uint64 => {
            let v = extract_u64(py, ptr, field_name)?;
            append_varint(dst, v);
        }
        ScalarKind::Sint32 => {
            let v = extract_i64(py, ptr, field_name)?;
            let Ok(v32) = i32::try_from(v) else {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} sint32 {v} out of range"),
                ));
            };
            let zz32 = u64::from(((v32 << 1) ^ (v32 >> 31)) as u32);
            append_varint(dst, zz32);
        }
        ScalarKind::Enum => {
            let v = extract_enum_i64(py, ptr, field_name)?;
            let Ok(v32) = i32::try_from(v) else {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} enum {v} out of range"),
                ));
            };
            let zz32 = u64::from(((v32 << 1) ^ (v32 >> 31)) as u32);
            append_varint(dst, zz32);
        }
        ScalarKind::Sint64 => {
            let v = extract_i64(py, ptr, field_name)?;
            append_varint(dst, encode_zigzag(v));
        }
        ScalarKind::Fixed32 => {
            let v = extract_i64(py, ptr, field_name)?;
            let Ok(u) = u32::try_from(v) else {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} fixed32 {v} out of range"),
                ));
            };
            dst.extend_from_slice(&u.to_le_bytes());
        }
        ScalarKind::Sfixed32 => {
            let v = extract_i64(py, ptr, field_name)?;
            let Ok(i) = i32::try_from(v) else {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} sfixed32 {v} out of range"),
                ));
            };
            dst.extend_from_slice(&i.to_le_bytes());
        }
        ScalarKind::Fixed64 => {
            let v = extract_u64(py, ptr, field_name)?;
            dst.extend_from_slice(&v.to_le_bytes());
        }
        ScalarKind::Sfixed64 => {
            let v = extract_i64(py, ptr, field_name)?;
            dst.extend_from_slice(&v.to_le_bytes());
        }
        ScalarKind::Float32 => {
            let v = extract_f64(py, ptr, field_name)?;
            let f = v as f32;
            if v.is_finite() && !f.is_finite() {
                return Err(encode_err(
                    py,
                    format!("omnibuf: field {field_name} float32 overflow"),
                ));
            }
            dst.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        ScalarKind::Float64 => {
            let v = extract_f64(py, ptr, field_name)?;
            dst.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        ScalarKind::String | ScalarKind::StrAsBytes => unsafe {
            let mut size: ffi::Py_ssize_t = 0;
            let utf8_ptr = ffi::PyUnicode_AsUTF8AndSize(ptr, &mut size);
            if utf8_ptr.is_null() {
                let err = PyErr::fetch(py);
                return Err(encode_err(
                    py,
                    format!("omnibuf: invalid UTF-8 in field {field_name}: {err}"),
                ));
            }
            write_raw_bytes_elem(dst, utf8_ptr.cast::<u8>(), size as usize);
        },
        ScalarKind::Bytes => {
            let obj = unsafe { Borrowed::from_ptr(py, ptr) };
            let borrowed = LeafBytes::extract(py, &obj)
                .map_err(|err| encode_err(py, format!("omnibuf: field {field_name}: {err}")))?;
            let slice = borrowed.as_slice();
            unsafe {
                write_raw_bytes_elem(dst, slice.as_ptr(), slice.len());
            }
        }
        ScalarKind::BytesAsStr => {
            let obj = unsafe { Borrowed::from_ptr(py, ptr) };
            let borrowed = LeafBytes::extract(py, &obj)
                .map_err(|err| encode_err(py, format!("omnibuf: field {field_name}: {err}")))?;
            let slice = borrowed.as_slice();
            validate_utf8(slice).map_err(|e| encode_err(py, e.to_string()))?;
            unsafe {
                write_raw_bytes_elem(dst, slice.as_ptr(), slice.len());
            }
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn read_scalar_payload<'py>(
    py: Python<'py>,
    data: &[u8],
    pos: usize,
    kind: ScalarKind,
    enum_cls: Option<&Py<PyAny>>,
    zc_owner: Option<(&ByteSliceOwner, usize)>,
) -> PyResult<(Bound<'py, PyAny>, usize)> {
    let rem = data
        .get(pos..)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated scalar payload"))?;
    match kind {
        ScalarKind::Bool => {
            let b = *rem
                .first()
                .ok_or_else(|| decode_err(py, "omnibuf: truncated bool element"))?;
            if b > 1 {
                return Err(decode_err(
                    py,
                    format!("omnibuf: invalid bool byte 0x{b:02x}"),
                ));
            }
            Ok((PyBool::new(py, b == 1).to_owned().into_any(), pos + 1))
        }
        ScalarKind::Uint32 => {
            let (v, w) = if let Some(&b0) = rem.first()
                && (b0 & 1) != 0
            {
                (u64::from(b0 >> 1), 1)
            } else {
                decode_varint(rem)
                    .ok_or_else(|| decode_err(py, "omnibuf: invalid uint32 varint"))?
            };
            let u32_val = u64::from(v as u32);
            let obj = unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u32_val))?
            };
            Ok((obj, pos + w))
        }
        ScalarKind::Uint64 => {
            let (v, w) = if let Some(&b0) = rem.first()
                && (b0 & 1) != 0
            {
                (u64::from(b0 >> 1), 1)
            } else {
                decode_varint(rem)
                    .ok_or_else(|| decode_err(py, "omnibuf: invalid uint64 varint"))?
            };
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v))? };
            Ok((obj, pos + w))
        }
        ScalarKind::Sint32 => {
            let (v, w) = if let Some(&b0) = rem.first()
                && (b0 & 1) != 0
            {
                (u64::from(b0 >> 1), 1)
            } else {
                decode_varint(rem)
                    .ok_or_else(|| decode_err(py, "omnibuf: invalid sint32 varint"))?
            };
            let i32_val = i64::from(decode_zigzag(v) as i32);
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i32_val))? };
            Ok((obj, pos + w))
        }
        ScalarKind::Enum => {
            let (v, w) = if let Some(&b0) = rem.first()
                && (b0 & 1) != 0
            {
                (u64::from(b0 >> 1), 1)
            } else {
                decode_varint(rem).ok_or_else(|| decode_err(py, "omnibuf: invalid enum varint"))?
            };
            let i32_val = i64::from(decode_zigzag(v) as i32);
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i32_val))? };
            if let Some(e_cls) = enum_cls {
                let wrapped = match e_cls.bind(py).call1((&obj,)) {
                    Ok(w_obj) => w_obj,
                    Err(err) if err.is_instance_of::<PyValueError>(py) => {
                        let is_int_enum = unsafe {
                            ffi::PyType_Check(e_cls.as_ptr()) != 0
                                && ffi::PyType_IsSubtype(
                                    e_cls.as_ptr().cast::<ffi::PyTypeObject>(),
                                    std::ptr::addr_of_mut!(ffi::PyLong_Type),
                                ) != 0
                        };
                        if is_int_enum {
                            obj
                        } else {
                            return Err(decode_err(
                                py,
                                format!("omnibuf: invalid enum value {i32_val}: {err}"),
                            ));
                        }
                    }
                    Err(err) => return Err(err),
                };
                Ok((wrapped, pos + w))
            } else {
                Ok((obj, pos + w))
            }
        }
        ScalarKind::Sint64 => {
            let (v, w) = if let Some(&b0) = rem.first()
                && (b0 & 1) != 0
            {
                (u64::from(b0 >> 1), 1)
            } else {
                decode_varint(rem)
                    .ok_or_else(|| decode_err(py, "omnibuf: invalid sint64 varint"))?
            };
            let i64_val = decode_zigzag(v);
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i64_val))? };
            Ok((obj, pos + w))
        }
        ScalarKind::Fixed32 => {
            let raw: [u8; 4] = rem
                .get(..4)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated fixed32"))?
                .try_into()
                .unwrap();
            let u = u64::from(u32::from_le_bytes(raw));
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u))? };
            Ok((obj, pos + 4))
        }
        ScalarKind::Sfixed32 => {
            let raw: [u8; 4] = rem
                .get(..4)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated sfixed32"))?
                .try_into()
                .unwrap();
            let i = i64::from(i32::from_le_bytes(raw));
            let obj = unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i))? };
            Ok((obj, pos + 4))
        }
        ScalarKind::Fixed64 => {
            let raw: [u8; 8] = rem
                .get(..8)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated fixed64"))?
                .try_into()
                .unwrap();
            let u = u64::from_le_bytes(raw);
            let obj =
                unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u))? };
            Ok((obj, pos + 8))
        }
        ScalarKind::Sfixed64 => {
            let raw: [u8; 8] = rem
                .get(..8)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated sfixed64"))?
                .try_into()
                .unwrap();
            let i = i64::from_le_bytes(raw);
            let obj = unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i))? };
            Ok((obj, pos + 8))
        }
        ScalarKind::Float32 => {
            let raw: [u8; 4] = rem
                .get(..4)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated float32"))?
                .try_into()
                .unwrap();
            let f = f64::from(f32::from_bits(u32::from_le_bytes(raw)));
            Ok((PyFloat::new(py, f).into_any(), pos + 4))
        }
        ScalarKind::Float64 => {
            let raw: [u8; 8] = rem
                .get(..8)
                .ok_or_else(|| decode_err(py, "omnibuf: truncated float64"))?
                .try_into()
                .unwrap();
            let f = f64::from_bits(u64::from_le_bytes(raw));
            Ok((PyFloat::new(py, f).into_any(), pos + 8))
        }
        ScalarKind::String | ScalarKind::StrAsBytes => {
            let (s, next_pos) =
                read_str_slice(data, pos).map_err(|e| decode_err(py, e.to_string()))?;
            let obj = unsafe {
                Bound::from_owned_ptr_or_err(
                    py,
                    ffi::PyUnicode_FromStringAndSize(
                        s.as_ptr().cast::<std::os::raw::c_char>(),
                        s.len() as ffi::Py_ssize_t,
                    ),
                )?
            };
            Ok((obj, next_pos))
        }
        ScalarKind::Bytes => {
            let (b, next_pos) =
                read_len_slice(data, pos, 0).map_err(|e| decode_err(py, e.to_string()))?;
            if let Some((owner, base_offset)) = zc_owner {
                let rel_start = base_offset + (next_pos - b.len());
                let rel_end = base_offset + next_pos;
                let mv = owner.to_readonly_memoryview(py, rel_start, rel_end)?;
                return Ok((mv, next_pos));
            }
            Ok((PyBytes::new(py, b).into_any(), next_pos))
        }
        ScalarKind::BytesAsStr => {
            let (b, next_pos) =
                read_len_slice(data, pos, 0).map_err(|e| decode_err(py, e.to_string()))?;
            validate_utf8(b).map_err(|e| decode_err(py, e.to_string()))?;
            if let Some((owner, base_offset)) = zc_owner {
                let rel_start = base_offset + (next_pos - b.len());
                let rel_end = base_offset + next_pos;
                let mv = owner.to_readonly_memoryview(py, rel_start, rel_end)?;
                return Ok((mv, next_pos));
            }
            Ok((PyBytes::new(py, b).into_any(), next_pos))
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortableMapKey {
    Str(String),
    Uint(u64),
    Sint(i64),
    Bool(bool),
}

fn extract_sortable_key(
    py: Python<'_>,
    kind: ScalarKind,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<SortableMapKey> {
    match kind {
        ScalarKind::String | ScalarKind::StrAsBytes => unsafe {
            let mut size: ffi::Py_ssize_t = 0;
            let utf8_ptr = ffi::PyUnicode_AsUTF8AndSize(ptr, &mut size);
            if utf8_ptr.is_null() {
                let err = PyErr::fetch(py);
                return Err(encode_err(py, format!("omnibuf: invalid UTF-8 key: {err}")));
            }
            let slice = std::slice::from_raw_parts(utf8_ptr.cast::<u8>(), size as usize);
            Ok(SortableMapKey::Str(
                std::str::from_utf8(slice)
                    .map_err(|e| encode_err(py, e.to_string()))?
                    .to_owned(),
            ))
        },
        ScalarKind::Uint32 | ScalarKind::Fixed32 => {
            let v = extract_i64(py, ptr, field_name)?;
            if !(0..=i64::from(u32::MAX)).contains(&v) {
                return Err(encode_err(py, "omnibuf: map u32 key out of range"));
            }
            Ok(SortableMapKey::Uint(v as u64))
        }
        ScalarKind::Uint64 | ScalarKind::Fixed64 => {
            Ok(SortableMapKey::Uint(extract_u64(py, ptr, field_name)?))
        }
        ScalarKind::Sint32 | ScalarKind::Sfixed32 | ScalarKind::Sint64 | ScalarKind::Sfixed64 => {
            Ok(SortableMapKey::Sint(extract_i64(py, ptr, field_name)?))
        }
        ScalarKind::Enum => Ok(SortableMapKey::Sint(extract_enum_i64(py, ptr, field_name)?)),
        ScalarKind::Bool => Ok(SortableMapKey::Bool(extract_bool(py, ptr)?)),
        _ => Err(encode_err(py, "omnibuf: unsupported map key kind")),
    }
}

impl CompiledCodec {
    #[inline]
    fn inner_plan(&self, py: Python<'_>) -> PyResult<&CodecInner> {
        self.inner.get().ok_or_else(|| {
            encode_err(
                py,
                format!("omnibuf: codec {} not initialized", self.type_name),
            )
        })
    }

    pub fn field0_bytes(&self) -> &[u8] {
        self.inner.get().map_or(&[], |i| i.field0_wire.as_slice())
    }

    pub fn is_recursive(&self) -> bool {
        *self.recursive.get_or_init(|| {
            let mut active = HashSet::new();
            self.detect_cycle(&mut active)
        })
    }

    fn detect_cycle(&self, active: &mut HashSet<usize>) -> bool {
        let addr = std::ptr::from_ref(self) as usize;
        if !active.insert(addr) {
            return true;
        }
        let Some(inner) = self.inner.get() else {
            active.remove(&addr);
            return false;
        };
        for fp in &inner.fields {
            let cyc = match &fp.kind {
                FieldPlanKind::SubMsg { codec } | FieldPlanKind::ArraySubMsg { codec } => {
                    codec.get().detect_cycle(active)
                }
                FieldPlanKind::Map {
                    val_plan: MapValPlan::SubMsg(codec),
                    ..
                } => codec.get().detect_cycle(active),
                _ => false,
            };
            if cyc {
                active.remove(&addr);
                return true;
            }
        }
        active.remove(&addr);
        false
    }

    fn build_static_schema_meta(
        &self,
        py: Python<'_>,
        schema_depth: usize,
        active: &mut HashSet<usize>,
    ) -> PyResult<CoreSchemaMeta> {
        let addr = std::ptr::from_ref(self) as usize;
        let inner = self.inner_plan(py)?;
        let mut meta = CoreSchemaMeta {
            type_name: self.type_name.clone(),
            ..CoreSchemaMeta::default()
        };
        if schema_depth + 1 > MAX_NESTING_DEPTH {
            return Ok(meta);
        }
        for fp in &inner.fields {
            meta.fields.insert(fp.field_num, fp.wire_name.clone());
        }
        if schema_depth + 3 > MAX_NESTING_DEPTH || !active.insert(addr) {
            return Ok(meta);
        }
        for fp in &inner.fields {
            let sub_opt = match &fp.kind {
                FieldPlanKind::SubMsg { codec } | FieldPlanKind::ArraySubMsg { codec } => {
                    Some(codec.get())
                }
                FieldPlanKind::Map {
                    val_plan: MapValPlan::SubMsg(codec),
                    ..
                } => Some(codec.get()),
                _ => None,
            };
            if let Some(sub) = sub_opt {
                let sub_addr = std::ptr::from_ref(sub) as usize;
                if !active.contains(&sub_addr) {
                    let child = sub.build_static_schema_meta(py, schema_depth + 2, active)?;
                    meta.children.insert(fp.field_num, child);
                }
            }
        }
        active.remove(&addr);
        Ok(meta)
    }

    fn build_instance_schema_meta(
        &self,
        py: Python<'_>,
        obj_ptr: *mut ffi::PyObject,
        schema_depth: usize,
    ) -> PyResult<CoreSchemaMeta> {
        let inner = self.inner_plan(py)?;
        let mut meta = CoreSchemaMeta {
            type_name: self.type_name.clone(),
            ..CoreSchemaMeta::default()
        };
        if schema_depth + 1 > MAX_NESTING_DEPTH {
            return Ok(meta);
        }
        for fp in &inner.fields {
            meta.fields.insert(fp.field_num, fp.wire_name.clone());
        }
        if schema_depth + 3 > MAX_NESTING_DEPTH {
            return Ok(meta);
        }
        let obj_bound = unsafe { Borrowed::from_ptr(py, obj_ptr) };
        for fp in &inner.fields {
            match &fp.kind {
                FieldPlanKind::SubMsg { codec } => {
                    let sub = codec.get();
                    if !sub.is_recursive() {
                        let mut active = HashSet::new();
                        let child =
                            sub.build_static_schema_meta(py, schema_depth + 2, &mut active)?;
                        meta.children.insert(fp.field_num, child);
                        continue;
                    }
                    if fp.pbpy_presence {
                        let has: bool = obj_bound
                            .call_method1(&inner.has_field_intern, (&fp.attr_str,))?
                            .extract()?;
                        if !has {
                            continue;
                        }
                    }
                    let raw_val = fp.access.get(py, obj_ptr)?;
                    if raw_val.is_none()
                        || (fp.omitempty && self.is_value_empty(py, fp, &raw_val, 0)?)
                    {
                        continue;
                    }
                    let child =
                        sub.build_instance_schema_meta(py, raw_val.as_ptr(), schema_depth + 2)?;
                    meta.children.insert(fp.field_num, child);
                }
                FieldPlanKind::ArraySubMsg { codec } => {
                    let sub = codec.get();
                    if !sub.is_recursive() {
                        let mut active = HashSet::new();
                        let child =
                            sub.build_static_schema_meta(py, schema_depth + 2, &mut active)?;
                        meta.children.insert(fp.field_num, child);
                        continue;
                    }
                    let raw_val = fp.access.get(py, obj_ptr)?;
                    if raw_val.is_none() {
                        continue;
                    }
                    let seq = raw_val.cast::<PySequence>().map_err(|_| {
                        encode_err(
                            py,
                            format!("omnibuf: field {} expects a sequence", fp.wire_name),
                        )
                    })?;
                    let n = seq.len()?;
                    let mut merged: Option<CoreSchemaMeta> = None;
                    for i in 0..n {
                        let item = seq.get_item(i)?;
                        if item.is_none() {
                            continue;
                        }
                        let child =
                            sub.build_instance_schema_meta(py, item.as_ptr(), schema_depth + 2)?;
                        if let Some(ref mut m) = merged {
                            m.merge_from(child);
                        } else {
                            merged = Some(child);
                        }
                    }
                    if let Some(m) = merged {
                        meta.children.insert(fp.field_num, m);
                    }
                }
                FieldPlanKind::Map {
                    val_plan: MapValPlan::SubMsg(codec),
                    ..
                } => {
                    let sub = codec.get();
                    if !sub.is_recursive() {
                        let mut active = HashSet::new();
                        let child =
                            sub.build_static_schema_meta(py, schema_depth + 2, &mut active)?;
                        meta.children.insert(fp.field_num, child);
                        continue;
                    }
                    let raw_val = fp.access.get(py, obj_ptr)?;
                    if raw_val.is_none() {
                        continue;
                    }
                    let values_obj = raw_val.call_method0("values")?;
                    let mut merged: Option<CoreSchemaMeta> = None;
                    for v_res in values_obj.try_iter()? {
                        let v = v_res?;
                        if v.is_none() {
                            continue;
                        }
                        let child =
                            sub.build_instance_schema_meta(py, v.as_ptr(), schema_depth + 2)?;
                        if let Some(ref mut m) = merged {
                            m.merge_from(child);
                        } else {
                            merged = Some(child);
                        }
                    }
                    if let Some(m) = merged {
                        meta.children.insert(fp.field_num, m);
                    }
                }
                _ => {}
            }
        }
        Ok(meta)
    }

    #[inline]
    fn write_field0(
        &self,
        py: Python<'_>,
        dst: &mut Vec<u8>,
        obj_ptr: *mut ffi::PyObject,
        inner: &CodecInner,
    ) -> PyResult<()> {
        if self.is_recursive() {
            let meta = self.build_instance_schema_meta(py, obj_ptr, 1)?;
            meta.append_field0(dst);
        } else {
            dst.extend_from_slice(&inner.field0_wire);
        }
        Ok(())
    }

    pub fn alloc_default_instance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner_plan(py)?;
        if inner.fast_alloc {
            let inst = self.alloc_raw_slot_instance(py)?;
            let inst_ptr = inst.as_ptr();
            for fp in &inner.fields {
                if let Some(def_val) = fp.make_default(py)? {
                    fp.access.set(py, inst_ptr, def_val.as_ptr())?;
                }
            }
            Ok(inst)
        } else {
            self.cls.bind(py).call0()
        }
    }

    #[inline(always)]
    fn alloc_raw_slot_instance_with<'py>(
        &self,
        py: Python<'py>,
        inner: &CodecInner,
    ) -> PyResult<Bound<'py, PyAny>> {
        unsafe {
            let cls_ptr = self.cls.as_ptr().cast::<ffi::PyTypeObject>();
            if let Some(alloc_fn) = inner.tp_alloc {
                let raw_inst = alloc_fn(cls_ptr, 0);
                return Bound::from_owned_ptr_or_err(py, raw_inst);
            }
            let Some(new_fn) = (*cls_ptr).tp_new else {
                return self.cls.bind(py).call0();
            };
            let empty_args = PyTuple::empty(py);
            let raw_inst = new_fn(cls_ptr, empty_args.as_ptr(), std::ptr::null_mut());
            Bound::from_owned_ptr_or_err(py, raw_inst)
        }
    }

    #[inline]
    fn alloc_raw_slot_instance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(inner) = self.inner.get() {
            return self.alloc_raw_slot_instance_with(py, inner);
        }
        unsafe {
            let cls_ptr = self.cls.as_ptr().cast::<ffi::PyTypeObject>();
            let Some(new_fn) = (*cls_ptr).tp_new else {
                return self.cls.bind(py).call0();
            };
            let empty_args = PyTuple::empty(py);
            let raw_inst = new_fn(cls_ptr, empty_args.as_ptr(), std::ptr::null_mut());
            Bound::from_owned_ptr_or_err(py, raw_inst)
        }
    }

    fn is_value_empty(
        &self,
        py: Python<'_>,
        fp: &FieldPlan,
        val: &Bound<'_, PyAny>,
        depth: usize,
    ) -> PyResult<bool> {
        if depth > MAX_NESTING_DEPTH {
            return Err(encode_err(
                py,
                format!("omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"),
            ));
        }
        if val.is_none() {
            return Ok(true);
        }
        let ptr = val.as_ptr();
        match &fp.kind {
            FieldPlanKind::Scalar { kind, .. } => match kind {
                ScalarKind::Bool => Ok(!extract_bool(py, ptr)?),
                ScalarKind::Uint32
                | ScalarKind::Sint32
                | ScalarKind::Sint64
                | ScalarKind::Fixed32
                | ScalarKind::Sfixed32
                | ScalarKind::Sfixed64 => Ok(extract_i64(py, ptr, &fp.wire_name)? == 0),
                ScalarKind::Enum => Ok(extract_enum_i64(py, ptr, &fp.wire_name)? == 0),
                ScalarKind::Uint64 | ScalarKind::Fixed64 => {
                    Ok(extract_u64(py, ptr, &fp.wire_name)? == 0)
                }
                ScalarKind::Float32 => {
                    Ok((extract_f64(py, ptr, &fp.wire_name)? as f32).to_bits() == 0)
                }
                ScalarKind::Float64 => Ok(extract_f64(py, ptr, &fp.wire_name)?.to_bits() == 0),
                ScalarKind::String
                | ScalarKind::StrAsBytes
                | ScalarKind::Bytes
                | ScalarKind::BytesAsStr => Ok(val.len()? == 0),
            },
            FieldPlanKind::ArrayScalar { .. }
            | FieldPlanKind::ArraySubMsg { .. }
            | FieldPlanKind::Map { .. } => Ok(val.len()? == 0),
            FieldPlanKind::SubMsg { codec } => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(encode_err(
                        py,
                        format!(
                            "omnibuf: nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let sub = codec.get();
                let sub_inner = sub.inner_plan(py)?;
                for sub_fp in &sub_inner.fields {
                    let child_val = sub_fp.access.get(py, ptr)?;
                    if !sub.is_value_empty(py, sub_fp, &child_val, depth + 1)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    pub fn encode_single_field(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        deterministic: bool,
    ) -> PyResult<()> {
        let inner = self.inner_plan(py)?;
        let idx = lookup_field_index(inner, fnum).ok_or_else(|| {
            encode_err(
                py,
                format!("omnibuf: unknown field #{fnum} on {}", self.type_name),
            )
        })?;
        let fp = &inner.fields[idx];
        if val.is_none() {
            if fp.skip_if_none || matches!(fp.kind, FieldPlanKind::SubMsg { .. }) {
                return Ok(());
            }
            return Err(encode_err(
                py,
                format!("omnibuf: field {} cannot be None", fp.wire_name),
            ));
        }
        self.encode_field_value(py, enc, fp, val, deterministic, 0)
    }

    #[inline]
    unsafe fn try_encode_pure_fast_slots(
        &self,
        py: Python<'_>,
        buf: &mut Vec<u8>,
        inner: &CodecInner,
        obj_ptr: *mut ffi::PyObject,
        depth: usize,
    ) -> Option<PyResult<()>> {
        if depth > MAX_NESTING_DEPTH {
            return Some(Err(encode_err(
                py,
                format!("omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"),
            )));
        }
        unsafe {
            if obj_ptr.is_null()
                || !inner.fast_slot_encode
                || ffi::Py_IS_TYPE(obj_ptr, self.cls.as_ptr().cast::<ffi::PyTypeObject>()) == 0
            {
                return None;
            }
            let checkpoint = buf.len();
            buf.reserve(inner.min_wire_reserve);
            let none_ptr = ffi::Py_None();

            for fp in &inner.fields {
                let mut val_ptr = *obj_ptr
                    .byte_add(fp.slot_offset)
                    .cast::<*mut ffi::PyObject>();
                if val_ptr.is_null() {
                    buf.truncate(checkpoint);
                    return None;
                }
                if val_ptr == none_ptr {
                    if fp.skip_if_none {
                        continue;
                    }
                    match &fp.default_plan {
                        DefaultPlan::Const(c) => {
                            let cp = c.as_ptr();
                            if cp == none_ptr {
                                continue;
                            }
                            val_ptr = cp;
                        }
                        DefaultPlan::EmptyList => {
                            if depth + 1 > MAX_NESTING_DEPTH {
                                return Some(Err(encode_err(
                                    py,
                                    format!(
                                        "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                                        depth + 1
                                    ),
                                )));
                            }
                            match &fp.kind {
                                FieldPlanKind::ArrayScalar { elem_wt, .. } => {
                                    let lp = write_raw_tag_and_len_placeholder(
                                        buf,
                                        fp.tag_bytes,
                                        fp.tag_len,
                                    );
                                    buf.extend_from_slice(&[*elem_wt, 0x01]);
                                    backpatch_container_fast(buf, lp);
                                    continue;
                                }
                                FieldPlanKind::ArraySubMsg { .. } => {
                                    let lp = write_raw_tag_and_len_placeholder(
                                        buf,
                                        fp.tag_bytes,
                                        fp.tag_len,
                                    );
                                    buf.extend_from_slice(&[WIRE_SUB_MSG, 0x01]);
                                    backpatch_container_fast(buf, lp);
                                    continue;
                                }
                                _ => {
                                    buf.truncate(checkpoint);
                                    return None;
                                }
                            }
                        }
                        DefaultPlan::PbpySkip => continue,
                        _ => {
                            buf.truncate(checkpoint);
                            return None;
                        }
                    }
                }

                match &fp.kind {
                    FieldPlanKind::Scalar { kind, .. } => {
                        match Self::encode_exact_scalar_tagged(py, buf, fp, *kind, val_ptr) {
                            Some(Ok(())) => {}
                            Some(Err(e)) => return Some(Err(e)),
                            None => {
                                buf.truncate(checkpoint);
                                return None;
                            }
                        }
                    }
                    FieldPlanKind::SubMsg { codec } => {
                        if depth + 1 > MAX_NESTING_DEPTH {
                            return Some(Err(encode_err(
                                py,
                                format!(
                                    "omnibuf: nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                                    depth + 1
                                ),
                            )));
                        }
                        let sub = codec.get();
                        let Some(sub_inner) = sub.inner.get() else {
                            buf.truncate(checkpoint);
                            return None;
                        };
                        let sub_min = slot_submsg_min_wire_size(
                            sub.cls.as_ptr().cast::<ffi::PyTypeObject>(),
                            sub_inner,
                            val_ptr,
                        );
                        let use_len4 = sub_min > 16_383;
                        if use_len4 {
                            buf.reserve(sub_min.saturating_add(64));
                        }
                        let len_pos = if use_len4 {
                            write_raw_tag_and_len4_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        } else {
                            write_raw_tag_and_len_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        };
                        match sub.try_encode_pure_fast_slots(py, buf, sub_inner, val_ptr, depth + 1)
                        {
                            Some(Ok(())) => {
                                if use_len4 {
                                    backpatch_container_len4(buf, len_pos);
                                } else {
                                    backpatch_container_fast(buf, len_pos);
                                }
                            }
                            Some(Err(e)) => return Some(Err(e)),
                            None => {
                                buf.truncate(checkpoint);
                                return None;
                            }
                        }
                    }
                    FieldPlanKind::ArrayScalar {
                        elem_kind, elem_wt, ..
                    } => {
                        if depth + 1 > MAX_NESTING_DEPTH {
                            return Some(Err(encode_err(
                                py,
                                format!(
                                    "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                                    depth + 1
                                ),
                            )));
                        }
                        if ffi::PyList_CheckExact(val_ptr) == 0 {
                            buf.truncate(checkpoint);
                            return None;
                        }
                        let n = ffi::PyList_GET_SIZE(val_ptr) as usize;
                        let use_len4 = 2usize.saturating_add(
                            n.saturating_mul(scalar_elem_min_wire_bytes(*elem_kind)),
                        ) > 16_383;
                        let len_pos = if use_len4 {
                            write_raw_tag_and_len4_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        } else {
                            write_raw_tag_and_len_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        };
                        buf.push(*elem_wt);
                        append_varint(buf, n as u64);

                        match *elem_kind {
                            ScalarKind::String | ScalarKind::StrAsBytes => {
                                for i in 0..n {
                                    let item_ptr =
                                        ffi::PyList_GET_ITEM(val_ptr, i as ffi::Py_ssize_t);
                                    if ffi::PyUnicode_CheckExact(item_ptr) == 0 {
                                        buf.truncate(checkpoint);
                                        return None;
                                    }
                                    let mut size: ffi::Py_ssize_t = 0;
                                    let utf8_ptr =
                                        ffi::PyUnicode_AsUTF8AndSize(item_ptr, &mut size);
                                    if utf8_ptr.is_null() {
                                        let err = PyErr::fetch(py);
                                        return Some(Err(encode_err(
                                            py,
                                            format!(
                                                "omnibuf: invalid UTF-8 in field {}: {err}",
                                                fp.wire_name
                                            ),
                                        )));
                                    }
                                    write_raw_bytes_elem(buf, utf8_ptr.cast::<u8>(), size as usize);
                                }
                            }
                            ScalarKind::Uint32 => {
                                let Some(reserve_bytes) = n.checked_mul(9) else {
                                    return Some(Err(encode_err(
                                        py,
                                        format!(
                                            "omnibuf: field {} array size overflow",
                                            fp.wire_name
                                        ),
                                    )));
                                };
                                if buf.try_reserve(reserve_bytes).is_err() {
                                    return Some(Err(encode_err(
                                        py,
                                        format!(
                                            "omnibuf: field {} allocation failed",
                                            fp.wire_name
                                        ),
                                    )));
                                }
                                for i in 0..n {
                                    let item_ptr =
                                        ffi::PyList_GET_ITEM(val_ptr, i as ffi::Py_ssize_t);
                                    if ffi::PyLong_CheckExact(item_ptr) == 0 {
                                        buf.truncate(checkpoint);
                                        return None;
                                    }
                                    let mut overflow: std::os::raw::c_int = 0;
                                    let v =
                                        ffi::PyLong_AsLongLongAndOverflow(item_ptr, &mut overflow);
                                    if overflow == 0 && (v as u64) <= u64::from(u32::MAX) {
                                        let c = buf.len();
                                        let written =
                                            put_varint_inline(buf.as_mut_ptr().add(c), v as u64);
                                        buf.set_len(c + written);
                                    } else {
                                        return Some(Err(encode_err(
                                            py,
                                            format!(
                                                "omnibuf: field {} uint32 out of range",
                                                fp.wire_name
                                            ),
                                        )));
                                    }
                                }
                            }
                            _ => {
                                for i in 0..n {
                                    let item_ptr =
                                        ffi::PyList_GET_ITEM(val_ptr, i as ffi::Py_ssize_t);
                                    if !is_exact_primitive(*elem_kind, item_ptr) {
                                        buf.truncate(checkpoint);
                                        return None;
                                    }
                                    if let Err(e) = write_scalar_payload(
                                        py,
                                        buf,
                                        *elem_kind,
                                        item_ptr,
                                        &fp.wire_name,
                                    ) {
                                        return Some(Err(e));
                                    }
                                }
                            }
                        }
                        if use_len4 {
                            backpatch_container_len4(buf, len_pos);
                        } else {
                            backpatch_container_fast(buf, len_pos);
                        }
                    }
                    FieldPlanKind::ArraySubMsg { codec } => {
                        if depth + 1 > MAX_NESTING_DEPTH {
                            return Some(Err(encode_err(
                                py,
                                format!(
                                    "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                                    depth + 1
                                ),
                            )));
                        }
                        if ffi::PyList_CheckExact(val_ptr) == 0 {
                            buf.truncate(checkpoint);
                            return None;
                        }
                        let sub = codec.get();
                        let Some(sub_inner) = sub.inner.get() else {
                            buf.truncate(checkpoint);
                            return None;
                        };
                        let n = ffi::PyList_GET_SIZE(val_ptr) as usize;
                        let sub_cls_ptr = sub.cls.as_ptr().cast::<ffi::PyTypeObject>();
                        let mut arr_min = 2usize.saturating_add(n.saturating_mul(2));
                        if n <= 64 {
                            for i in 0..n {
                                let item_ptr = ffi::PyList_GET_ITEM(val_ptr, i as ffi::Py_ssize_t);
                                arr_min = arr_min.saturating_add(slot_submsg_min_wire_size(
                                    sub_cls_ptr,
                                    sub_inner,
                                    item_ptr,
                                ));
                            }
                        }
                        let use_len4 = arr_min > 16_383;
                        if use_len4 {
                            buf.reserve(arr_min.saturating_add(64));
                        }
                        let len_pos = if use_len4 {
                            write_raw_tag_and_len4_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        } else {
                            write_raw_tag_and_len_placeholder(buf, fp.tag_bytes, fp.tag_len)
                        };
                        buf.push(WIRE_SUB_MSG);
                        append_varint(buf, n as u64);

                        for i in 0..n {
                            let item_ptr = ffi::PyList_GET_ITEM(val_ptr, i as ffi::Py_ssize_t);
                            let elem_len4 = use_len4
                                && slot_submsg_min_wire_size(sub_cls_ptr, sub_inner, item_ptr)
                                    > 16_383;
                            let elem_len_pos = buf.len();
                            if elem_len4 {
                                buf.reserve(4);
                                core::ptr::write_unaligned(
                                    buf.as_mut_ptr().add(elem_len_pos).cast::<u32>(),
                                    0u32,
                                );
                                buf.set_len(elem_len_pos + 4);
                            } else {
                                buf.reserve(2);
                                core::ptr::write_unaligned(
                                    buf.as_mut_ptr().add(elem_len_pos).cast::<u16>(),
                                    0u16,
                                );
                                buf.set_len(elem_len_pos + 2);
                            }
                            match sub.try_encode_pure_fast_slots(
                                py,
                                buf,
                                sub_inner,
                                item_ptr,
                                depth + 2,
                            ) {
                                Some(Ok(())) => {
                                    if elem_len4 {
                                        backpatch_container_len4(buf, elem_len_pos);
                                    } else {
                                        backpatch_container_fast(buf, elem_len_pos);
                                    }
                                }
                                Some(Err(e)) => return Some(Err(e)),
                                None => {
                                    buf.truncate(checkpoint);
                                    return None;
                                }
                            }
                        }
                        if use_len4 {
                            backpatch_container_len4(buf, len_pos);
                        } else {
                            backpatch_container_fast(buf, len_pos);
                        }
                    }
                    FieldPlanKind::Map { .. } => {
                        buf.truncate(checkpoint);
                        return None;
                    }
                }
            }
            Some(Ok(()))
        }
    }

    #[inline]
    fn encode_exact_scalar_tagged(
        py: Python<'_>,
        dst: &mut Vec<u8>,
        fp: &FieldPlan,
        kind: ScalarKind,
        val_ptr: *mut ffi::PyObject,
    ) -> Option<PyResult<()>> {
        unsafe {
            match kind {
                ScalarKind::Bool => {
                    if val_ptr == ffi::Py_True() {
                        fp.write_bool_tag_to(dst, true);
                        return Some(Ok(()));
                    }
                    if val_ptr == ffi::Py_False() {
                        fp.write_bool_tag_to(dst, false);
                        return Some(Ok(()));
                    }
                    None
                }
                ScalarKind::Uint32 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0 && (v as u64) <= u64::from(u32::MAX) {
                            write_raw_tagged_varint(dst, fp.tag_bytes, fp.tag_len, v as u64);
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} uint32 out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Uint64 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        return Some(extract_u64(py, val_ptr, &fp.wire_name).map(|u| {
                            write_raw_tagged_varint(dst, fp.tag_bytes, fp.tag_len, u);
                        }));
                    }
                    None
                }
                ScalarKind::Sint32 | ScalarKind::Enum => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0
                            && let Ok(v32) = i32::try_from(v)
                        {
                            let zz32 = u64::from(((v32 << 1) ^ (v32 >> 31)) as u32);
                            write_raw_tagged_varint(dst, fp.tag_bytes, fp.tag_len, zz32);
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} 32-bit signed out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Sint64 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0 {
                            write_raw_tagged_varint(
                                dst,
                                fp.tag_bytes,
                                fp.tag_len,
                                encode_zigzag(v),
                            );
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} integer out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Fixed32 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0
                            && let Ok(u) = u32::try_from(v)
                        {
                            write_raw_tagged_fixed4(dst, fp.tag_bytes, fp.tag_len, u.to_le_bytes());
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} fixed32 out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Sfixed32 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0
                            && let Ok(i) = i32::try_from(v)
                        {
                            write_raw_tagged_fixed4(dst, fp.tag_bytes, fp.tag_len, i.to_le_bytes());
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} sfixed32 out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Fixed64 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        return Some(extract_u64(py, val_ptr, &fp.wire_name).map(|u| {
                            write_raw_tagged_fixed8(dst, fp.tag_bytes, fp.tag_len, u.to_le_bytes());
                        }));
                    }
                    None
                }
                ScalarKind::Sfixed64 => {
                    if ffi::PyLong_CheckExact(val_ptr) != 0 {
                        let mut overflow: std::os::raw::c_int = 0;
                        let v = ffi::PyLong_AsLongLongAndOverflow(val_ptr, &mut overflow);
                        if overflow == 0 {
                            write_raw_tagged_fixed8(dst, fp.tag_bytes, fp.tag_len, v.to_le_bytes());
                            return Some(Ok(()));
                        }
                        return Some(Err(encode_err(
                            py,
                            format!("omnibuf: field {} integer out of range", fp.wire_name),
                        )));
                    }
                    None
                }
                ScalarKind::Float32 => {
                    if ffi::PyFloat_CheckExact(val_ptr) != 0 {
                        let v = ffi::PyFloat_AS_DOUBLE(val_ptr);
                        let f = v as f32;
                        if v.is_finite() && !f.is_finite() {
                            return Some(Err(encode_err(
                                py,
                                format!("omnibuf: field {} float32 overflow", fp.wire_name),
                            )));
                        }
                        write_raw_tagged_fixed4(
                            dst,
                            fp.tag_bytes,
                            fp.tag_len,
                            f.to_bits().to_le_bytes(),
                        );
                        return Some(Ok(()));
                    }
                    None
                }
                ScalarKind::Float64 => {
                    if ffi::PyFloat_CheckExact(val_ptr) != 0 {
                        let v = ffi::PyFloat_AS_DOUBLE(val_ptr);
                        write_raw_tagged_fixed8(
                            dst,
                            fp.tag_bytes,
                            fp.tag_len,
                            v.to_bits().to_le_bytes(),
                        );
                        return Some(Ok(()));
                    }
                    None
                }
                ScalarKind::String | ScalarKind::StrAsBytes => {
                    if ffi::PyUnicode_CheckExact(val_ptr) != 0 {
                        let mut size: ffi::Py_ssize_t = 0;
                        let utf8_ptr = ffi::PyUnicode_AsUTF8AndSize(val_ptr, &mut size);
                        if utf8_ptr.is_null() {
                            let err = PyErr::fetch(py);
                            return Some(Err(encode_err(
                                py,
                                format!("omnibuf: invalid UTF-8 in field {}: {err}", fp.wire_name),
                            )));
                        }
                        write_raw_tagged_bytes(
                            dst,
                            fp.tag_bytes,
                            fp.tag_len,
                            utf8_ptr.cast::<u8>(),
                            size as usize,
                        );
                        return Some(Ok(()));
                    }
                    None
                }
                ScalarKind::Bytes => {
                    if ffi::PyBytes_CheckExact(val_ptr) != 0 {
                        let len = ffi::PyBytes_Size(val_ptr) as usize;
                        let src = if len == 0 {
                            std::ptr::NonNull::<u8>::dangling().as_ptr()
                        } else {
                            ffi::PyBytes_AS_STRING(val_ptr).cast::<u8>()
                        };
                        write_raw_tagged_bytes(dst, fp.tag_bytes, fp.tag_len, src, len);
                        return Some(Ok(()));
                    }
                    None
                }
                ScalarKind::BytesAsStr => {
                    if ffi::PyBytes_CheckExact(val_ptr) != 0 {
                        let len = ffi::PyBytes_Size(val_ptr) as usize;
                        let slice = if len == 0 {
                            &[]
                        } else {
                            std::slice::from_raw_parts(
                                ffi::PyBytes_AS_STRING(val_ptr).cast::<u8>(),
                                len,
                            )
                        };
                        if let Err(e) = validate_utf8(slice) {
                            return Some(Err(encode_err(py, e.to_string())));
                        }
                        write_raw_tagged_bytes(
                            dst,
                            fp.tag_bytes,
                            fp.tag_len,
                            slice.as_ptr(),
                            slice.len(),
                        );
                        return Some(Ok(()));
                    }
                    None
                }
            }
        }
    }

    #[inline]
    fn encode_list_scalar_fast(
        py: Python<'_>,
        enc: &mut Encoder,
        fp: &FieldPlan,
        elem_kind: ScalarKind,
        elem_wt: u8,
        list_ptr: *mut ffi::PyObject,
    ) -> PyResult<()> {
        fp.write_tag_to(enc.buf_mut());
        let buf = enc.buf_mut();
        let len_pos = buf.len();
        let use_len4;
        unsafe {
            let n = ffi::PyList_GET_SIZE(list_ptr) as usize;
            use_len4 = 2usize
                .saturating_add(n.saturating_mul(scalar_elem_min_wire_bytes(elem_kind)))
                > 16_383;
            buf.reserve(14);
            let cur = buf.len();
            let p = buf.as_mut_ptr().add(cur);
            if use_len4 {
                core::ptr::write_unaligned(p.cast::<u32>(), 0u32);
                *p.add(4) = elem_wt;
                let vn = put_varint_inline(p.add(5), n as u64);
                buf.set_len(cur + 5 + vn);
            } else {
                *p = 0;
                *p.add(1) = 0;
                *p.add(2) = elem_wt;
                let vn = put_varint_inline(p.add(3), n as u64);
                buf.set_len(cur + 3 + vn);
            }

            match elem_kind {
                ScalarKind::String | ScalarKind::StrAsBytes => {
                    for i in 0..n {
                        let item_ptr = ffi::PyList_GET_ITEM(list_ptr, i as ffi::Py_ssize_t);
                        if ffi::PyUnicode_CheckExact(item_ptr) != 0 {
                            let mut size: ffi::Py_ssize_t = 0;
                            let utf8_ptr = ffi::PyUnicode_AsUTF8AndSize(item_ptr, &mut size);
                            if utf8_ptr.is_null() {
                                let err = PyErr::fetch(py);
                                return Err(encode_err(
                                    py,
                                    format!(
                                        "omnibuf: invalid UTF-8 in field {}: {err}",
                                        fp.wire_name
                                    ),
                                ));
                            }
                            write_raw_bytes_elem(buf, utf8_ptr.cast::<u8>(), size as usize);
                        } else {
                            let mut tail: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n - i);
                            for j in i..n {
                                let jp = ffi::PyList_GET_ITEM(list_ptr, j as ffi::Py_ssize_t);
                                tail.push(Borrowed::from_ptr(py, jp).to_owned());
                            }
                            for item in &tail {
                                write_scalar_payload(
                                    py,
                                    buf,
                                    elem_kind,
                                    item.as_ptr(),
                                    &fp.wire_name,
                                )?;
                            }
                            break;
                        }
                    }
                }
                ScalarKind::Uint32 => {
                    for i in 0..n {
                        let item_ptr = ffi::PyList_GET_ITEM(list_ptr, i as ffi::Py_ssize_t);
                        if ffi::PyLong_CheckExact(item_ptr) != 0 {
                            let mut overflow: std::os::raw::c_int = 0;
                            let v = ffi::PyLong_AsLongLongAndOverflow(item_ptr, &mut overflow);
                            if overflow == 0 && (v as u64) <= u64::from(u32::MAX) {
                                append_varint(buf, v as u64);
                            } else {
                                return Err(encode_err(
                                    py,
                                    format!("omnibuf: field {} uint32 out of range", fp.wire_name),
                                ));
                            }
                        } else {
                            let mut tail: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n - i);
                            for j in i..n {
                                let jp = ffi::PyList_GET_ITEM(list_ptr, j as ffi::Py_ssize_t);
                                tail.push(Borrowed::from_ptr(py, jp).to_owned());
                            }
                            for item in &tail {
                                write_scalar_payload(
                                    py,
                                    buf,
                                    elem_kind,
                                    item.as_ptr(),
                                    &fp.wire_name,
                                )?;
                            }
                            break;
                        }
                    }
                }
                _ => {
                    for i in 0..n {
                        let item_ptr = ffi::PyList_GET_ITEM(list_ptr, i as ffi::Py_ssize_t);
                        if is_exact_primitive(elem_kind, item_ptr) {
                            write_scalar_payload(py, buf, elem_kind, item_ptr, &fp.wire_name)?;
                        } else {
                            let mut tail: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n - i);
                            for j in i..n {
                                let jp = ffi::PyList_GET_ITEM(list_ptr, j as ffi::Py_ssize_t);
                                tail.push(Borrowed::from_ptr(py, jp).to_owned());
                            }
                            for item in &tail {
                                write_scalar_payload(
                                    py,
                                    buf,
                                    elem_kind,
                                    item.as_ptr(),
                                    &fp.wire_name,
                                )?;
                            }
                            break;
                        }
                    }
                }
            }
        }
        if use_len4 {
            backpatch_container_len4(enc.buf_mut(), len_pos);
        } else {
            backpatch_container_len(enc.buf_mut(), len_pos);
        }
        Ok(())
    }

    #[inline]
    fn encode_list_submsg_fast(
        py: Python<'_>,
        enc: &mut Encoder,
        fp: &FieldPlan,
        sub: &CompiledCodec,
        list_ptr: *mut ffi::PyObject,
        deterministic: bool,
        depth: usize,
    ) -> PyResult<()> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(encode_err(
                py,
                format!(
                    "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                    depth + 1
                ),
            ));
        }
        fp.write_tag_to(enc.buf_mut());
        let len_pos = enc.buf_mut().len();
        let use_len4;
        unsafe {
            let n = ffi::PyList_GET_SIZE(list_ptr) as usize;
            use_len4 = 2usize.saturating_add(n) > 16_383;
            {
                let buf = enc.buf_mut();
                buf.reserve(14);
                let cur = buf.len();
                let p = buf.as_mut_ptr().add(cur);
                if use_len4 {
                    core::ptr::write_unaligned(p.cast::<u32>(), 0u32);
                    *p.add(4) = WIRE_SUB_MSG;
                    let vn = put_varint_inline(p.add(5), n as u64);
                    buf.set_len(cur + 5 + vn);
                } else {
                    *p = 0;
                    *p.add(1) = 0;
                    *p.add(2) = WIRE_SUB_MSG;
                    let vn = put_varint_inline(p.add(3), n as u64);
                    buf.set_len(cur + 3 + vn);
                }
            }

            if HAS_GIL {
                let sub_inner = sub.inner_plan(py)?;
                let mut idx = 0usize;
                while idx < n {
                    let item_ptr = ffi::PyList_GET_ITEM(list_ptr, idx as ffi::Py_ssize_t);
                    let elem_len_pos = enc.buf_mut().len();
                    enc.buf_mut().extend_from_slice(&[0, 0]);
                    match sub.try_encode_pure_fast_slots(
                        py,
                        enc.buf_mut(),
                        sub_inner,
                        item_ptr,
                        depth + 2,
                    ) {
                        Some(Ok(())) => {
                            backpatch_container_len(enc.buf_mut(), elem_len_pos);
                            idx += 1;
                        }
                        Some(Err(e)) => return Err(e),
                        None => {
                            enc.buf_mut().truncate(elem_len_pos);
                            let mut tail: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n - idx);
                            for j in idx..n {
                                let jp = ffi::PyList_GET_ITEM(list_ptr, j as ffi::Py_ssize_t);
                                tail.push(Borrowed::from_ptr(py, jp).to_owned());
                            }
                            for item in &tail {
                                if item.is_none() {
                                    return Err(encode_err(
                                        py,
                                        format!(
                                            "omnibuf: list elements in {} cannot be None",
                                            fp.wire_name
                                        ),
                                    ));
                                }
                                let lp = enc.buf_mut().len();
                                enc.buf_mut().extend_from_slice(&[0, 0]);
                                sub.encode_msg_into(
                                    py,
                                    enc,
                                    item.as_ptr(),
                                    deterministic,
                                    depth + 2,
                                )?;
                                backpatch_container_len(enc.buf_mut(), lp);
                            }
                            break;
                        }
                    }
                }
            } else {
                let mut items: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n);
                for i in 0..n {
                    let item_ptr = ffi::PyList_GET_ITEM(list_ptr, i as ffi::Py_ssize_t);
                    items.push(Borrowed::from_ptr(py, item_ptr).to_owned());
                }
                for item in &items {
                    if item.is_none() {
                        return Err(encode_err(
                            py,
                            format!("omnibuf: list elements in {} cannot be None", fp.wire_name),
                        ));
                    }
                    let elem_len_pos = enc.buf_mut().len();
                    enc.buf_mut().extend_from_slice(&[0, 0]);
                    sub.encode_msg_into(py, enc, item.as_ptr(), deterministic, depth + 2)?;
                    backpatch_container_len(enc.buf_mut(), elem_len_pos);
                }
            }
        }
        if use_len4 {
            backpatch_container_len4(enc.buf_mut(), len_pos);
        } else {
            backpatch_container_len(enc.buf_mut(), len_pos);
        }
        Ok(())
    }

    #[inline]
    fn encode_field_value(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        fp: &FieldPlan,
        val: &Bound<'_, PyAny>,
        deterministic: bool,
        depth: usize,
    ) -> PyResult<()> {
        let ptr = val.as_ptr();
        match &fp.kind {
            FieldPlanKind::Scalar { kind, .. } => {
                if let Some(res) =
                    Self::encode_exact_scalar_tagged(py, enc.buf_mut(), fp, *kind, ptr)
                {
                    return res;
                }
                if *kind == ScalarKind::Bool {
                    let b = extract_bool(py, ptr)?;
                    fp.write_bool_tag_to(enc.buf_mut(), b);
                    Ok(())
                } else {
                    fp.write_tag_to(enc.buf_mut());
                    write_scalar_payload(py, enc.buf_mut(), *kind, ptr, &fp.wire_name)
                }
            }
            FieldPlanKind::SubMsg { codec } => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(encode_err(
                        py,
                        format!(
                            "omnibuf: nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                fp.write_tag_to(enc.buf_mut());
                let len_pos = enc.buf_mut().len();
                enc.buf_mut().extend_from_slice(&[0, 0]);
                if !val.is_none() {
                    codec
                        .get()
                        .encode_msg_into(py, enc, ptr, deterministic, depth + 1)?;
                }
                backpatch_container_len(enc.buf_mut(), len_pos);
                Ok(())
            }
            FieldPlanKind::ArrayScalar {
                elem_kind, elem_wt, ..
            } => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(encode_err(
                        py,
                        format!(
                            "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                if unsafe { ffi::PyList_CheckExact(ptr) != 0 } {
                    return Self::encode_list_scalar_fast(py, enc, fp, *elem_kind, *elem_wt, ptr);
                }
                let seq = val.cast::<PySequence>().map_err(|_| {
                    encode_err(
                        py,
                        format!("omnibuf: field {} expects a sequence", fp.wire_name),
                    )
                })?;
                let n = seq.len()?;
                let mut items: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n.min(4096));
                for i in 0..n {
                    if (i & 0xFFF) == 0xFFF {
                        py.check_signals()?;
                    }
                    if items.len() == items.capacity() {
                        items.try_reserve(1).map_err(|_| {
                            encode_err(
                                py,
                                format!(
                                    "omnibuf: field {} sequence allocation failed",
                                    fp.wire_name
                                ),
                            )
                        })?;
                    }
                    items.push(seq.get_item(i)?);
                }
                let use_len4 = 2usize.saturating_add(
                    items
                        .len()
                        .saturating_mul(scalar_elem_min_wire_bytes(*elem_kind)),
                ) > 16_383;
                fp.write_tag_to(enc.buf_mut());
                let buf = enc.buf_mut();
                let len_pos = buf.len();
                if use_len4 {
                    buf.extend_from_slice(&[0, 0, 0, 0, *elem_wt]);
                } else {
                    buf.extend_from_slice(&[0, 0, *elem_wt]);
                }
                append_varint(buf, items.len() as u64);
                for item in &items {
                    write_scalar_payload(py, buf, *elem_kind, item.as_ptr(), &fp.wire_name)?;
                }
                if use_len4 {
                    backpatch_container_len4(enc.buf_mut(), len_pos);
                } else {
                    backpatch_container_len(enc.buf_mut(), len_pos);
                }
                Ok(())
            }
            FieldPlanKind::ArraySubMsg { codec } => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(encode_err(
                        py,
                        format!(
                            "omnibuf: array nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let sub = codec.get();
                if unsafe { ffi::PyList_CheckExact(ptr) != 0 } {
                    return Self::encode_list_submsg_fast(
                        py,
                        enc,
                        fp,
                        sub,
                        ptr,
                        deterministic,
                        depth,
                    );
                }
                let seq = val.cast::<PySequence>().map_err(|_| {
                    encode_err(
                        py,
                        format!("omnibuf: field {} expects a sequence", fp.wire_name),
                    )
                })?;
                let n = seq.len()?;
                let mut items: Vec<Bound<'_, PyAny>> = Vec::with_capacity(n.min(4096));
                for i in 0..n {
                    if (i & 0xFFF) == 0xFFF {
                        py.check_signals()?;
                    }
                    if items.len() == items.capacity() {
                        items.try_reserve(1).map_err(|_| {
                            encode_err(
                                py,
                                format!(
                                    "omnibuf: field {} sequence allocation failed",
                                    fp.wire_name
                                ),
                            )
                        })?;
                    }
                    items.push(seq.get_item(i)?);
                }
                let use_len4 = 2usize.saturating_add(items.len()) > 16_383;
                fp.write_tag_to(enc.buf_mut());
                let len_pos = enc.buf_mut().len();
                if use_len4 {
                    enc.buf_mut().extend_from_slice(&[0, 0, 0, 0, WIRE_SUB_MSG]);
                } else {
                    enc.buf_mut().extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
                }
                append_varint(enc.buf_mut(), items.len() as u64);
                for item in &items {
                    if item.is_none() {
                        return Err(encode_err(
                            py,
                            format!("omnibuf: list elements in {} cannot be None", fp.wire_name),
                        ));
                    }
                    let elem_len_pos = enc.buf_mut().len();
                    enc.buf_mut().extend_from_slice(&[0, 0]);
                    sub.encode_msg_into(py, enc, item.as_ptr(), deterministic, depth + 2)?;
                    backpatch_container_len(enc.buf_mut(), elem_len_pos);
                }
                if use_len4 {
                    backpatch_container_len4(enc.buf_mut(), len_pos);
                } else {
                    backpatch_container_len(enc.buf_mut(), len_pos);
                }
                Ok(())
            }
            FieldPlanKind::Map {
                key_kind,
                key_wt,
                val_wt,
                val_plan,
            } => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(encode_err(
                        py,
                        format!(
                            "omnibuf: map nesting depth {} exceeds limit {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let val_min = match val_plan {
                    MapValPlan::Scalar { kind: vk, .. } => scalar_elem_min_wire_bytes(*vk),
                    MapValPlan::SubMsg(_) => 1,
                };
                let entry_min = scalar_elem_min_wire_bytes(*key_kind) + val_min;
                unsafe {
                    if ffi::PyDict_CheckExact(ptr) != 0 {
                        let count = ffi::PyDict_Size(ptr) as usize;
                        let use_len4 =
                            3usize.saturating_add(count.saturating_mul(entry_min)) > 16_383;
                        fp.write_tag_to(enc.buf_mut());
                        let len_pos = enc.buf_mut().len();
                        if use_len4 {
                            enc.buf_mut()
                                .extend_from_slice(&[0, 0, 0, 0, *key_wt, *val_wt]);
                        } else {
                            enc.buf_mut().extend_from_slice(&[0, 0, *key_wt, *val_wt]);
                        }
                        let fast_scalar_vk = match val_plan {
                            MapValPlan::Scalar { kind: vk, .. } => {
                                let mut ppos: ffi::Py_ssize_t = 0;
                                let mut k_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                let mut v_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                let mut ok = true;
                                while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0
                                {
                                    if !is_exact_primitive(*key_kind, k_ptr)
                                        || !is_exact_primitive(*vk, v_ptr)
                                    {
                                        ok = false;
                                        break;
                                    }
                                }
                                ok.then_some(*vk)
                            }
                            MapValPlan::SubMsg(_) => None,
                        };

                        if let Some(vk) = fast_scalar_vk {
                            append_varint(enc.buf_mut(), count as u64);
                            if deterministic && count > 1 {
                                let mut entries: Vec<(
                                    SortableMapKey,
                                    *mut ffi::PyObject,
                                    *mut ffi::PyObject,
                                )> = Vec::with_capacity(count);
                                let mut ppos: ffi::Py_ssize_t = 0;
                                let mut k_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                let mut v_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0
                                {
                                    let sk =
                                        extract_sortable_key(py, *key_kind, k_ptr, &fp.wire_name)?;
                                    entries.push((sk, k_ptr, v_ptr));
                                }
                                entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                                for (_, kp, vp) in entries {
                                    write_scalar_payload(
                                        py,
                                        enc.buf_mut(),
                                        *key_kind,
                                        kp,
                                        &fp.wire_name,
                                    )?;
                                    write_scalar_payload(py, enc.buf_mut(), vk, vp, &fp.wire_name)?;
                                }
                            } else {
                                let mut ppos: ffi::Py_ssize_t = 0;
                                let mut k_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                let mut v_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                                while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0
                                {
                                    write_scalar_payload(
                                        py,
                                        enc.buf_mut(),
                                        *key_kind,
                                        k_ptr,
                                        &fp.wire_name,
                                    )?;
                                    write_scalar_payload(
                                        py,
                                        enc.buf_mut(),
                                        vk,
                                        v_ptr,
                                        &fp.wire_name,
                                    )?;
                                }
                            }
                        } else {
                            let mut raw_pairs: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)> =
                                Vec::with_capacity(count);
                            let mut ppos: ffi::Py_ssize_t = 0;
                            let mut k_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                            let mut v_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                            while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0 {
                                raw_pairs.push((
                                    Borrowed::from_ptr(py, k_ptr).to_owned(),
                                    Borrowed::from_ptr(py, v_ptr).to_owned(),
                                ));
                            }
                            self.write_snapshot_map_entries(
                                py,
                                enc,
                                fp,
                                *key_kind,
                                val_plan,
                                raw_pairs,
                                deterministic,
                                depth,
                            )?;
                        }
                        if use_len4 {
                            backpatch_container_len4(enc.buf_mut(), len_pos);
                        } else {
                            backpatch_container_len(enc.buf_mut(), len_pos);
                        }
                    } else {
                        let keys_obj = val.call_method0("keys")?;
                        let mut key_vec: Vec<Bound<'_, PyAny>> = Vec::new();
                        for k_res in keys_obj.try_iter()? {
                            key_vec.push(k_res?);
                        }
                        let mut raw_pairs: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)> =
                            Vec::with_capacity(key_vec.len());
                        for k in key_vec {
                            let v = val.get_item(&k)?;
                            raw_pairs.push((k, v));
                        }
                        let use_len4 = 3usize
                            .saturating_add(raw_pairs.len().saturating_mul(entry_min))
                            > 16_383;
                        fp.write_tag_to(enc.buf_mut());
                        let len_pos = enc.buf_mut().len();
                        if use_len4 {
                            enc.buf_mut()
                                .extend_from_slice(&[0, 0, 0, 0, *key_wt, *val_wt]);
                        } else {
                            enc.buf_mut().extend_from_slice(&[0, 0, *key_wt, *val_wt]);
                        }
                        self.write_snapshot_map_entries(
                            py,
                            enc,
                            fp,
                            *key_kind,
                            val_plan,
                            raw_pairs,
                            deterministic,
                            depth,
                        )?;
                        if use_len4 {
                            backpatch_container_len4(enc.buf_mut(), len_pos);
                        } else {
                            backpatch_container_len(enc.buf_mut(), len_pos);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_snapshot_map_entries(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        fp: &FieldPlan,
        key_kind: ScalarKind,
        val_plan: &MapValPlan,
        raw_pairs: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)>,
        deterministic: bool,
        depth: usize,
    ) -> PyResult<()> {
        let n_entries = raw_pairs.len();
        let ordered_pairs: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)> =
            if deterministic && n_entries > 1 {
                let mut keyed: Vec<(SortableMapKey, Bound<'_, PyAny>, Bound<'_, PyAny>)> =
                    Vec::with_capacity(n_entries);
                for (k, v) in raw_pairs {
                    let sk = extract_sortable_key(py, key_kind, k.as_ptr(), &fp.wire_name)?;
                    keyed.push((sk, k, v));
                }
                keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                keyed.into_iter().map(|(_, k, v)| (k, v)).collect()
            } else {
                raw_pairs
            };

        append_varint(enc.buf_mut(), ordered_pairs.len() as u64);
        for (k, v) in &ordered_pairs {
            write_scalar_payload(py, enc.buf_mut(), key_kind, k.as_ptr(), &fp.wire_name)?;
            match val_plan {
                MapValPlan::Scalar { kind: vk, .. } => {
                    write_scalar_payload(py, enc.buf_mut(), *vk, v.as_ptr(), &fp.wire_name)?;
                }
                MapValPlan::SubMsg(sub_c) => {
                    if v.is_none() {
                        return Err(encode_err(
                            py,
                            format!("omnibuf: map values in {} cannot be None", fp.wire_name),
                        ));
                    }
                    enc.begin_container();
                    sub_c
                        .get()
                        .encode_msg_into(py, enc, v.as_ptr(), deterministic, depth + 2)?;
                    enc.end_container();
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encode_msg_into(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        obj_ptr: *mut ffi::PyObject,
        deterministic: bool,
        depth: usize,
    ) -> PyResult<()> {
        if depth > MAX_NESTING_DEPTH {
            return Err(encode_err(
                py,
                format!("omnibuf: nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}"),
            ));
        }
        let inner = self.inner_plan(py)?;
        if HAS_GIL
            && let Some(res) =
                unsafe { self.try_encode_pure_fast_slots(py, enc.buf_mut(), inner, obj_ptr, depth) }
        {
            return res;
        }
        let obj_bound = unsafe { Borrowed::from_ptr(py, obj_ptr) };

        for fp in &inner.fields {
            if fp.pbpy_presence {
                let has: bool = obj_bound
                    .call_method1(&inner.has_field_intern, (&fp.attr_str,))?
                    .extract()?;
                if !has {
                    continue;
                }
            }

            let raw_val = fp.access.get(py, obj_ptr)?;
            let val = if raw_val.is_none() {
                if fp.skip_if_none {
                    continue;
                }
                match fp.make_default(py)? {
                    Some(def_v) => def_v,
                    None => continue,
                }
            } else {
                if !self.pbpy_mode && !fp.oneof_siblings.is_empty() {
                    for &sib_idx in &fp.oneof_siblings {
                        if sib_idx > fp.index {
                            let sib_val = inner.fields[sib_idx].access.get(py, obj_ptr)?;
                            if !sib_val.is_none() {
                                return Err(encode_err(
                                    py,
                                    format!(
                                        "omnibuf: multiple fields set in oneof ({} and {})",
                                        fp.wire_name, inner.fields[sib_idx].wire_name
                                    ),
                                ));
                            }
                        }
                    }
                }
                raw_val
            };

            if fp.omitempty && self.is_value_empty(py, fp, &val, depth)? {
                continue;
            }

            self.encode_field_value(py, enc, fp, &val, deterministic, depth)?;
        }
        Ok(())
    }

    pub fn decode_slice<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        out: Option<&Bound<'py, PyAny>>,
        depth: usize,
        merge: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut budget = DecodeBudget::default_budget();
        self.decode_slice_budget(py, data, out, depth, merge, &mut budget, None)
    }

    #[cold]
    #[inline(never)]
    fn decode_fast_slot_missing_defaults(
        &self,
        py: Python<'_>,
        inner: &CodecInner,
        dst_ptr: *mut ffi::PyObject,
        seen_64: u64,
    ) -> PyResult<()> {
        for fp in &inner.fields {
            if (seen_64 & (1u64 << fp.index)) == 0
                && let Some(def_val) = fp.make_default(py)?
            {
                unsafe {
                    let slot = dst_ptr
                        .byte_add(fp.slot_offset)
                        .cast::<*mut ffi::PyObject>();
                    *slot = def_val.into_ptr();
                }
            }
        }
        Ok(())
    }

    #[cold]
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn decode_fast_slot_cold_field(
        &self,
        py: Python<'_>,
        inner: &CodecInner,
        dst_ptr: *mut ffi::PyObject,
        f_idx: usize,
        fdf: &FastDecodeField,
        already_seen: bool,
        data: &[u8],
        pos: usize,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> PyResult<usize> {
        let fp = unsafe { inner.fields.get_unchecked(f_idx) };
        let slot = unsafe {
            dst_ptr
                .byte_add(usize::from(fdf.slot_offset))
                .cast::<*mut ffi::PyObject>()
        };
        match fdf.kind {
            FastKind::Enum => {
                let enum_cls = match &fp.kind {
                    FieldPlanKind::Scalar { enum_cls, .. } => enum_cls.as_ref(),
                    _ => None,
                };
                let (val_obj, next_pos) =
                    read_scalar_payload(py, data, pos, ScalarKind::Enum, enum_cls, None)?;
                unsafe {
                    let rv = val_obj.into_ptr();
                    if !already_seen {
                        *slot = rv;
                    } else {
                        let old = *slot;
                        *slot = rv;
                        ffi::Py_XDECREF(old);
                    }
                }
                Ok(next_pos)
            }
            FastKind::SubMsg => {
                let (sub_slice, next_pos) =
                    read_len_slice_fast(data, pos, 0).map_err(|m| decode_err(py, m))?;
                let sub_c = unsafe { &*fdf.sub_codec };
                let cur_sub = fp.access.get_optional(py, dst_ptr)?;
                let sub_merge = cur_sub.is_some();
                let decoded_sub = sub_c.decode_slice_budget(
                    py,
                    sub_slice,
                    cur_sub.as_ref(),
                    depth + 1,
                    sub_merge,
                    budget,
                    None,
                )?;
                if cur_sub.is_none() {
                    unsafe {
                        let rv = decoded_sub.into_ptr();
                        let old = *slot;
                        *slot = rv;
                        ffi::Py_XDECREF(old);
                    }
                }
                Ok(next_pos)
            }
            FastKind::ArrayScalar => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let (arr_body, next_pos) =
                    read_len_slice_fast(data, pos, 2).map_err(|m| decode_err(py, m))?;
                let (ewt, count, mut p) = parse_array_header_fast(arr_body).ok_or_else(|| {
                    decode_err(
                        py,
                        format!("omnibuf: invalid array header on field {}", fp.wire_name),
                    )
                })?;
                if ewt != fdf.elem_wt {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: invalid array element wire type on field {}",
                            fp.wire_name
                        ),
                    ));
                }
                budget.consume(py, count)?;
                let enum_cls = match &fp.kind {
                    FieldPlanKind::ArrayScalar { enum_cls, .. } => enum_cls.as_ref(),
                    _ => None,
                };
                let cur_opt = fp.access.get_optional(py, dst_ptr)?;
                let list = match cur_opt {
                    Some(existing) if existing.is_instance_of::<PyList>() => existing,
                    _ => {
                        let fresh = PyList::empty(py).into_any();
                        fp.access.set(py, dst_ptr, fresh.as_ptr())?;
                        fresh
                    }
                };
                for i in 0..count {
                    if (i & 0xFFF) == 0xFFF {
                        py.check_signals()?;
                    }
                    let (item, next_p) =
                        read_scalar_payload(py, arr_body, p, fdf.elem_kind, enum_cls, None)?;
                    p = next_p;
                    unsafe {
                        if ffi::PyList_Append(list.as_ptr(), item.as_ptr()) != 0 {
                            return Err(PyErr::fetch(py));
                        }
                    }
                }
                if p != arr_body.len() {
                    return Err(decode_err(
                        py,
                        format!("omnibuf: trailing array bytes on field {}", fp.wire_name),
                    ));
                }
                Ok(next_pos)
            }
            FastKind::ArraySubMsg => {
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let (arr_body, next_pos) =
                    read_len_slice_fast(data, pos, 2).map_err(|m| decode_err(py, m))?;
                let (ewt, count, mut p) = parse_array_header_fast(arr_body).ok_or_else(|| {
                    decode_err(
                        py,
                        format!(
                            "omnibuf: invalid submsg array header on field {}",
                            fp.wire_name
                        ),
                    )
                })?;
                if ewt != WIRE_SUB_MSG {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: invalid submsg array header on field {}",
                            fp.wire_name
                        ),
                    ));
                }
                budget.consume(py, count)?;
                let sub_c = unsafe { &*fdf.sub_codec };
                let cur_opt = fp.access.get_optional(py, dst_ptr)?;
                let list = match cur_opt {
                    Some(existing) if existing.is_instance_of::<PyList>() => existing,
                    _ => {
                        let fresh = PyList::empty(py).into_any();
                        fp.access.set(py, dst_ptr, fresh.as_ptr())?;
                        fresh
                    }
                };
                for i in 0..count {
                    if (i & 0xFFF) == 0xFFF {
                        py.check_signals()?;
                    }
                    let (elem_slice, next_p) =
                        read_len_slice_fast(arr_body, p, 0).map_err(|m| decode_err(py, m))?;
                    p = next_p;
                    let elem_obj = sub_c.decode_slice_budget(
                        py,
                        elem_slice,
                        None,
                        depth + 2,
                        false,
                        budget,
                        None,
                    )?;
                    unsafe {
                        if ffi::PyList_Append(list.as_ptr(), elem_obj.as_ptr()) != 0 {
                            return Err(PyErr::fetch(py));
                        }
                    }
                }
                if p != arr_body.len() {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: trailing submsg array bytes on field {}",
                            fp.wire_name
                        ),
                    ));
                }
                Ok(next_pos)
            }
            FastKind::Map => {
                let FieldPlanKind::Map {
                    key_kind,
                    key_wt,
                    val_wt,
                    val_plan,
                } = &fp.kind
                else {
                    unreachable!()
                };
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(decode_err(
                        py,
                        format!(
                            "omnibuf: map nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                            depth + 1
                        ),
                    ));
                }
                let (map_body, next_pos) =
                    read_len_slice_fast(data, pos, 3).map_err(|m| decode_err(py, m))?;
                let (kwt, vwt, count, mut p) = parse_map_header(map_body).ok_or_else(|| {
                    decode_err(
                        py,
                        format!("omnibuf: invalid map header on field {}", fp.wire_name),
                    )
                })?;
                if kwt != *key_wt || vwt != *val_wt {
                    return Err(decode_err(
                        py,
                        format!("omnibuf: invalid map header on field {}", fp.wire_name),
                    ));
                }
                budget.consume(py, count)?;
                let dict_any = if !already_seen {
                    let d = PyDict::new(py).into_any();
                    unsafe {
                        let d_ptr = d.as_ptr();
                        ffi::Py_INCREF(d_ptr);
                        *slot = d_ptr;
                    }
                    d
                } else {
                    match fp.access.get_optional(py, dst_ptr)? {
                        Some(existing) if existing.is_instance_of::<PyDict>() => existing,
                        _ => {
                            let d = PyDict::new(py).into_any();
                            fp.access.set(py, dst_ptr, d.as_ptr())?;
                            d
                        }
                    }
                };
                for i in 0..count {
                    if (i & 0xFFF) == 0xFFF {
                        py.check_signals()?;
                    }
                    let (k_obj, after_k) =
                        read_scalar_payload(py, map_body, p, *key_kind, None, None)?;
                    let (v_obj, after_v) = match val_plan {
                        MapValPlan::Scalar {
                            kind: vk,
                            enum_cls: ve,
                        } => read_scalar_payload(py, map_body, after_k, *vk, ve.as_ref(), None)?,
                        MapValPlan::SubMsg(sub_c) => {
                            let (v_slice, vp) = read_len_slice_fast(map_body, after_k, 0)
                                .map_err(|m| decode_err(py, m))?;
                            let msg_v = sub_c.get().decode_slice_budget(
                                py,
                                v_slice,
                                None,
                                depth + 2,
                                false,
                                budget,
                                None,
                            )?;
                            (msg_v, vp)
                        }
                    };
                    p = after_v;
                    unsafe {
                        if ffi::PyDict_SetItem(dict_any.as_ptr(), k_obj.as_ptr(), v_obj.as_ptr())
                            != 0
                        {
                            return Err(PyErr::fetch(py));
                        }
                    }
                }
                if p != map_body.len() {
                    return Err(decode_err(
                        py,
                        format!("omnibuf: trailing map bytes on field {}", fp.wire_name),
                    ));
                }
                Ok(next_pos)
            }
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    unsafe fn try_decode_pure_fast_slots_dispatch<'py>(
        &self,
        py: Python<'py>,
        inner: &CodecInner,
        data: &[u8],
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> PyResult<Bound<'py, PyAny>> {
        if data.len() < 4096 {
            unsafe { self.try_decode_pure_fast_slots_impl::<false>(py, inner, data, depth, budget) }
        } else {
            unsafe { self.try_decode_pure_fast_slots_impl::<true>(py, inner, data, depth, budget) }
        }
    }

    #[inline]
    unsafe fn try_decode_pure_fast_slots_impl<'py, const CHECK_SIGNALS: bool>(
        &self,
        py: Python<'py>,
        inner: &CodecInner,
        data: &[u8],
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inst = self.alloc_raw_slot_instance_with(py, inner)?;
        let dst_ptr = inst.as_ptr();
        let empty_str = inner.empty_str.as_ptr();
        let mut seen_64: u64 = 0;
        let mut pos = 0usize;
        let n = data.len();
        let mut step = 0usize;

        while pos < n {
            if CHECK_SIGNALS {
                step += 1;
                if (step & 0xFFF) == 0 {
                    py.check_signals()?;
                }
            }
            let b0 = unsafe { *data.get_unchecked(pos) };
            let (f_idx, wt): (usize, u8) = if (b0 & 1) != 0 {
                let tag = usize::from(b0 >> 1);
                let mapped = unsafe { *inner.fast_tag_map.get_unchecked(tag) };
                pos += 1;
                if mapped != u8::MAX {
                    (usize::from(mapped), (tag & 0x0F) as u8)
                } else {
                    let fnum = (tag >> 4) as u32;
                    let wt = (tag & 0x0F) as u8;
                    if fnum == 0 {
                        if wt != WIRE_SUB_MSG {
                            return Err(decode_err(
                                py,
                                format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                            ));
                        }
                        pos = validate_field0_slice(data, pos, depth)
                            .map_err(|m| decode_err(py, m))?;
                        continue;
                    }
                    pos = validate_unknown_value(py, data, pos, wt, depth)?;
                    continue;
                }
            } else {
                let (tag, tn) = decode_varint_fast(data, pos).ok_or_else(|| {
                    decode_err(
                        py,
                        format!("omnibuf: invalid or truncated tag at byte {pos}"),
                    )
                })?;
                if (tag >> 4) > omnibuf_core::wire::MAX_FIELD_NUMBER {
                    return Err(decode_err(
                        py,
                        "omnibuf: field number exceeds maximum 29-bit limit",
                    ));
                }
                pos += tn;
                let fnum = (tag >> 4) as u32;
                let wt = (tag & 0x0F) as u8;

                if fnum == 0 {
                    if wt != WIRE_SUB_MSG {
                        return Err(decode_err(
                            py,
                            format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                        ));
                    }
                    pos = validate_field0_slice(data, pos, depth).map_err(|m| decode_err(py, m))?;
                    continue;
                }

                let Some(idx) = lookup_field_index(inner, fnum) else {
                    pos = validate_unknown_value(py, data, pos, wt, depth)?;
                    continue;
                };
                let fdf_chk = unsafe { inner.fast_decode_fields.get_unchecked(idx) };
                let wt_ok = if fdf_chk.kind == FastKind::Bool {
                    wt == WIRE_BOOL_FALSE || wt == WIRE_BOOL_TRUE
                } else {
                    fdf_chk.wire_type == wt
                };
                if !wt_ok {
                    pos = validate_unknown_value(py, data, pos, wt, depth)?;
                    continue;
                }
                (idx, wt)
            };

            let fdf = unsafe { inner.fast_decode_fields.get_unchecked(f_idx) };
            let bit = 1u64 << f_idx;
            let already_seen = (seen_64 & bit) != 0;
            seen_64 |= bit;

            let slot = unsafe {
                dst_ptr
                    .byte_add(usize::from(fdf.slot_offset))
                    .cast::<*mut ffi::PyObject>()
            };

            macro_rules! store_slot {
                ($raw_val:expr) => {
                    unsafe {
                        let rv: *mut ffi::PyObject = $raw_val;
                        if !already_seen {
                            *slot = rv;
                        } else {
                            let old = *slot;
                            *slot = rv;
                            ffi::Py_XDECREF(old);
                        }
                    }
                };
            }

            match fdf.kind {
                FastKind::Bool => {
                    let b_ptr = unsafe {
                        let p = if wt == WIRE_BOOL_TRUE {
                            ffi::Py_True()
                        } else {
                            ffi::Py_False()
                        };
                        ffi::Py_INCREF(p);
                        p
                    };
                    store_slot!(b_ptr);
                }
                FastKind::Uint32 => {
                    let (v, w) = decode_varint_fast(data, pos)
                        .ok_or_else(|| decode_err(py, "omnibuf: invalid uint32 varint"))?;
                    pos += w;
                    let raw_val = unsafe { py_long_from_u32(py, v as u32)? };
                    store_slot!(raw_val);
                }
                FastKind::Uint64 => {
                    let (v, w) = decode_varint_fast(data, pos)
                        .ok_or_else(|| decode_err(py, "omnibuf: invalid uint64 varint"))?;
                    pos += w;
                    let raw_val = unsafe { py_long_from_u64(py, v)? };
                    store_slot!(raw_val);
                }
                FastKind::Sint32 => {
                    let (v, w) = decode_varint_fast(data, pos)
                        .ok_or_else(|| decode_err(py, "omnibuf: invalid sint32 varint"))?;
                    pos += w;
                    let raw_val = unsafe { py_long_from_i32(py, decode_zigzag(v) as i32)? };
                    store_slot!(raw_val);
                }
                FastKind::Sint64 => {
                    let (v, w) = decode_varint_fast(data, pos)
                        .ok_or_else(|| decode_err(py, "omnibuf: invalid sint64 varint"))?;
                    pos += w;
                    let raw_val = unsafe { py_long_from_i64(py, decode_zigzag(v))? };
                    store_slot!(raw_val);
                }
                FastKind::Enum => {
                    if !fdf.has_enum_cls {
                        let (v, w) = decode_varint_fast(data, pos)
                            .ok_or_else(|| decode_err(py, "omnibuf: invalid enum varint"))?;
                        pos += w;
                        let raw_val = unsafe { py_long_from_i32(py, decode_zigzag(v) as i32)? };
                        store_slot!(raw_val);
                    } else {
                        pos = self.decode_fast_slot_cold_field(
                            py,
                            inner,
                            dst_ptr,
                            f_idx,
                            fdf,
                            already_seen,
                            data,
                            pos,
                            depth,
                            budget,
                        )?;
                    }
                }
                FastKind::Fixed32 => {
                    if pos + 4 > n {
                        return Err(decode_err(py, "omnibuf: truncated fixed32"));
                    }
                    let u = u32::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u32>())
                    });
                    pos += 4;
                    let raw_val = unsafe { py_long_from_u32(py, u)? };
                    store_slot!(raw_val);
                }
                FastKind::Sfixed32 => {
                    if pos + 4 > n {
                        return Err(decode_err(py, "omnibuf: truncated sfixed32"));
                    }
                    let i = i32::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<i32>())
                    });
                    pos += 4;
                    let raw_val = unsafe { py_long_from_i32(py, i)? };
                    store_slot!(raw_val);
                }
                FastKind::Fixed64 => {
                    if pos + 8 > n {
                        return Err(decode_err(py, "omnibuf: truncated fixed64"));
                    }
                    let u = u64::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u64>())
                    });
                    pos += 8;
                    let raw_val = unsafe { py_long_from_u64(py, u)? };
                    store_slot!(raw_val);
                }
                FastKind::Sfixed64 => {
                    if pos + 8 > n {
                        return Err(decode_err(py, "omnibuf: truncated sfixed64"));
                    }
                    let i = i64::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<i64>())
                    });
                    pos += 8;
                    let raw_val = unsafe { py_long_from_i64(py, i)? };
                    store_slot!(raw_val);
                }
                FastKind::Float32 => {
                    if pos + 4 > n {
                        return Err(decode_err(py, "omnibuf: truncated float32"));
                    }
                    let bits = u32::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u32>())
                    });
                    pos += 4;
                    let raw_val =
                        unsafe { py_float_from_f64(py, f64::from(f32::from_bits(bits)))? };
                    store_slot!(raw_val);
                }
                FastKind::Float64 => {
                    if pos + 8 > n {
                        return Err(decode_err(py, "omnibuf: truncated float64"));
                    }
                    let bits = u64::from_le(unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u64>())
                    });
                    pos += 8;
                    let raw_val = unsafe { py_float_from_f64(py, f64::from_bits(bits))? };
                    store_slot!(raw_val);
                }
                FastKind::String => {
                    let (s_bytes, next_pos) =
                        read_len_slice_fast(data, pos, 0).map_err(|m| decode_err(py, m))?;
                    pos = next_pos;
                    let raw_val = unsafe { py_str_from_utf8_fast(py, s_bytes, empty_str)? };
                    store_slot!(raw_val);
                }
                FastKind::Bytes => {
                    let (b, next_pos) =
                        read_len_slice_fast(data, pos, 0).map_err(|m| decode_err(py, m))?;
                    pos = next_pos;
                    let raw_val = PyBytes::new(py, b).into_any().into_ptr();
                    store_slot!(raw_val);
                }
                FastKind::BytesAsStr => {
                    let (b, next_pos) =
                        read_len_slice_fast(data, pos, 0).map_err(|m| decode_err(py, m))?;
                    validate_utf8(b).map_err(|e| decode_err(py, e.to_string()))?;
                    pos = next_pos;
                    let raw_val = PyBytes::new(py, b).into_any().into_ptr();
                    store_slot!(raw_val);
                }
                FastKind::SubMsg => {
                    if already_seen {
                        pos = self.decode_fast_slot_cold_field(
                            py, inner, dst_ptr, f_idx, fdf, true, data, pos, depth, budget,
                        )?;
                        continue;
                    }
                    let (sub_slice, next_pos) =
                        read_len_slice_fast(data, pos, 0).map_err(|m| decode_err(py, m))?;
                    pos = next_pos;
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let sub_c = unsafe { &*fdf.sub_codec };
                    let sub_inner = if !fdf.sub_inner.is_null() {
                        unsafe { &*fdf.sub_inner }
                    } else {
                        sub_c.inner_plan(py)?
                    };
                    let decoded_sub = if sub_inner.fast_slot_decode {
                        unsafe {
                            if !CHECK_SIGNALS {
                                sub_c.try_decode_pure_fast_slots_impl::<false>(
                                    py,
                                    sub_inner,
                                    sub_slice,
                                    depth + 1,
                                    budget,
                                )?
                            } else {
                                sub_c.try_decode_pure_fast_slots_dispatch(
                                    py,
                                    sub_inner,
                                    sub_slice,
                                    depth + 1,
                                    budget,
                                )?
                            }
                        }
                    } else {
                        sub_c.decode_slice_budget(
                            py,
                            sub_slice,
                            None,
                            depth + 1,
                            false,
                            budget,
                            None,
                        )?
                    };
                    unsafe {
                        *slot = decoded_sub.into_ptr();
                    }
                }
                FastKind::ArrayScalar => {
                    if already_seen {
                        pos = self.decode_fast_slot_cold_field(
                            py, inner, dst_ptr, f_idx, fdf, true, data, pos, depth, budget,
                        )?;
                        continue;
                    }
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let (arr_body, next_pos) =
                        read_len_slice_fast(data, pos, 2).map_err(|m| decode_err(py, m))?;
                    pos = next_pos;
                    let (ewt, count, mut p) =
                        parse_array_header_fast(arr_body).ok_or_else(|| {
                            decode_err(
                                py,
                                format!(
                                    "omnibuf: invalid array header on field {}",
                                    inner.fields[f_idx].wire_name
                                ),
                            )
                        })?;
                    if ewt != fdf.elem_wt {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: invalid array element wire type on field {}",
                                inner.fields[f_idx].wire_name
                            ),
                        ));
                    }
                    budget.consume(py, count)?;
                    unsafe {
                        let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                        let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                        let lp = list.as_ptr();
                        let arr_len = arr_body.len();
                        match fdf.elem_kind {
                            ScalarKind::Uint32 => {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (v, w) =
                                        decode_varint_fast(arr_body, p).ok_or_else(|| {
                                            decode_err(py, "omnibuf: invalid uint32 varint")
                                        })?;
                                    p += w;
                                    let item_ptr = py_long_from_u32(py, v as u32)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Uint64 => {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (v, w) =
                                        decode_varint_fast(arr_body, p).ok_or_else(|| {
                                            decode_err(py, "omnibuf: invalid uint64 varint")
                                        })?;
                                    p += w;
                                    let item_ptr = py_long_from_u64(py, v)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Sint32 => {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (v, w) =
                                        decode_varint_fast(arr_body, p).ok_or_else(|| {
                                            decode_err(py, "omnibuf: invalid sint32 varint")
                                        })?;
                                    p += w;
                                    let item_ptr = py_long_from_i32(py, decode_zigzag(v) as i32)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Sint64 => {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (v, w) =
                                        decode_varint_fast(arr_body, p).ok_or_else(|| {
                                            decode_err(py, "omnibuf: invalid sint64 varint")
                                        })?;
                                    p += w;
                                    let item_ptr = py_long_from_i64(py, decode_zigzag(v))?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::String | ScalarKind::StrAsBytes => {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (s_bytes, next_p) = read_len_slice_fast(arr_body, p, 0)
                                        .map_err(|m| decode_err(py, m))?;
                                    p = next_p;
                                    let item_ptr = py_str_from_utf8_fast(py, s_bytes, empty_str)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Bool => {
                                if arr_len - p != count {
                                    return Err(decode_err(
                                        py,
                                        "omnibuf: invalid bool array byte length",
                                    ));
                                }
                                for i in 0..count {
                                    let b = *arr_body.get_unchecked(p + i);
                                    if b > 1 {
                                        return Err(decode_err(
                                            py,
                                            format!("omnibuf: invalid bool byte 0x{b:02x}"),
                                        ));
                                    }
                                    let bp = if b == 1 {
                                        ffi::Py_True()
                                    } else {
                                        ffi::Py_False()
                                    };
                                    ffi::Py_INCREF(bp);
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, bp);
                                }
                                p += count;
                            }
                            ScalarKind::Float32 => {
                                if Some(arr_len - p) != count.checked_mul(4) {
                                    return Err(decode_err(py, "omnibuf: truncated float32 array"));
                                }
                                for i in 0..count {
                                    let bits = u32::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<u32>(),
                                    ));
                                    p += 4;
                                    let item_ptr =
                                        py_float_from_f64(py, f64::from(f32::from_bits(bits)))?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Float64 => {
                                if Some(arr_len - p) != count.checked_mul(8) {
                                    return Err(decode_err(py, "omnibuf: truncated float64 array"));
                                }
                                for i in 0..count {
                                    let bits = u64::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<u64>(),
                                    ));
                                    p += 8;
                                    let item_ptr = py_float_from_f64(py, f64::from_bits(bits))?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Fixed32 => {
                                if Some(arr_len - p) != count.checked_mul(4) {
                                    return Err(decode_err(py, "omnibuf: truncated fixed32 array"));
                                }
                                for i in 0..count {
                                    let u = u32::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<u32>(),
                                    ));
                                    p += 4;
                                    let item_ptr = py_long_from_u32(py, u)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Sfixed32 => {
                                if Some(arr_len - p) != count.checked_mul(4) {
                                    return Err(decode_err(
                                        py,
                                        "omnibuf: truncated sfixed32 array",
                                    ));
                                }
                                for i in 0..count {
                                    let v = i32::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<i32>(),
                                    ));
                                    p += 4;
                                    let item_ptr = py_long_from_i32(py, v)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Fixed64 => {
                                if Some(arr_len - p) != count.checked_mul(8) {
                                    return Err(decode_err(py, "omnibuf: truncated fixed64 array"));
                                }
                                for i in 0..count {
                                    let u = u64::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<u64>(),
                                    ));
                                    p += 8;
                                    let item_ptr = py_long_from_u64(py, u)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            ScalarKind::Sfixed64 => {
                                if Some(arr_len - p) != count.checked_mul(8) {
                                    return Err(decode_err(
                                        py,
                                        "omnibuf: truncated sfixed64 array",
                                    ));
                                }
                                for i in 0..count {
                                    let v = i64::from_le(core::ptr::read_unaligned(
                                        arr_body.as_ptr().add(p).cast::<i64>(),
                                    ));
                                    p += 8;
                                    let item_ptr = py_long_from_i64(py, v)?;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item_ptr);
                                }
                            }
                            _ => {
                                let fp = inner.fields.get_unchecked(f_idx);
                                let enum_cls = match &fp.kind {
                                    FieldPlanKind::ArrayScalar { enum_cls, .. } => {
                                        enum_cls.as_ref()
                                    }
                                    _ => None,
                                };
                                for i in 0..count {
                                    if (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (item, next_p) = read_scalar_payload(
                                        py,
                                        arr_body,
                                        p,
                                        fdf.elem_kind,
                                        enum_cls,
                                        None,
                                    )?;
                                    p = next_p;
                                    ffi::PyList_SET_ITEM(lp, i as ffi::Py_ssize_t, item.into_ptr());
                                }
                            }
                        }
                        *slot = list.into_ptr();
                    }
                    if p != arr_body.len() {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: trailing array bytes on field {}",
                                inner.fields[f_idx].wire_name
                            ),
                        ));
                    }
                }
                FastKind::ArraySubMsg => {
                    if already_seen {
                        pos = self.decode_fast_slot_cold_field(
                            py, inner, dst_ptr, f_idx, fdf, true, data, pos, depth, budget,
                        )?;
                        continue;
                    }
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let (arr_body, next_pos) =
                        read_len_slice_fast(data, pos, 2).map_err(|m| decode_err(py, m))?;
                    pos = next_pos;
                    let (ewt, count, mut p) =
                        parse_array_header_fast(arr_body).ok_or_else(|| {
                            decode_err(
                                py,
                                format!(
                                    "omnibuf: invalid submsg array header on field {}",
                                    inner.fields[f_idx].wire_name
                                ),
                            )
                        })?;
                    if ewt != WIRE_SUB_MSG {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: invalid submsg array header on field {}",
                                inner.fields[f_idx].wire_name
                            ),
                        ));
                    }
                    budget.consume(py, count)?;
                    let sub_c = unsafe { &*fdf.sub_codec };
                    unsafe {
                        let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                        let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                        let lp = list.as_ptr();
                        if count > 0 {
                            if depth + 2 > MAX_NESTING_DEPTH {
                                return Err(decode_err(
                                    py,
                                    format!(
                                        "omnibuf: nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                        depth + 2
                                    ),
                                ));
                            }
                            let sub_inner = if !fdf.sub_inner.is_null() {
                                &*fdf.sub_inner
                            } else {
                                sub_c.inner_plan(py)?
                            };
                            if sub_inner.fast_slot_decode {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (elem_slice, next_p) = read_len_slice_fast(arr_body, p, 0)
                                        .map_err(|m| decode_err(py, m))?;
                                    p = next_p;
                                    let elem_obj = if !CHECK_SIGNALS {
                                        sub_c.try_decode_pure_fast_slots_impl::<false>(
                                            py,
                                            sub_inner,
                                            elem_slice,
                                            depth + 2,
                                            budget,
                                        )?
                                    } else {
                                        sub_c.try_decode_pure_fast_slots_dispatch(
                                            py,
                                            sub_inner,
                                            elem_slice,
                                            depth + 2,
                                            budget,
                                        )?
                                    };
                                    ffi::PyList_SET_ITEM(
                                        lp,
                                        i as ffi::Py_ssize_t,
                                        elem_obj.into_ptr(),
                                    );
                                }
                            } else {
                                for i in 0..count {
                                    if CHECK_SIGNALS && (i & 0xFFF) == 0xFFF {
                                        py.check_signals()?;
                                    }
                                    let (elem_slice, next_p) = read_len_slice_fast(arr_body, p, 0)
                                        .map_err(|m| decode_err(py, m))?;
                                    p = next_p;
                                    let elem_obj = sub_c.decode_slice_budget(
                                        py,
                                        elem_slice,
                                        None,
                                        depth + 2,
                                        false,
                                        budget,
                                        None,
                                    )?;
                                    ffi::PyList_SET_ITEM(
                                        lp,
                                        i as ffi::Py_ssize_t,
                                        elem_obj.into_ptr(),
                                    );
                                }
                            }
                        }
                        *slot = list.into_ptr();
                    }
                    if p != arr_body.len() {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: trailing submsg array bytes on field {}",
                                inner.fields[f_idx].wire_name
                            ),
                        ));
                    }
                }
                FastKind::Map => {
                    pos = self.decode_fast_slot_cold_field(
                        py,
                        inner,
                        dst_ptr,
                        f_idx,
                        fdf,
                        already_seen,
                        data,
                        pos,
                        depth,
                        budget,
                    )?;
                }
            }
        }

        if seen_64 != inner.all_seen_mask_64 {
            self.decode_fast_slot_missing_defaults(py, inner, dst_ptr, seen_64)?;
        }

        Ok(inst)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_slice_budget<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        out: Option<&Bound<'py, PyAny>>,
        depth: usize,
        merge: bool,
        budget: &mut DecodeBudget,
        zc_owner: Option<(&ByteSliceOwner, usize)>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if depth > MAX_NESTING_DEPTH {
            return Err(decode_err(
                py,
                format!("omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}"),
            ));
        }
        let inner = self.inner_plan(py)?;

        if HAS_GIL && inner.fast_slot_decode && out.is_none() && !merge && zc_owner.is_none() {
            return unsafe {
                self.try_decode_pure_fast_slots_dispatch(py, inner, data, depth, budget)
            };
        }

        let (inst, is_fresh_raw) = match out {
            Some(existing) if !existing.is_none() => {
                if self.pbpy_mode && !merge {
                    for fp in &inner.fields {
                        existing.call_method1(&inner.clear_field_intern, (&fp.attr_str,))?;
                    }
                }
                (existing.clone(), false)
            }
            _ => {
                if inner.fast_alloc {
                    (self.alloc_raw_slot_instance(py)?, true)
                } else {
                    (self.cls.bind(py).call0()?, false)
                }
            }
        };

        let dst_ptr = inst.as_ptr();
        let mut seen_64: u64 = 0;
        let mut seen_ext: Vec<u64> = if inner.fields.len() > 64 {
            vec![0; inner.fields.len().div_ceil(64)]
        } else {
            Vec::new()
        };

        let mut dec =
            Decoder::with_depth(data, depth).map_err(|e| decode_err(py, e.to_string()))?;
        let mut step = 0usize;

        while let Some((fnum, wt)) = dec.next_tag().map_err(|e| decode_err(py, e.to_string()))? {
            step += 1;
            if (step & 0xFFF) == 0 {
                py.check_signals()?;
            }
            if fnum == 0 {
                if wt != WIRE_SUB_MSG {
                    return Err(decode_err(
                        py,
                        format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                    ));
                }
                let next_p = validate_field0_slice(data, dec.position(), depth)
                    .map_err(|m| decode_err(py, m))?;
                dec.set_position(next_p);
                continue;
            }

            let Some(f_idx) = lookup_field_index(inner, fnum) else {
                let next_p = validate_unknown_value(py, data, dec.position(), wt, dec.depth())?;
                dec.set_position(next_p);
                continue;
            };
            let fp = &inner.fields[f_idx];

            let is_bool = matches!(
                fp.kind,
                FieldPlanKind::Scalar {
                    kind: ScalarKind::Bool,
                    ..
                }
            );
            let wt_matches = if is_bool {
                wt == WIRE_BOOL_FALSE || wt == WIRE_BOOL_TRUE
            } else {
                fp.wire_type == wt
            };
            if !wt_matches {
                let next_p = validate_unknown_value(py, data, dec.position(), wt, dec.depth())?;
                dec.set_position(next_p);
                continue;
            }

            let mut sib_cleared = false;
            if !self.pbpy_mode && !fp.oneof_siblings.is_empty() {
                for &sib_idx in &fp.oneof_siblings {
                    inner.fields[sib_idx]
                        .access
                        .set(py, dst_ptr, unsafe { ffi::Py_None() })?;
                    if sib_idx < 64 {
                        seen_64 &= !(1u64 << sib_idx);
                    } else {
                        seen_ext[sib_idx >> 6] &= !(1u64 << (sib_idx & 63));
                    }
                    sib_cleared = true;
                }
            }

            let already_seen = if f_idx < 64 {
                let bit = 1u64 << f_idx;
                let prev = (seen_64 & bit) != 0;
                seen_64 |= bit;
                prev || merge
            } else {
                let word = f_idx >> 6;
                let bit = 1u64 << (f_idx & 63);
                let prev = (seen_ext[word] & bit) != 0;
                seen_ext[word] |= bit;
                prev || merge
            };
            let _ = sib_cleared;

            match &fp.kind {
                FieldPlanKind::Scalar {
                    kind: ScalarKind::Bool,
                    ..
                } => {
                    let b_obj = PyBool::new(py, wt == WIRE_BOOL_TRUE);
                    fp.access.set(py, dst_ptr, b_obj.as_ptr())?;
                }
                FieldPlanKind::Scalar { kind, enum_cls } => {
                    let (val_obj, next_pos) = read_scalar_payload(
                        py,
                        data,
                        dec.position(),
                        *kind,
                        enum_cls.as_ref(),
                        zc_owner,
                    )?;
                    dec.set_position(next_pos);
                    fp.access.set_owned(py, dst_ptr, val_obj)?;
                }
                FieldPlanKind::SubMsg { codec } => {
                    let sub_slice = dec
                        .read_container(0)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let sub_zc = zc_owner.map(|(owner, base)| {
                        let rel = sub_slice.as_ptr() as usize - data.as_ptr() as usize;
                        (owner, base + rel)
                    });
                    let cur_sub = if is_fresh_raw && !already_seen {
                        None
                    } else {
                        fp.access.get_optional(py, dst_ptr)?
                    };
                    let sub_merge = cur_sub.is_some() && already_seen;
                    let decoded_sub = codec.get().decode_slice_budget(
                        py,
                        sub_slice,
                        cur_sub.as_ref(),
                        depth + 1,
                        sub_merge,
                        budget,
                        sub_zc,
                    )?;
                    if cur_sub.is_none() || self.pbpy_mode {
                        fp.access.set_owned(py, dst_ptr, decoded_sub)?;
                    }
                }
                FieldPlanKind::ArrayScalar {
                    elem_kind,
                    elem_wt,
                    enum_cls,
                } => {
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let arr_body = dec
                        .read_container(2)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let arr_zc = zc_owner.map(|(owner, base)| {
                        let rel = arr_body.as_ptr() as usize - data.as_ptr() as usize;
                        (owner, base + rel)
                    });
                    let (ewt, count, mut p) = parse_array_header(arr_body).ok_or_else(|| {
                        decode_err(
                            py,
                            format!("omnibuf: invalid array header on field {}", fp.wire_name),
                        )
                    })?;
                    if ewt != *elem_wt {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: invalid array element wire type on field {}",
                                fp.wire_name
                            ),
                        ));
                    }
                    budget.consume(py, count)?;

                    if self.pbpy_mode {
                        let target_list = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_list.len()? > 0 {
                            target_list.call_method0("clear")?;
                        }
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (item, next_p) = read_scalar_payload(
                                py,
                                arr_body,
                                p,
                                *elem_kind,
                                enum_cls.as_ref(),
                                None,
                            )?;
                            p = next_p;
                            target_list.call_method1("append", (item,))?;
                        }
                    } else if !already_seen {
                        unsafe {
                            let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                            let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                            for i in 0..count {
                                if (i & 0xFFF) == 0xFFF {
                                    py.check_signals()?;
                                }
                                let (item, next_p) = read_scalar_payload(
                                    py,
                                    arr_body,
                                    p,
                                    *elem_kind,
                                    enum_cls.as_ref(),
                                    arr_zc,
                                )?;
                                p = next_p;
                                ffi::PyList_SET_ITEM(
                                    list.as_ptr(),
                                    i as ffi::Py_ssize_t,
                                    item.into_ptr(),
                                );
                            }
                            fp.access.set_owned(py, dst_ptr, list)?;
                        }
                    } else {
                        let cur_opt = fp.access.get_optional(py, dst_ptr)?;
                        let list = match cur_opt {
                            Some(existing) if existing.is_instance_of::<PyList>() => existing,
                            _ => {
                                let fresh = PyList::empty(py).into_any();
                                fp.access.set(py, dst_ptr, fresh.as_ptr())?;
                                fresh
                            }
                        };
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (item, next_p) = read_scalar_payload(
                                py,
                                arr_body,
                                p,
                                *elem_kind,
                                enum_cls.as_ref(),
                                arr_zc,
                            )?;
                            p = next_p;
                            unsafe {
                                if ffi::PyList_Append(list.as_ptr(), item.as_ptr()) != 0 {
                                    return Err(PyErr::fetch(py));
                                }
                            }
                        }
                    }

                    if p != arr_body.len() {
                        return Err(decode_err(
                            py,
                            format!("omnibuf: trailing array bytes on field {}", fp.wire_name),
                        ));
                    }
                }
                FieldPlanKind::ArraySubMsg { codec } => {
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: array nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let arr_body = dec
                        .read_container(2)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let arr_base = zc_owner.map(|(owner, base)| {
                        (
                            owner,
                            base + (arr_body.as_ptr() as usize - data.as_ptr() as usize),
                        )
                    });
                    let (ewt, count, mut p) = parse_array_header(arr_body).ok_or_else(|| {
                        decode_err(
                            py,
                            format!(
                                "omnibuf: invalid submsg array header on field {}",
                                fp.wire_name
                            ),
                        )
                    })?;
                    if ewt != WIRE_SUB_MSG {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: invalid submsg array header on field {}",
                                fp.wire_name
                            ),
                        ));
                    }
                    budget.consume(py, count)?;
                    let sub_c = codec.get();

                    if self.pbpy_mode {
                        let target_list = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_list.len()? > 0 {
                            target_list.call_method0("clear")?;
                        }
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                .map_err(|e| decode_err(py, e.to_string()))?;
                            p = next_p;
                            let elem_obj = sub_c.decode_slice_budget(
                                py,
                                elem_slice,
                                None,
                                depth + 2,
                                false,
                                budget,
                                None,
                            )?;
                            target_list.call_method1("append", (elem_obj,))?;
                        }
                    } else if !already_seen {
                        unsafe {
                            let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                            let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                            for i in 0..count {
                                if (i & 0xFFF) == 0xFFF {
                                    py.check_signals()?;
                                }
                                let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                    .map_err(|e| decode_err(py, e.to_string()))?;
                                p = next_p;
                                let elem_zc = arr_base.map(|(owner, base)| {
                                    (
                                        owner,
                                        base + (elem_slice.as_ptr() as usize
                                            - arr_body.as_ptr() as usize),
                                    )
                                });
                                let elem_obj = sub_c.decode_slice_budget(
                                    py,
                                    elem_slice,
                                    None,
                                    depth + 2,
                                    false,
                                    budget,
                                    elem_zc,
                                )?;
                                ffi::PyList_SET_ITEM(
                                    list.as_ptr(),
                                    i as ffi::Py_ssize_t,
                                    elem_obj.into_ptr(),
                                );
                            }
                            fp.access.set_owned(py, dst_ptr, list)?;
                        }
                    } else {
                        let cur_opt = fp.access.get_optional(py, dst_ptr)?;
                        let list = match cur_opt {
                            Some(existing) if existing.is_instance_of::<PyList>() => existing,
                            _ => {
                                let fresh = PyList::empty(py).into_any();
                                fp.access.set(py, dst_ptr, fresh.as_ptr())?;
                                fresh
                            }
                        };
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                .map_err(|e| decode_err(py, e.to_string()))?;
                            p = next_p;
                            let elem_zc = arr_base.map(|(owner, base)| {
                                (
                                    owner,
                                    base + (elem_slice.as_ptr() as usize
                                        - arr_body.as_ptr() as usize),
                                )
                            });
                            let elem_obj = sub_c.decode_slice_budget(
                                py,
                                elem_slice,
                                None,
                                depth + 2,
                                false,
                                budget,
                                elem_zc,
                            )?;
                            unsafe {
                                if ffi::PyList_Append(list.as_ptr(), elem_obj.as_ptr()) != 0 {
                                    return Err(PyErr::fetch(py));
                                }
                            }
                        }
                    }

                    if p != arr_body.len() {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: trailing submsg array bytes on field {}",
                                fp.wire_name
                            ),
                        ));
                    }
                }
                FieldPlanKind::Map {
                    key_kind,
                    key_wt,
                    val_wt,
                    val_plan,
                } => {
                    if depth + 1 > MAX_NESTING_DEPTH {
                        return Err(decode_err(
                            py,
                            format!(
                                "omnibuf: map nesting depth {} exceeds {MAX_NESTING_DEPTH}",
                                depth + 1
                            ),
                        ));
                    }
                    let map_body = dec
                        .read_container(3)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let map_zc = zc_owner.map(|(owner, base)| {
                        (
                            owner,
                            base + (map_body.as_ptr() as usize - data.as_ptr() as usize),
                        )
                    });
                    let (kwt, vwt, count, mut p) = parse_map_header(map_body).ok_or_else(|| {
                        decode_err(
                            py,
                            format!("omnibuf: invalid map header on field {}", fp.wire_name),
                        )
                    })?;
                    if kwt != *key_wt || vwt != *val_wt {
                        return Err(decode_err(
                            py,
                            format!("omnibuf: invalid map header on field {}", fp.wire_name),
                        ));
                    }
                    budget.consume(py, count)?;

                    if self.pbpy_mode {
                        let target_map = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_map.len()? > 0 {
                            target_map.call_method0("clear")?;
                        }
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (k_obj, after_k) =
                                read_scalar_payload(py, map_body, p, *key_kind, None, None)?;
                            let (v_obj, after_v) = match val_plan {
                                MapValPlan::Scalar {
                                    kind: vk,
                                    enum_cls: ve,
                                } => read_scalar_payload(
                                    py,
                                    map_body,
                                    after_k,
                                    *vk,
                                    ve.as_ref(),
                                    None,
                                )?,
                                MapValPlan::SubMsg(sub_c) => {
                                    let (v_slice, vp) = read_len_slice(map_body, after_k, 0)
                                        .map_err(|e| decode_err(py, e.to_string()))?;
                                    let msg_v = sub_c.get().decode_slice_budget(
                                        py,
                                        v_slice,
                                        None,
                                        depth + 2,
                                        false,
                                        budget,
                                        None,
                                    )?;
                                    (msg_v, vp)
                                }
                            };
                            p = after_v;
                            target_map.set_item(k_obj, v_obj)?;
                        }
                    } else {
                        let dict_any = if !already_seen {
                            let d = PyDict::new(py).into_any();
                            fp.access.set(py, dst_ptr, d.as_ptr())?;
                            d
                        } else {
                            match fp.access.get_optional(py, dst_ptr)? {
                                Some(existing) if existing.is_instance_of::<PyDict>() => existing,
                                _ => {
                                    let d = PyDict::new(py).into_any();
                                    fp.access.set(py, dst_ptr, d.as_ptr())?;
                                    d
                                }
                            }
                        };
                        for i in 0..count {
                            if (i & 0xFFF) == 0xFFF {
                                py.check_signals()?;
                            }
                            let (k_obj, after_k) =
                                read_scalar_payload(py, map_body, p, *key_kind, None, None)?;
                            let (v_obj, after_v) = match val_plan {
                                MapValPlan::Scalar {
                                    kind: vk,
                                    enum_cls: ve,
                                } => read_scalar_payload(
                                    py,
                                    map_body,
                                    after_k,
                                    *vk,
                                    ve.as_ref(),
                                    map_zc,
                                )?,
                                MapValPlan::SubMsg(sub_c) => {
                                    let (v_slice, vp) = read_len_slice(map_body, after_k, 0)
                                        .map_err(|e| decode_err(py, e.to_string()))?;
                                    let v_zc = map_zc.map(|(owner, base)| {
                                        (
                                            owner,
                                            base + (v_slice.as_ptr() as usize
                                                - map_body.as_ptr() as usize),
                                        )
                                    });
                                    let msg_v = sub_c.get().decode_slice_budget(
                                        py,
                                        v_slice,
                                        None,
                                        depth + 2,
                                        false,
                                        budget,
                                        v_zc,
                                    )?;
                                    (msg_v, vp)
                                }
                            };
                            p = after_v;
                            unsafe {
                                if ffi::PyDict_SetItem(
                                    dict_any.as_ptr(),
                                    k_obj.as_ptr(),
                                    v_obj.as_ptr(),
                                ) != 0
                                {
                                    return Err(PyErr::fetch(py));
                                }
                            }
                        }
                    }

                    if p != map_body.len() {
                        return Err(decode_err(
                            py,
                            format!("omnibuf: trailing map bytes on field {}", fp.wire_name),
                        ));
                    }
                }
            }
        }

        if !self.pbpy_mode && (!merge || is_fresh_raw) {
            if inner.fields.len() <= 64 {
                if seen_64 != inner.all_seen_mask_64 {
                    for fp in &inner.fields {
                        if (seen_64 & (1u64 << fp.index)) == 0
                            && let Some(def_val) = fp.make_default(py)?
                        {
                            fp.access.set_owned(py, dst_ptr, def_val)?;
                        }
                    }
                }
            } else {
                for fp in &inner.fields {
                    let was_seen = if fp.index < 64 {
                        (seen_64 & (1u64 << fp.index)) != 0
                    } else {
                        (seen_ext[fp.index >> 6] & (1u64 << (fp.index & 63))) != 0
                    };
                    if !was_seen && let Some(def_val) = fp.make_default(py)? {
                        fp.access.set_owned(py, dst_ptr, def_val)?;
                    }
                }
            }
        }

        Ok(inst)
    }

    #[inline]
    pub(crate) fn marshal_raw<'py>(
        &self,
        py: Python<'py>,
        msg_ptr: *mut ffi::PyObject,
        deterministic: bool,
        self_describing: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner_plan(py)?;
        TLS_ENCODER.with(|cell| {
            if let Ok(mut enc) = cell.try_borrow_mut() {
                enc.reset();
                if self_describing {
                    self.write_field0(py, enc.buf_mut(), msg_ptr, inner)?;
                }
                self.encode_msg_into(py, &mut enc, msg_ptr, deterministic, 0)?;
                Ok(PyBytes::new(py, enc.as_bytes()))
            } else {
                let mut fallback = Encoder::new(256);
                if self_describing {
                    self.write_field0(py, fallback.buf_mut(), msg_ptr, inner)?;
                }
                self.encode_msg_into(py, &mut fallback, msg_ptr, deterministic, 0)?;
                Ok(PyBytes::new(py, fallback.as_bytes()))
            }
        })
    }
}

#[inline]
fn lookup_field_index(inner: &CodecInner, fnum: u32) -> Option<usize> {
    let idx = fnum as usize;
    if idx < inner.dense_by_num.len() {
        let mapped = inner.dense_by_num[idx];
        return (mapped != u16::MAX).then_some(usize::from(mapped));
    }
    inner
        .fields
        .binary_search_by_key(&fnum, |f| f.field_num)
        .ok()
}

#[pymethods]
impl CompiledCodec {
    #[new]
    #[pyo3(signature = (cls, type_name, *, fast_alloc=true, pbpy_mode=false))]
    fn new(cls: Py<PyType>, type_name: String, fast_alloc: bool, pbpy_mode: bool) -> Self {
        Self {
            cls,
            type_name,
            req_fast_alloc: fast_alloc,
            pbpy_mode,
            inner: OnceLock::new(),
            recursive: OnceLock::new(),
        }
    }

    #[classmethod]
    fn __class_getitem__<'py>(
        cls: &Bound<'py, PyType>,
        _item: &Bound<'py, PyAny>,
    ) -> Bound<'py, PyType> {
        cls.clone()
    }

    fn set_fields(
        &self,
        py: Python<'_>,
        specs: &Bound<'_, PyList>,
        field0_wire: &Bound<'_, PyBytes>,
    ) -> PyResult<()> {
        if self.inner.get().is_some() {
            return Ok(());
        }
        let cls_bound = self.cls.bind(py);
        let cls_dict = cls_bound.getattr("__dict__")?;
        let n = specs.len();
        let mut fields: Vec<FieldPlan> = Vec::with_capacity(n);
        let mut raw_siblings: Vec<(u32, Vec<u32>)> = Vec::new();
        let mut all_slots = self.req_fast_alloc && !self.pbpy_mode;

        for i in 0..n {
            let item = specs.get_item(i)?;
            let d = item.cast::<PyDict>()?;

            let field_num: u32 = d
                .get_item("number")?
                .ok_or_else(|| encode_err(py, "missing field number"))?
                .extract()?;
            let attr: String = d
                .get_item("attr")?
                .ok_or_else(|| encode_err(py, "missing attr"))?
                .extract()?;
            let wire_name: String = match d.get_item("wire_name")? {
                Some(wn) => wn.extract()?,
                None => attr.clone(),
            };
            let kind_str: String = d
                .get_item("kind")?
                .ok_or_else(|| encode_err(py, "missing kind"))?
                .extract()?;
            let wire_type: u8 = d
                .get_item("wire_type")?
                .ok_or_else(|| encode_err(py, "missing wire_type"))?
                .extract()?;
            let skip_if_none: bool = match d.get_item("skip_if_none")? {
                Some(v) => v.extract()?,
                None => false,
            };
            let pbpy_presence: bool = match d.get_item("pbpy_presence")? {
                Some(v) => v.extract()?,
                None => false,
            };
            let omitempty: bool = match d.get_item("omitempty")? {
                Some(v) => v.extract()?,
                None => false,
            };
            if let Some(sib_obj) = d.get_item("oneof_siblings")? {
                let sib_nums: Vec<u32> = sib_obj.extract()?;
                if !sib_nums.is_empty() {
                    raw_siblings.push((field_num, sib_nums));
                }
            }

            let attr_intern = PyString::intern(py, &attr).unbind();

            let (access, slot_offset) = if !self.pbpy_mode
                && let Ok(descr_obj) = cls_dict.get_item(&attr)
            {
                unsafe {
                    let descr_type = ffi::Py_TYPE(descr_obj.as_ptr());
                    if descr_type == std::ptr::addr_of_mut!(ffi::PyMemberDescr_Type)
                        && let Some(get_fn) = (*descr_type).tp_descr_get
                        && let Some(set_fn) = (*descr_type).tp_descr_set
                    {
                        let member_descr = descr_obj.as_ptr().cast::<ffi::PyMemberDescrObject>();
                        let owner = (*member_descr).d_common.d_type;
                        if ffi::PyType_IsSubtype(cls_bound.as_ptr().cast(), owner) == 0 {
                            return Err(encode_err(
                                py,
                                format!("omnibuf: slot {attr} belongs to an unrelated class"),
                            ));
                        }
                        let d_member = (*member_descr).d_member;
                        let (direct_offset, direct_writable) = if HAS_GIL
                            && !d_member.is_null()
                            && (*d_member).type_code == ffi::Py_T_OBJECT_EX
                            && (*d_member).offset >= 0
                            && ((*d_member).flags & (ffi::Py_RELATIVE_OFFSET | ffi::Py_AUDIT_READ))
                                == 0
                        {
                            let off = (*d_member).offset as usize;
                            let writable = ((*d_member).flags & ffi::Py_READONLY) == 0;
                            (Some(off), writable)
                        } else {
                            (None, false)
                        };
                        let raw_off = direct_offset.unwrap_or(usize::MAX);
                        (
                            FieldAccess::Slot(SlotBinding {
                                descr: descr_obj.unbind(),
                                get_fn,
                                set_fn,
                                cls_ptr: self.cls.as_ptr(),
                                direct_offset,
                                direct_writable,
                            }),
                            raw_off,
                        )
                    } else {
                        all_slots = false;
                        (FieldAccess::Attr(attr_intern.clone_ref(py)), usize::MAX)
                    }
                }
            } else {
                all_slots = false;
                (FieldAccess::Attr(attr_intern.clone_ref(py)), usize::MAX)
            };

            let enum_cls_opt: Option<Py<PyAny>> = match d.get_item("enum_cls")? {
                Some(ec) if !ec.is_none() => Some(ec.unbind()),
                _ => None,
            };

            let plan_kind = match kind_str.as_str() {
                "submsg" => {
                    let sub_c: Py<CompiledCodec> = d
                        .get_item("sub_codec")?
                        .ok_or_else(|| encode_err(py, "missing sub_codec"))?
                        .extract()?;
                    FieldPlanKind::SubMsg { codec: sub_c }
                }
                "array_scalar" | "list_scalar" => {
                    let ek_str: String = d
                        .get_item("elem_kind")?
                        .ok_or_else(|| encode_err(py, "missing elem_kind"))?
                        .extract()?;
                    let elem_kind = ScalarKind::from_name(&ek_str)
                        .ok_or_else(|| encode_err(py, format!("unknown elem_kind {ek_str}")))?;
                    let elem_wt: u8 = d
                        .get_item("elem_wt")?
                        .ok_or_else(|| encode_err(py, "missing elem_wt"))?
                        .extract()?;
                    FieldPlanKind::ArrayScalar {
                        elem_kind,
                        elem_wt,
                        enum_cls: enum_cls_opt,
                    }
                }
                "array_submsg" | "list_submsg" => {
                    let sub_c: Py<CompiledCodec> = d
                        .get_item("sub_codec")?
                        .ok_or_else(|| encode_err(py, "missing sub_codec"))?
                        .extract()?;
                    FieldPlanKind::ArraySubMsg { codec: sub_c }
                }
                "map" => {
                    let kk_str: String = d
                        .get_item("key_kind")?
                        .ok_or_else(|| encode_err(py, "missing key_kind"))?
                        .extract()?;
                    let key_kind = ScalarKind::from_name(&kk_str)
                        .ok_or_else(|| encode_err(py, format!("unknown key_kind {kk_str}")))?;
                    let key_wt: u8 = d
                        .get_item("key_wt")?
                        .ok_or_else(|| encode_err(py, "missing key_wt"))?
                        .extract()?;
                    let vk_str: String = d
                        .get_item("val_kind")?
                        .ok_or_else(|| encode_err(py, "missing val_kind"))?
                        .extract()?;
                    let val_wt: u8 = d
                        .get_item("val_wt")?
                        .ok_or_else(|| encode_err(py, "missing val_wt"))?
                        .extract()?;
                    let val_plan = if vk_str == "submsg" {
                        let sub_c: Py<CompiledCodec> = d
                            .get_item("sub_codec")?
                            .ok_or_else(|| encode_err(py, "missing map sub_codec"))?
                            .extract()?;
                        MapValPlan::SubMsg(sub_c)
                    } else {
                        let vk = ScalarKind::from_name(&vk_str)
                            .ok_or_else(|| encode_err(py, format!("unknown val_kind {vk_str}")))?;
                        MapValPlan::Scalar {
                            kind: vk,
                            enum_cls: enum_cls_opt,
                        }
                    };
                    FieldPlanKind::Map {
                        key_kind,
                        key_wt,
                        val_wt,
                        val_plan,
                    }
                }
                scalar_s => {
                    let sk = ScalarKind::from_name(scalar_s)
                        .ok_or_else(|| encode_err(py, format!("unknown scalar kind {scalar_s}")))?;
                    FieldPlanKind::Scalar {
                        kind: sk,
                        enum_cls: enum_cls_opt,
                    }
                }
            };

            let def_mode: String = match d.get_item("default_mode")? {
                Some(m) => m.extract()?,
                None => "const".to_owned(),
            };
            let default_plan = match def_mode.as_str() {
                "list" => DefaultPlan::EmptyList,
                "dict" => DefaultPlan::EmptyDict,
                "submsg" => {
                    let sub_c: Py<CompiledCodec> = d
                        .get_item("sub_codec")?
                        .ok_or_else(|| encode_err(py, "missing sub_codec for default"))?
                        .extract()?;
                    DefaultPlan::SubMsg(sub_c)
                }
                "factory" => {
                    let fac = d
                        .get_item("default_val")?
                        .ok_or_else(|| encode_err(py, "missing default_val factory"))?;
                    DefaultPlan::Factory(fac.unbind())
                }
                "pbpy" => DefaultPlan::PbpySkip,
                _ => {
                    let val = match d.get_item("default_val")? {
                        Some(v) => v.unbind(),
                        None => py.None(),
                    };
                    DefaultPlan::Const(val)
                }
            };

            let (tag_bytes, tag_len) = encode_tag_inline(field_num, wire_type);
            let (tag_false_bytes, tag_false_len) = encode_tag_inline(field_num, WIRE_BOOL_FALSE);
            let (tag_true_bytes, tag_true_len) = encode_tag_inline(field_num, WIRE_BOOL_TRUE);

            fields.push(FieldPlan {
                index: i,
                field_num,
                attr_str: attr_intern,
                wire_name,
                access,
                slot_offset,
                wire_type,
                tag_bytes,
                tag_len,
                tag_false_bytes,
                tag_false_len,
                tag_true_bytes,
                tag_true_len,
                skip_if_none,
                pbpy_presence,
                omitempty,
                oneof_siblings: Box::new([]),
                kind: plan_kind,
                default_plan,
            });
        }

        fields.sort_by_key(|f| f.field_num);
        for (idx, fp) in fields.iter_mut().enumerate() {
            fp.index = idx;
        }
        for (fnum, sib_nums) in raw_siblings {
            if let Ok(owner_idx) = fields.binary_search_by_key(&fnum, |f| f.field_num) {
                let mut sib_indices = Vec::with_capacity(sib_nums.len());
                for sn in sib_nums {
                    if sn != fnum
                        && let Ok(s_idx) = fields.binary_search_by_key(&sn, |f| f.field_num)
                    {
                        sib_indices.push(s_idx);
                    }
                }
                fields[owner_idx].oneof_siblings = sib_indices.into_boxed_slice();
            }
        }

        let fast_slot_encode = !self.pbpy_mode
            && fields.iter().all(|f| {
                f.slot_offset != usize::MAX
                    && !f.pbpy_presence
                    && !f.omitempty
                    && f.oneof_siblings.is_empty()
            });
        let min_wire_reserve = fields.len() * 8;

        let max_dense = fields
            .iter()
            .filter_map(|f| (f.field_num <= 512).then_some(f.field_num as usize))
            .max()
            .unwrap_or(0);
        let mut dense_by_num = vec![u16::MAX; max_dense + 1];
        for fp in &fields {
            if (fp.field_num as usize) < dense_by_num.len() {
                dense_by_num[fp.field_num as usize] = fp.index as u16;
            }
        }

        let all_seen_mask_64 = if fields.len() >= 64 {
            u64::MAX
        } else if fields.is_empty() {
            0
        } else {
            (1u64 << fields.len()) - 1
        };

        let tp_alloc = unsafe {
            let cls_ptr = self.cls.as_ptr().cast::<ffi::PyTypeObject>();
            let base_new = ffi::PyBaseObject_Type.tp_new;
            let same_new = match ((*cls_ptr).tp_new, base_new) {
                (Some(a), Some(b)) => std::ptr::fn_addr_eq(a, b),
                _ => false,
            };
            let same_alloc = match (*cls_ptr).tp_alloc {
                Some(a) => std::ptr::fn_addr_eq(a, ffi::PyType_GenericAlloc as ffi::allocfunc),
                None => false,
            };
            if same_new && ((*cls_ptr).tp_flags & ffi::Py_TPFLAGS_IS_ABSTRACT) == 0 && same_alloc {
                (*cls_ptr).tp_alloc
            } else {
                None
            }
        };

        let fast_slot_decode = HAS_GIL
            && !self.pbpy_mode
            && all_slots
            && tp_alloc.is_some()
            && fields.len() <= 64
            && fields.iter().all(|f| {
                f.slot_offset != usize::MAX
                    && f.slot_offset <= usize::from(u16::MAX)
                    && f.oneof_siblings.is_empty()
                    && matches!(&f.access, FieldAccess::Slot(sb) if sb.direct_writable)
            });

        let mut fast_decode_fields = Vec::with_capacity(fields.len());
        let mut fast_tag_map = [u8::MAX; 128];
        if fast_slot_decode {
            for fp in &fields {
                let (fk, elem_kind, elem_wt, has_enum_cls, sub_codec) = match &fp.kind {
                    FieldPlanKind::Scalar { kind, enum_cls } => {
                        let fk = match kind {
                            ScalarKind::Bool => FastKind::Bool,
                            ScalarKind::Uint32 => FastKind::Uint32,
                            ScalarKind::Uint64 => FastKind::Uint64,
                            ScalarKind::Sint32 => FastKind::Sint32,
                            ScalarKind::Sint64 => FastKind::Sint64,
                            ScalarKind::Enum => FastKind::Enum,
                            ScalarKind::Fixed32 => FastKind::Fixed32,
                            ScalarKind::Sfixed32 => FastKind::Sfixed32,
                            ScalarKind::Fixed64 => FastKind::Fixed64,
                            ScalarKind::Sfixed64 => FastKind::Sfixed64,
                            ScalarKind::Float32 => FastKind::Float32,
                            ScalarKind::Float64 => FastKind::Float64,
                            ScalarKind::String | ScalarKind::StrAsBytes => FastKind::String,
                            ScalarKind::Bytes => FastKind::Bytes,
                            ScalarKind::BytesAsStr => FastKind::BytesAsStr,
                        };
                        (
                            fk,
                            ScalarKind::Bool,
                            0u8,
                            enum_cls.is_some(),
                            std::ptr::null(),
                        )
                    }
                    FieldPlanKind::SubMsg { codec } => (
                        FastKind::SubMsg,
                        ScalarKind::Bool,
                        0u8,
                        false,
                        std::ptr::from_ref(codec.get()),
                    ),
                    FieldPlanKind::ArrayScalar {
                        elem_kind,
                        elem_wt,
                        enum_cls,
                    } => (
                        FastKind::ArrayScalar,
                        *elem_kind,
                        *elem_wt,
                        enum_cls.is_some(),
                        std::ptr::null(),
                    ),
                    FieldPlanKind::ArraySubMsg { codec } => (
                        FastKind::ArraySubMsg,
                        ScalarKind::Bool,
                        0u8,
                        false,
                        std::ptr::from_ref(codec.get()),
                    ),
                    FieldPlanKind::Map { .. } => (
                        FastKind::Map,
                        ScalarKind::Bool,
                        0u8,
                        false,
                        std::ptr::null(),
                    ),
                };
                let sub_inner = if !sub_codec.is_null() {
                    unsafe { (*sub_codec).inner.get() }.map_or(std::ptr::null(), std::ptr::from_ref)
                } else {
                    std::ptr::null()
                };
                fast_decode_fields.push(FastDecodeField {
                    slot_offset: fp.slot_offset as u16,
                    kind: fk,
                    wire_type: fp.wire_type,
                    elem_kind,
                    elem_wt,
                    has_enum_cls,
                    sub_codec,
                    sub_inner,
                });
                if fp.field_num >= 1 && fp.field_num <= 7 {
                    if fk == FastKind::Bool {
                        fast_tag_map[((fp.field_num << 4) | u32::from(WIRE_BOOL_FALSE)) as usize] =
                            fp.index as u8;
                        fast_tag_map[((fp.field_num << 4) | u32::from(WIRE_BOOL_TRUE)) as usize] =
                            fp.index as u8;
                    } else {
                        fast_tag_map[((fp.field_num << 4) | u32::from(fp.wire_type)) as usize] =
                            fp.index as u8;
                    }
                }
            }
        }

        let _ = self.inner.set(CodecInner {
            fields,
            fast_decode_fields,
            fast_tag_map,
            dense_by_num,
            field0_wire: field0_wire.as_bytes().to_vec(),
            fast_alloc: self.req_fast_alloc && !self.pbpy_mode,
            fast_slot_encode,
            fast_slot_decode,
            tp_alloc,
            empty_str: PyString::intern(py, "").unbind(),
            min_wire_reserve,
            all_seen_mask_64,
            has_field_intern: PyString::intern(py, "has_field").unbind(),
            clear_field_intern: PyString::intern(py, "clear_field").unbind(),
        });
        Ok(())
    }

    #[pyo3(name = "field0_bytes")]
    pub fn field0_bytes_py<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.field0_bytes())
    }

    #[pyo3(name = "encode_single_field", signature = (fnum, val, *, deterministic=false))]
    pub fn encode_single_field_py<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        val: &Bound<'py, PyAny>,
        deterministic: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut enc = Encoder::new(64);
        self.encode_single_field(py, &mut enc, fnum, val, deterministic)?;
        Ok(PyBytes::new(py, enc.as_bytes()))
    }

    #[pyo3(signature = (msg, *, deterministic=false, self_describing=false))]
    pub fn marshal<'py>(
        &self,
        py: Python<'py>,
        msg: &Bound<'py, PyAny>,
        deterministic: bool,
        self_describing: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.marshal_raw(py, msg.as_ptr(), deterministic, self_describing)
    }

    #[pyo3(signature = (data, out=None, *, max_elements=None, zero_copy_bytes=false))]
    pub fn unmarshal<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
        out: Option<&Bound<'py, PyAny>>,
        max_elements: Option<&Bound<'py, PyAny>>,
        zero_copy_bytes: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        if HAS_GIL
            && out.is_none()
            && max_elements.is_none()
            && !zero_copy_bytes
            && unsafe { ffi::PyBytes_CheckExact(data.as_ptr()) != 0 }
            && let Some(inner) = self.inner.get()
            && inner.fast_slot_decode
        {
            let slice = unsafe {
                let obj_ptr = data.as_ptr();
                let len = ffi::PyBytes_Size(obj_ptr) as usize;
                if len == 0 {
                    &[]
                } else {
                    std::slice::from_raw_parts(ffi::PyBytes_AS_STRING(obj_ptr).cast::<u8>(), len)
                }
            };
            let mut budget = DecodeBudget::default_budget();
            return unsafe {
                self.try_decode_pure_fast_slots_dispatch(py, inner, slice, 0, &mut budget)
            };
        }
        let mut budget = match max_elements {
            Some(obj) => extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        if zero_copy_bytes && !self.pbpy_mode {
            let owner = ByteSliceOwner::from_py_any(py, data)?;
            let slice = owner.as_slice(py);
            return self.decode_slice_budget(
                py,
                slice,
                out,
                0,
                false,
                &mut budget,
                Some((&owner, 0)),
            );
        }
        let input = InputBytes::extract(py, data)?;
        self.decode_slice_budget(py, input.as_slice(), out, 0, false, &mut budget, None)
    }

    #[pyo3(signature = (data, out=None, depth=0, merge=false, *, max_elements=None, zero_copy_bytes=false))]
    #[allow(clippy::too_many_arguments)]
    pub fn decode_at<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
        out: Option<&Bound<'py, PyAny>>,
        depth: usize,
        merge: bool,
        max_elements: Option<&Bound<'py, PyAny>>,
        zero_copy_bytes: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut budget = match max_elements {
            Some(obj) => extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        if zero_copy_bytes && !self.pbpy_mode {
            let owner = ByteSliceOwner::from_py_any(py, data)?;
            let slice = owner.as_slice(py);
            return self.decode_slice_budget(
                py,
                slice,
                out,
                depth,
                merge,
                &mut budget,
                Some((&owner, 0)),
            );
        }
        let input = InputBytes::extract(py, data)?;
        self.decode_slice_budget(py, input.as_slice(), out, depth, merge, &mut budget, None)
    }
}

// Keep a bounded cache of owning references. Callers retain their own reference
// while invoking Python, so eviction and reentrant registration cannot invalidate it.
const MAX_CACHED_DATACLASS_CODECS: usize = 128;

fn cache_dataclass_codec(
    _py: Python<'_>,
    cls: &Bound<'_, PyType>,
    codec: &Bound<'_, CompiledCodec>,
) {
    let mut guard = DATACLASS_CODECS.lock().unwrap_or_else(|e| e.into_inner());
    if guard.iter().any(|(c, _)| c.as_ptr() == cls.as_ptr()) {
        return;
    }
    let evicted = if guard.len() == MAX_CACHED_DATACLASS_CODECS {
        let removed = guard.remove(0);
        DATACLASS_CACHE_EPOCH.fetch_add(1, Ordering::AcqRel);
        Some(removed)
    } else {
        None
    };
    guard.push((cls.clone().unbind(), codec.clone().unbind()));
    drop(guard);
    // Dropping Python objects can run finalizers and reenter this cache.
    drop(evicted);
}

#[inline]
fn tls_put_dataclass_codec(cls_key: usize, codec_ptr: usize, epoch: u64) {
    if !HAS_GIL {
        return;
    }
    TLS_DC_CACHE.with(|cell| {
        let cur = cell.get();
        cell.set([(cls_key, codec_ptr, epoch), cur[0], cur[1], cur[2]]);
    });
}

#[cold]
#[inline(never)]
fn resolve_dataclass_codec_slow<'py>(
    py: Python<'py>,
    cls_ptr: *mut ffi::PyTypeObject,
) -> PyResult<Bound<'py, CompiledCodec>> {
    let key = cls_ptr as usize;
    let cls_obj_ptr = cls_ptr.cast::<ffi::PyObject>();
    {
        let guard = DATACLASS_CODECS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, codec)) = guard.iter().rev().find(|(c, _)| c.as_ptr() == cls_obj_ptr) {
            let epoch = DATACLASS_CACHE_EPOCH.load(Ordering::Acquire);
            let bound = codec.bind(py).clone();
            tls_put_dataclass_codec(key, bound.as_ptr() as usize, epoch);
            return Ok(bound);
        }
    }
    let resolver = DATACLASS_RESOLVER
        .get()
        .ok_or_else(|| encode_err(py, "omnibuf: dataclass codec resolver not initialized"))?;
    let cls_bound = unsafe { Borrowed::from_ptr(py, cls_obj_ptr).cast_unchecked::<PyType>() };
    let resolved = resolver.bind(py).call1((&*cls_bound,))?;
    let codec = resolved.cast::<CompiledCodec>()?.clone();
    cache_dataclass_codec(py, &cls_bound, &codec);
    {
        let guard = DATACLASS_CODECS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, cached)) = guard.iter().rev().find(|(c, _)| c.as_ptr() == cls_obj_ptr) {
            let epoch = DATACLASS_CACHE_EPOCH.load(Ordering::Acquire);
            tls_put_dataclass_codec(key, cached.as_ptr() as usize, epoch);
        }
    }
    Ok(codec)
}

#[inline(always)]
fn lookup_or_resolve_dataclass_codec<'py>(
    py: Python<'py>,
    cls_ptr: *mut ffi::PyTypeObject,
) -> PyResult<Bound<'py, CompiledCodec>> {
    if HAS_GIL {
        let key = cls_ptr as usize;
        let epoch = DATACLASS_CACHE_EPOCH.load(Ordering::Acquire);
        let codec_ptr = TLS_DC_CACHE.with(|cell| {
            let entries = cell.get();
            if entries[0].0 == key && entries[0].2 == epoch {
                return entries[0].1;
            }
            if entries[1].0 == key && entries[1].2 == epoch {
                let mut next = entries;
                next.swap(0, 1);
                cell.set(next);
                return entries[1].1;
            }
            if entries[2].0 == key && entries[2].2 == epoch {
                let mut next = entries;
                next.swap(0, 2);
                cell.set(next);
                return entries[2].1;
            }
            if entries[3].0 == key && entries[3].2 == epoch {
                let mut next = entries;
                next.swap(0, 3);
                cell.set(next);
                return entries[3].1;
            }
            0
        });
        if codec_ptr != 0 {
            // SAFETY: Under the GIL, no thread can mutate `DATACLASS_CODECS` or advance
            // `DATACLASS_CACHE_EPOCH` while `py` is held here, so the matching epoch proves
            // `DATACLASS_CODECS` still owns both `cls_ptr` and `codec_ptr`. Cloning into an
            // owning `Bound` keeps the codec alive across subsequent Python callbacks or eviction.
            let bound = unsafe {
                Borrowed::from_ptr(py, codec_ptr as *mut ffi::PyObject)
                    .cast_unchecked::<CompiledCodec>()
                    .to_owned()
            };
            return Ok(bound);
        }
    }
    resolve_dataclass_codec_slow(py, cls_ptr)
}

#[pyfunction]
pub fn register_dataclass_codec_py<'py>(
    py: Python<'py>,
    cls: &Bound<'py, PyType>,
    codec: &Bound<'py, CompiledCodec>,
) {
    cache_dataclass_codec(py, cls, codec);
}

#[pyfunction]
pub fn set_dataclass_resolver_py(resolver: &Bound<'_, PyAny>) {
    let _ = DATACLASS_RESOLVER.set(resolver.clone().unbind());
}

#[pyfunction]
#[pyo3(signature = (msg, *, deterministic=false, self_describing=false))]
pub fn marshal_dataclass_py<'py>(
    py: Python<'py>,
    msg: &Bound<'py, PyAny>,
    deterministic: bool,
    self_describing: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let msg_ptr = msg.as_ptr();
    let cls_ptr = unsafe { ffi::Py_TYPE(msg_ptr) };
    let codec = lookup_or_resolve_dataclass_codec(py, cls_ptr)?;
    codec
        .get()
        .marshal_raw(py, msg_ptr, deterministic, self_describing)
}

#[pyfunction]
#[pyo3(signature = (packet, target, *, max_elements=None, zero_copy_bytes=false))]
pub fn unmarshal_dataclass_py<'py>(
    py: Python<'py>,
    packet: &Bound<'py, PyAny>,
    target: &Bound<'py, PyAny>,
    max_elements: Option<&Bound<'py, PyAny>>,
    zero_copy_bytes: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let mut budget = match max_elements {
        Some(obj) => extract_max_elements(py, obj)?,
        None => DecodeBudget::default_budget(),
    };
    let target_ptr = target.as_ptr();
    let is_type = target.is_instance_of::<PyType>();
    let cls_ptr = if is_type {
        target_ptr.cast::<ffi::PyTypeObject>()
    } else {
        unsafe { ffi::Py_TYPE(target_ptr) }
    };
    let codec = lookup_or_resolve_dataclass_codec(py, cls_ptr)?;
    if HAS_GIL
        && is_type
        && max_elements.is_none()
        && !zero_copy_bytes
        && unsafe { ffi::PyBytes_CheckExact(packet.as_ptr()) != 0 }
        && let Some(inner) = codec.get().inner.get()
        && inner.fast_slot_decode
    {
        let slice = unsafe {
            let obj_ptr = packet.as_ptr();
            let len = ffi::PyBytes_Size(obj_ptr) as usize;
            if len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ffi::PyBytes_AS_STRING(obj_ptr).cast::<u8>(), len)
            }
        };
        return unsafe {
            codec
                .get()
                .try_decode_pure_fast_slots_dispatch(py, inner, slice, 0, &mut budget)
        };
    }
    let out_inst = if is_type { None } else { Some(target) };
    if zero_copy_bytes {
        let owner = ByteSliceOwner::from_py_any(py, packet)?;
        let slice = owner.as_slice(py);
        return codec.get().decode_slice_budget(
            py,
            slice,
            out_inst,
            0,
            false,
            &mut budget,
            Some((&owner, 0)),
        );
    }
    let input = InputBytes::extract(py, packet)?;
    codec
        .get()
        .decode_slice_budget(py, input.as_slice(), out_inst, 0, false, &mut budget, None)
}
