use std::cell::RefCell;
use std::sync::OnceLock;

use omnibuf_core::wire::{
    Decoder, Encoder, MAX_NESTING_DEPTH, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_SUB_MSG, append_tag,
    append_varint, backpatch_container_len, decode_varint, decode_zigzag, encode_zigzag,
    parse_array_header, parse_map_header, read_len_slice, read_str_slice, validate_utf8,
};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyBytes, PyDict, PyFloat, PyList, PySequence, PyString, PyTuple, PyType,
};

use crate::{BorrowedBytes, decode_err, encode_err};

thread_local! {
    static TLS_ENCODER: RefCell<Encoder> = RefCell::new(Encoder::new(1024));
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

struct SlotBinding {
    descr: Py<PyAny>,
    get_fn: ffi::descrgetfunc,
    set_fn: ffi::descrsetfunc,
    cls_ptr: *mut ffi::PyObject,
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
                    let ptr = (sb.get_fn)(sb.descr.as_ptr(), obj_ptr, sb.cls_ptr);
                    if ptr.is_null() {
                        ffi::PyErr_Clear();
                        return Ok(None);
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
                        ffi::PyErr_Clear();
                        return Ok(None);
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
    wire_type: u8,
    tag_bytes: [u8; 5],
    tag_len: u8,
    tag_false: [u8; 5],
    tag_false_len: u8,
    tag_true: [u8; 5],
    tag_true_len: u8,
    skip_if_none: bool,
    pbpy_presence: bool,
    omitempty: bool,
    kind: FieldPlanKind,
    default_plan: DefaultPlan,
}

impl FieldPlan {
    #[inline]
    fn write_tag_to(&self, dst: &mut Vec<u8>) {
        if self.tag_len == 1 {
            dst.push(self.tag_bytes[0]);
        } else {
            dst.extend_from_slice(&self.tag_bytes[..usize::from(self.tag_len)]);
        }
    }

    #[inline]
    fn write_bool_tag_to(&self, dst: &mut Vec<u8>, is_true: bool) {
        if is_true {
            if self.tag_true_len == 1 {
                dst.push(self.tag_true[0]);
            } else {
                dst.extend_from_slice(&self.tag_true[..usize::from(self.tag_true_len)]);
            }
        } else if self.tag_false_len == 1 {
            dst.push(self.tag_false[0]);
        } else {
            dst.extend_from_slice(&self.tag_false[..usize::from(self.tag_false_len)]);
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

struct CodecInner {
    fields: Vec<FieldPlan>,
    dense_by_num: Vec<u16>,
    field0_wire: Vec<u8>,
    fast_alloc: bool,
    all_seen_mask_64: u64,
    has_field_intern: Py<PyString>,
    clear_field_intern: Py<PyString>,
}

#[pyclass(frozen)]
pub struct CompiledCodec {
    cls: Py<PyType>,
    type_name: String,
    req_fast_alloc: bool,
    pbpy_mode: bool,
    inner: OnceLock<CodecInner>,
}

fn encode_tag_inline(fnum: u32, wt: u8) -> ([u8; 5], u8) {
    let mut v = Vec::with_capacity(5);
    append_tag(&mut v, fnum, wt);
    let mut arr = [0u8; 5];
    let len = v.len();
    arr[..len].copy_from_slice(&v);
    (arr, len as u8)
}

#[inline]
pub(crate) fn extract_i64(
    py: Python<'_>,
    ptr: *mut ffi::PyObject,
    field_name: &str,
) -> PyResult<i64> {
    unsafe {
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
        let rc = ffi::PyObject_IsTrue(ptr);
        if rc < 0 {
            Err(PyErr::fetch(py))
        } else {
            Ok(rc != 0)
        }
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
            if !(0..=i64::from(u32::MAX)).contains(&v) {
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
        ScalarKind::Sint32 | ScalarKind::Enum => {
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
            let len = size as usize;
            append_varint(dst, len as u64);
            if len > 0 {
                let bytes = std::slice::from_raw_parts(utf8_ptr.cast::<u8>(), len);
                dst.extend_from_slice(bytes);
            }
        },
        ScalarKind::Bytes => {
            let borrowed = BorrowedBytes::extract(py, ptr)?;
            let slice = borrowed.as_slice();
            append_varint(dst, slice.len() as u64);
            dst.extend_from_slice(slice);
        }
        ScalarKind::BytesAsStr => {
            let borrowed = BorrowedBytes::extract(py, ptr)?;
            let slice = borrowed.as_slice();
            validate_utf8(slice).map_err(|e| decode_err(py, e.to_string()))?;
            append_varint(dst, slice.len() as u64);
            dst.extend_from_slice(slice);
        }
    }
    Ok(())
}

#[inline]
pub fn read_scalar_payload<'py>(
    py: Python<'py>,
    data: &[u8],
    pos: usize,
    kind: ScalarKind,
    enum_cls: Option<&Py<PyAny>>,
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
                let wrapped = e_cls.bind(py).call1((obj,))?;
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
            Ok((PyBytes::new(py, b).into_any(), next_pos))
        }
        ScalarKind::BytesAsStr => {
            let (b, next_pos) =
                read_len_slice(data, pos, 0).map_err(|e| decode_err(py, e.to_string()))?;
            validate_utf8(b).map_err(|e| decode_err(py, e.to_string()))?;
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
        ScalarKind::Sint32
        | ScalarKind::Sfixed32
        | ScalarKind::Sint64
        | ScalarKind::Sfixed64
        | ScalarKind::Enum => Ok(SortableMapKey::Sint(extract_i64(py, ptr, field_name)?)),
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

    #[inline]
    fn alloc_raw_slot_instance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
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
    ) -> PyResult<bool> {
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
                | ScalarKind::Enum
                | ScalarKind::Fixed32
                | ScalarKind::Sfixed32
                | ScalarKind::Sfixed64 => Ok(extract_i64(py, ptr, &fp.wire_name)? == 0),
                ScalarKind::Uint64 | ScalarKind::Fixed64 => {
                    Ok(extract_u64(py, ptr, &fp.wire_name)? == 0)
                }
                ScalarKind::Float32 | ScalarKind::Float64 => {
                    Ok(extract_f64(py, ptr, &fp.wire_name)? == 0.0)
                }
                ScalarKind::String
                | ScalarKind::StrAsBytes
                | ScalarKind::Bytes
                | ScalarKind::BytesAsStr => Ok(val.len()? == 0),
            },
            FieldPlanKind::ArrayScalar { .. }
            | FieldPlanKind::ArraySubMsg { .. }
            | FieldPlanKind::Map { .. } => Ok(val.len()? == 0),
            FieldPlanKind::SubMsg { codec } => {
                let sub = codec.get();
                let sub_inner = sub.inner_plan(py)?;
                for sub_fp in &sub_inner.fields {
                    let child_val = sub_fp.access.get(py, ptr)?;
                    if !sub.is_value_empty(py, sub_fp, &child_val)? {
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
        if val.is_none() && (fp.skip_if_none || matches!(fp.kind, FieldPlanKind::SubMsg { .. })) {
            return Ok(());
        }
        self.encode_field_value(py, enc, fp, val, deterministic)
    }

    #[inline]
    fn encode_field_value(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        fp: &FieldPlan,
        val: &Bound<'_, PyAny>,
        deterministic: bool,
    ) -> PyResult<()> {
        let ptr = val.as_ptr();
        match &fp.kind {
            FieldPlanKind::Scalar {
                kind: ScalarKind::Bool,
                ..
            } => {
                let b = extract_bool(py, ptr)?;
                fp.write_bool_tag_to(enc.buf_mut(), b);
                Ok(())
            }
            FieldPlanKind::Scalar { kind, .. } => {
                fp.write_tag_to(enc.buf_mut());
                write_scalar_payload(py, enc.buf_mut(), *kind, ptr, &fp.wire_name)
            }
            FieldPlanKind::SubMsg { codec } => {
                fp.write_tag_to(enc.buf_mut());
                enc.begin_container();
                if !val.is_none() {
                    codec.get().encode_msg_into(py, enc, ptr, deterministic)?;
                }
                enc.end_container();
                Ok(())
            }
            FieldPlanKind::ArrayScalar {
                elem_kind, elem_wt, ..
            } => {
                fp.write_tag_to(enc.buf_mut());
                let buf = enc.buf_mut();
                let len_pos = buf.len();
                buf.extend_from_slice(&[0, 0, *elem_wt]);
                unsafe {
                    if ffi::PyList_CheckExact(ptr) != 0 {
                        let n = ffi::PyList_GET_SIZE(ptr) as usize;
                        append_varint(buf, n as u64);
                        for i in 0..n {
                            let item_ptr = ffi::PyList_GET_ITEM(ptr, i as ffi::Py_ssize_t);
                            write_scalar_payload(py, buf, *elem_kind, item_ptr, &fp.wire_name)?;
                        }
                    } else {
                        let seq = val.cast::<PySequence>()?;
                        let n = seq.len()?;
                        append_varint(buf, n as u64);
                        for i in 0..n {
                            let item = seq.get_item(i)?;
                            write_scalar_payload(
                                py,
                                buf,
                                *elem_kind,
                                item.as_ptr(),
                                &fp.wire_name,
                            )?;
                        }
                    }
                }
                backpatch_container_len(enc.buf_mut(), len_pos);
                Ok(())
            }
            FieldPlanKind::ArraySubMsg { codec } => {
                fp.write_tag_to(enc.buf_mut());
                let sub = codec.get();
                let len_pos = enc.buf_mut().len();
                enc.buf_mut().extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
                unsafe {
                    if ffi::PyList_CheckExact(ptr) != 0 {
                        let n = ffi::PyList_GET_SIZE(ptr) as usize;
                        append_varint(enc.buf_mut(), n as u64);
                        for i in 0..n {
                            let item_ptr = ffi::PyList_GET_ITEM(ptr, i as ffi::Py_ssize_t);
                            enc.begin_container();
                            if item_ptr != ffi::Py_None() {
                                sub.encode_msg_into(py, enc, item_ptr, deterministic)?;
                            }
                            enc.end_container();
                        }
                    } else {
                        let seq = val.cast::<PySequence>()?;
                        let n = seq.len()?;
                        append_varint(enc.buf_mut(), n as u64);
                        for i in 0..n {
                            let item = seq.get_item(i)?;
                            enc.begin_container();
                            if !item.is_none() {
                                sub.encode_msg_into(py, enc, item.as_ptr(), deterministic)?;
                            }
                            enc.end_container();
                        }
                    }
                }
                backpatch_container_len(enc.buf_mut(), len_pos);
                Ok(())
            }
            FieldPlanKind::Map {
                key_kind,
                key_wt,
                val_wt,
                val_plan,
            } => {
                fp.write_tag_to(enc.buf_mut());
                let len_pos = enc.buf_mut().len();
                enc.buf_mut().extend_from_slice(&[0, 0, *key_wt, *val_wt]);
                unsafe {
                    if ffi::PyDict_CheckExact(ptr) != 0 {
                        let count = ffi::PyDict_Size(ptr) as usize;
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
                            while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0 {
                                let sk = extract_sortable_key(py, *key_kind, k_ptr, &fp.wire_name)?;
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
                                match val_plan {
                                    MapValPlan::Scalar { kind: vk, .. } => {
                                        write_scalar_payload(
                                            py,
                                            enc.buf_mut(),
                                            *vk,
                                            vp,
                                            &fp.wire_name,
                                        )?;
                                    }
                                    MapValPlan::SubMsg(sub_c) => {
                                        enc.begin_container();
                                        if vp != ffi::Py_None() {
                                            sub_c.get().encode_msg_into(
                                                py,
                                                enc,
                                                vp,
                                                deterministic,
                                            )?;
                                        }
                                        enc.end_container();
                                    }
                                }
                            }
                        } else {
                            let mut ppos: ffi::Py_ssize_t = 0;
                            let mut k_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                            let mut v_ptr: *mut ffi::PyObject = std::ptr::null_mut();
                            while ffi::PyDict_Next(ptr, &mut ppos, &mut k_ptr, &mut v_ptr) != 0 {
                                write_scalar_payload(
                                    py,
                                    enc.buf_mut(),
                                    *key_kind,
                                    k_ptr,
                                    &fp.wire_name,
                                )?;
                                match val_plan {
                                    MapValPlan::Scalar { kind: vk, .. } => {
                                        write_scalar_payload(
                                            py,
                                            enc.buf_mut(),
                                            *vk,
                                            v_ptr,
                                            &fp.wire_name,
                                        )?;
                                    }
                                    MapValPlan::SubMsg(sub_c) => {
                                        enc.begin_container();
                                        if v_ptr != ffi::Py_None() {
                                            sub_c.get().encode_msg_into(
                                                py,
                                                enc,
                                                v_ptr,
                                                deterministic,
                                            )?;
                                        }
                                        enc.end_container();
                                    }
                                }
                            }
                        }
                    } else {
                        let count = val.len()?;
                        append_varint(enc.buf_mut(), count as u64);
                        let keys_obj = val.call_method0("keys")?;
                        let keys_list: Bound<'_, PyList> = PyList::empty(py);
                        for k_res in keys_obj.try_iter()? {
                            keys_list.append(k_res?)?;
                        }
                        let n_keys = keys_list.len();
                        let mut entries: Vec<(SortableMapKey, Bound<'_, PyAny>, Bound<'_, PyAny>)> =
                            Vec::with_capacity(n_keys);
                        for i in 0..n_keys {
                            let k = keys_list.get_item(i)?;
                            let v = val.get_item(&k)?;
                            let sk = if deterministic && n_keys > 1 {
                                extract_sortable_key(py, *key_kind, k.as_ptr(), &fp.wire_name)?
                            } else {
                                SortableMapKey::Bool(false)
                            };
                            entries.push((sk, k, v));
                        }
                        if deterministic && entries.len() > 1 {
                            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                        }
                        for (_, k, v) in entries {
                            write_scalar_payload(
                                py,
                                enc.buf_mut(),
                                *key_kind,
                                k.as_ptr(),
                                &fp.wire_name,
                            )?;
                            match val_plan {
                                MapValPlan::Scalar { kind: vk, .. } => {
                                    write_scalar_payload(
                                        py,
                                        enc.buf_mut(),
                                        *vk,
                                        v.as_ptr(),
                                        &fp.wire_name,
                                    )?;
                                }
                                MapValPlan::SubMsg(sub_c) => {
                                    enc.begin_container();
                                    if !v.is_none() {
                                        sub_c.get().encode_msg_into(
                                            py,
                                            enc,
                                            v.as_ptr(),
                                            deterministic,
                                        )?;
                                    }
                                    enc.end_container();
                                }
                            }
                        }
                    }
                }
                backpatch_container_len(enc.buf_mut(), len_pos);
                Ok(())
            }
        }
    }

    pub(crate) fn encode_msg_into(
        &self,
        py: Python<'_>,
        enc: &mut Encoder,
        obj_ptr: *mut ffi::PyObject,
        deterministic: bool,
    ) -> PyResult<()> {
        let inner = self.inner_plan(py)?;
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
                raw_val
            };

            if fp.omitempty && self.is_value_empty(py, fp, &val)? {
                continue;
            }

            self.encode_field_value(py, enc, fp, &val, deterministic)?;
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
        if depth > MAX_NESTING_DEPTH {
            return Err(decode_err(
                py,
                format!("omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}"),
            ));
        }
        let inner = self.inner_plan(py)?;

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

        while let Some((fnum, wt)) = dec.next_tag().map_err(|e| decode_err(py, e.to_string()))? {
            if fnum == 0 {
                if wt != WIRE_SUB_MSG {
                    return Err(decode_err(
                        py,
                        format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                    ));
                }
                dec.skip_field0()
                    .map_err(|e| decode_err(py, e.to_string()))?;
                continue;
            }

            let Some(f_idx) = lookup_field_index(inner, fnum) else {
                dec.skip_unknown(fnum, wt)
                    .map_err(|e| decode_err(py, e.to_string()))?;
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
                dec.skip_unknown(fnum, wt)
                    .map_err(|e| decode_err(py, e.to_string()))?;
                continue;
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

            match &fp.kind {
                FieldPlanKind::Scalar {
                    kind: ScalarKind::Bool,
                    ..
                } => {
                    let b_obj = PyBool::new(py, wt == WIRE_BOOL_TRUE);
                    fp.access.set(py, dst_ptr, b_obj.as_ptr())?;
                }
                FieldPlanKind::Scalar { kind, enum_cls } => {
                    let (val_obj, next_pos) =
                        read_scalar_payload(py, data, dec.position(), *kind, enum_cls.as_ref())?;
                    dec.set_position(next_pos);
                    fp.access.set(py, dst_ptr, val_obj.as_ptr())?;
                }
                FieldPlanKind::SubMsg { codec } => {
                    let sub_slice = dec
                        .read_container(0)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let cur_sub = if is_fresh_raw && !already_seen {
                        None
                    } else {
                        fp.access.get_optional(py, dst_ptr)?
                    };
                    let decoded_sub = codec.get().decode_slice(
                        py,
                        sub_slice,
                        cur_sub.as_ref(),
                        depth + 1,
                        already_seen,
                    )?;
                    if cur_sub.is_none() {
                        fp.access.set(py, dst_ptr, decoded_sub.as_ptr())?;
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

                    if self.pbpy_mode {
                        let target_list = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_list.len()? > 0 {
                            target_list.call_method0("clear")?;
                        }
                        for _ in 0..count {
                            let (item, next_p) = read_scalar_payload(
                                py,
                                arr_body,
                                p,
                                *elem_kind,
                                enum_cls.as_ref(),
                            )?;
                            p = next_p;
                            target_list.call_method1("append", (item,))?;
                        }
                    } else if !already_seen {
                        unsafe {
                            let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                            let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                            for i in 0..count {
                                let (item, next_p) = read_scalar_payload(
                                    py,
                                    arr_body,
                                    p,
                                    *elem_kind,
                                    enum_cls.as_ref(),
                                )?;
                                p = next_p;
                                ffi::PyList_SET_ITEM(
                                    list.as_ptr(),
                                    i as ffi::Py_ssize_t,
                                    item.into_ptr(),
                                );
                            }
                            fp.access.set(py, dst_ptr, list.as_ptr())?;
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
                        for _ in 0..count {
                            let (item, next_p) = read_scalar_payload(
                                py,
                                arr_body,
                                p,
                                *elem_kind,
                                enum_cls.as_ref(),
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
                    let sub_c = codec.get();

                    if self.pbpy_mode {
                        let target_list = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_list.len()? > 0 {
                            target_list.call_method0("clear")?;
                        }
                        for _ in 0..count {
                            let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                .map_err(|e| decode_err(py, e.to_string()))?;
                            p = next_p;
                            let elem_obj =
                                sub_c.decode_slice(py, elem_slice, None, depth + 2, false)?;
                            target_list.call_method1("append", (elem_obj,))?;
                        }
                    } else if !already_seen {
                        unsafe {
                            let list_ptr = ffi::PyList_New(count as ffi::Py_ssize_t);
                            let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
                            for i in 0..count {
                                let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                    .map_err(|e| decode_err(py, e.to_string()))?;
                                p = next_p;
                                let elem_obj =
                                    sub_c.decode_slice(py, elem_slice, None, depth + 2, false)?;
                                ffi::PyList_SET_ITEM(
                                    list.as_ptr(),
                                    i as ffi::Py_ssize_t,
                                    elem_obj.into_ptr(),
                                );
                            }
                            fp.access.set(py, dst_ptr, list.as_ptr())?;
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
                        for _ in 0..count {
                            let (elem_slice, next_p) = read_len_slice(arr_body, p, 0)
                                .map_err(|e| decode_err(py, e.to_string()))?;
                            p = next_p;
                            let elem_obj =
                                sub_c.decode_slice(py, elem_slice, None, depth + 2, false)?;
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

                    if self.pbpy_mode {
                        let target_map = fp.access.get(py, dst_ptr)?;
                        if !already_seen && target_map.len()? > 0 {
                            target_map.call_method0("clear")?;
                        }
                        for _ in 0..count {
                            let (k_obj, after_k) =
                                read_scalar_payload(py, map_body, p, *key_kind, None)?;
                            let (v_obj, after_v) = match val_plan {
                                MapValPlan::Scalar {
                                    kind: vk,
                                    enum_cls: ve,
                                } => read_scalar_payload(py, map_body, after_k, *vk, ve.as_ref())?,
                                MapValPlan::SubMsg(sub_c) => {
                                    let (v_slice, vp) = read_len_slice(map_body, after_k, 0)
                                        .map_err(|e| decode_err(py, e.to_string()))?;
                                    let msg_v = sub_c.get().decode_slice(
                                        py,
                                        v_slice,
                                        None,
                                        depth + 2,
                                        false,
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
                        for _ in 0..count {
                            let (k_obj, after_k) =
                                read_scalar_payload(py, map_body, p, *key_kind, None)?;
                            let (v_obj, after_v) = match val_plan {
                                MapValPlan::Scalar {
                                    kind: vk,
                                    enum_cls: ve,
                                } => read_scalar_payload(py, map_body, after_k, *vk, ve.as_ref())?,
                                MapValPlan::SubMsg(sub_c) => {
                                    let (v_slice, vp) = read_len_slice(map_body, after_k, 0)
                                        .map_err(|e| decode_err(py, e.to_string()))?;
                                    let msg_v = sub_c.get().decode_slice(
                                        py,
                                        v_slice,
                                        None,
                                        depth + 2,
                                        false,
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
                            fp.access.set(py, dst_ptr, def_val.as_ptr())?;
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
                        fp.access.set(py, dst_ptr, def_val.as_ptr())?;
                    }
                }
            }
        }

        Ok(inst)
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

            let attr_intern = PyString::intern(py, &attr).unbind();

            let access = if !self.pbpy_mode
                && let Ok(descr_obj) = cls_dict.get_item(&attr)
            {
                unsafe {
                    let descr_type = ffi::Py_TYPE(descr_obj.as_ptr());
                    if descr_type == std::ptr::addr_of_mut!(ffi::PyMemberDescr_Type)
                        && let Some(get_fn) = (*descr_type).tp_descr_get
                        && let Some(set_fn) = (*descr_type).tp_descr_set
                    {
                        FieldAccess::Slot(SlotBinding {
                            descr: descr_obj.unbind(),
                            get_fn,
                            set_fn,
                            cls_ptr: self.cls.as_ptr(),
                        })
                    } else {
                        all_slots = false;
                        FieldAccess::Attr(attr_intern.clone_ref(py))
                    }
                }
            } else {
                all_slots = false;
                FieldAccess::Attr(attr_intern.clone_ref(py))
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
            let (tag_false, tag_false_len) = encode_tag_inline(field_num, WIRE_BOOL_FALSE);
            let (tag_true, tag_true_len) = encode_tag_inline(field_num, WIRE_BOOL_TRUE);

            fields.push(FieldPlan {
                index: i,
                field_num,
                attr_str: attr_intern,
                wire_name,
                access,
                wire_type,
                tag_bytes,
                tag_len,
                tag_false,
                tag_false_len,
                tag_true,
                tag_true_len,
                skip_if_none,
                pbpy_presence,
                omitempty,
                kind: plan_kind,
                default_plan,
            });
        }

        fields.sort_by_key(|f| f.field_num);
        for (idx, fp) in fields.iter_mut().enumerate() {
            fp.index = idx;
        }

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

        let _ = self.inner.set(CodecInner {
            fields,
            dense_by_num,
            field0_wire: field0_wire.as_bytes().to_vec(),
            fast_alloc: all_slots,
            all_seen_mask_64,
            has_field_intern: PyString::intern(py, "has_field").unbind(),
            clear_field_intern: PyString::intern(py, "clear_field").unbind(),
        });
        Ok(())
    }

    #[pyo3(signature = (msg, *, deterministic=false, self_describing=false))]
    pub fn marshal<'py>(
        &self,
        py: Python<'py>,
        msg: &Bound<'py, PyAny>,
        deterministic: bool,
        self_describing: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner_plan(py)?;
        TLS_ENCODER.with(|cell| {
            if let Ok(mut enc) = cell.try_borrow_mut() {
                enc.reset();
                if self_describing {
                    enc.write_raw(&inner.field0_wire);
                }
                self.encode_msg_into(py, &mut enc, msg.as_ptr(), deterministic)?;
                Ok(PyBytes::new(py, enc.as_bytes()))
            } else {
                let mut fallback = Encoder::new(256);
                if self_describing {
                    fallback.write_raw(&inner.field0_wire);
                }
                self.encode_msg_into(py, &mut fallback, msg.as_ptr(), deterministic)?;
                Ok(PyBytes::new(py, fallback.as_bytes()))
            }
        })
    }

    #[pyo3(signature = (data, out=None))]
    pub fn unmarshal<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
        out: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let borrowed = BorrowedBytes::extract(py, data.as_ptr())?;
        self.decode_slice(py, borrowed.as_slice(), out, 0, false)
    }

    #[pyo3(signature = (data, out=None, depth=0, merge=false))]
    pub fn decode_at<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
        out: Option<&Bound<'py, PyAny>>,
        depth: usize,
        merge: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let borrowed = BorrowedBytes::extract(py, data.as_ptr())?;
        self.decode_slice(py, borrowed.as_slice(), out, depth, merge)
    }
}
