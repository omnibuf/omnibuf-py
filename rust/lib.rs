use std::sync::OnceLock;

use omnibuf_core::field0::{read_field0_schema_meta, validate_field0};
use omnibuf_core::wire::{
    MAX_FIELD_NUMBER, WIRE_SUB_MSG, decode_varint, skip_value, validate_message,
};
use pyo3::exceptions::PyValueError;
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PySequence, PyType};

mod blind;
mod codec;
mod opaque;

use blind::{decode_blind_json_py, decode_blind_py};
use codec::CompiledCodec;
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

/// Zero-copy view over `bytes`, `bytearray`, or any buffer-protocol object (`memoryview`).
pub(crate) struct BorrowedBytes<'py> {
    ptr: *const u8,
    len: usize,
    view: Option<ffi::Py_buffer>,
    _marker: std::marker::PhantomData<&'py [u8]>,
}

impl<'py> BorrowedBytes<'py> {
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
            if ffi::PyByteArray_CheckExact(obj_ptr) != 0 {
                let len = ffi::PyByteArray_Size(obj_ptr) as usize;
                let ptr = if len == 0 {
                    std::ptr::NonNull::<u8>::dangling().as_ptr()
                } else {
                    ffi::PyByteArray_AsString(obj_ptr).cast::<u8>()
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

impl Drop for BorrowedBytes<'_> {
    #[inline]
    fn drop(&mut self) {
        if let Some(ref mut view) = self.view {
            unsafe {
                ffi::PyBuffer_Release(view);
            }
        }
    }
}

#[pyfunction]
fn init_exceptions(encode_cls: Bound<'_, PyType>, decode_cls: Bound<'_, PyType>) {
    let _ = ENCODE_ERR_CLS.set(encode_cls.unbind());
    let _ = DECODE_ERR_CLS.set(decode_cls.unbind());
}

#[pyfunction]
fn validate_message_py(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<()> {
    let borrowed = BorrowedBytes::extract(py, data.as_ptr())?;
    validate_message(borrowed.as_slice(), 0).map_err(|e| decode_err(py, e.to_string()))
}

#[pyfunction]
fn has_field0_py(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<bool> {
    let borrowed = BorrowedBytes::extract(py, data.as_ptr())?;
    Ok(read_field0_schema_meta(borrowed.as_slice()).is_some())
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
        let p_bytes = BorrowedBytes::extract(py, prefix_obj.as_ptr())?;
        let s = p_bytes.as_slice();
        let mut v = Vec::with_capacity(s.len() + 256);
        v.extend_from_slice(s);
        v
    } else {
        Vec::new()
    };

    let seq = replacements.cast::<PySequence>()?;
    let rep_len = seq.len()?;
    let src_bytes = BorrowedBytes::extract(py, src_packet.as_ptr())?;
    let src = src_bytes.as_slice();

    if rep_len == 0 {
        validate_message(src, 0).map_err(|e| decode_err(py, e.to_string()))?;
        out.extend_from_slice(src);
        return Ok(PyBytes::new(py, &out));
    }

    let mut ordered_nums: Vec<u32> = Vec::with_capacity(rep_len);
    let mut rep_payloads: Vec<Vec<u8>> = Vec::with_capacity(rep_len);

    for i in 0..rep_len {
        let item = seq.get_item(i)?;
        let fnum_i64: i64 = item.getattr("field_num")?.extract()?;
        if fnum_i64 <= 0 || fnum_i64 > MAX_FIELD_NUMBER as i64 {
            return Err(encode_err(
                py,
                format!("omnibuf: invalid splice field number {fnum_i64}"),
            ));
        }
        let fnum = fnum_i64 as u32;
        let enc_attr = item.getattr("encoded_field")?;
        let enc_borrowed = BorrowedBytes::extract(py, enc_attr.as_ptr())?;
        let payload = enc_borrowed.as_slice().to_vec();

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
            skip_value(src, pos, wt).map_err(|e| decode_err(py, e.to_string()))?
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
    m.add_function(wrap_pyfunction!(splice_fields_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_blind_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_blind_json_py, m)?)?;
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
