use std::collections::BTreeMap;

use omnibuf_core::blind::{BlindValue, decode_blind, encode_base64, stringify_blind_json};
use pyo3::exceptions::PyValueError;
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyString};

use crate::{BorrowedBytes, decode_err};

#[inline]
fn round_f32_shortest_to_f64(f: f32) -> f64 {
    if !f.is_finite() || f == 0.0 {
        return f64::from(f);
    }
    let mut rbuf = ryu::Buffer::new();
    rbuf.format_finite(f)
        .parse::<f64>()
        .unwrap_or_else(|_| f64::from(f))
}

fn blind_value_to_py<'py>(py: Python<'py>, val: &BlindValue) -> PyResult<Bound<'py, PyAny>> {
    match val {
        BlindValue::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
        BlindValue::Uint(u) => unsafe {
            let ptr = ffi::PyLong_FromUnsignedLongLong(*u);
            Bound::from_owned_ptr_or_err(py, ptr)
        },
        BlindValue::Int(i) => unsafe {
            let ptr = ffi::PyLong_FromLongLong(*i);
            Bound::from_owned_ptr_or_err(py, ptr)
        },
        BlindValue::Float32(f) => Ok(PyFloat::new(py, round_f32_shortest_to_f64(*f)).into_any()),
        BlindValue::Float64(f) => Ok(PyFloat::new(py, *f).into_any()),
        BlindValue::String(s) => Ok(PyString::new(py, s).into_any()),
        BlindValue::Bytes(b) => Ok(PyBytes::new(py, b).into_any()),
        BlindValue::Array(items) => unsafe {
            let list_ptr = ffi::PyList_New(items.len() as ffi::Py_ssize_t);
            let list = Bound::from_owned_ptr_or_err(py, list_ptr)?;
            for (idx, item) in items.iter().enumerate() {
                let py_item = blind_value_to_py(py, item)?;
                ffi::PyList_SET_ITEM(list.as_ptr(), idx as ffi::Py_ssize_t, py_item.into_ptr());
            }
            Ok(list)
        },
        BlindValue::Object(map) => blind_map_to_py_dict(py, map).map(Bound::into_any),
    }
}

fn blind_map_to_py_dict<'py>(
    py: Python<'py>,
    map: &BTreeMap<String, BlindValue>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in map {
        let py_k = PyString::new(py, k);
        let py_v = blind_value_to_py(py, v)?;
        unsafe {
            if ffi::PyDict_SetItem(dict.as_ptr(), py_k.as_ptr(), py_v.as_ptr()) != 0 {
                return Err(PyErr::fetch(py));
            }
        }
    }
    Ok(dict)
}

fn map_has_non_finite(map: &BTreeMap<String, BlindValue>) -> bool {
    map.values().any(val_has_non_finite)
}

fn val_has_non_finite(val: &BlindValue) -> bool {
    match val {
        BlindValue::Float32(f) => !f.is_finite(),
        BlindValue::Float64(f) => !f.is_finite(),
        BlindValue::Array(items) => items.iter().any(val_has_non_finite),
        BlindValue::Object(obj) => map_has_non_finite(obj),
        _ => false,
    }
}

fn write_escaped_json_str(dst: &mut String, s: &str) {
    dst.push('"');
    for ch in s.chars() {
        match ch {
            '"' => dst.push_str("\\\""),
            '\\' => dst.push_str("\\\\"),
            '\x08' => dst.push_str("\\b"),
            '\x0c' => dst.push_str("\\f"),
            '\n' => dst.push_str("\\n"),
            '\r' => dst.push_str("\\r"),
            '\t' => dst.push_str("\\t"),
            c if (c as u32) < 0x20 => dst.push_str(&format!("\\u{:04x}", c as u32)),
            c => dst.push(c),
        }
    }
    dst.push('"');
}

fn format_allow_nan_object(
    dst: &mut String,
    map: &BTreeMap<String, BlindValue>,
    step: &str,
    cur_indent: &str,
) {
    if map.is_empty() {
        dst.push_str("{}");
        return;
    }
    if step.is_empty() {
        dst.push('{');
        for (i, (k, v)) in map.iter().enumerate() {
            if i > 0 {
                dst.push(',');
            }
            write_escaped_json_str(dst, k);
            dst.push(':');
            format_allow_nan_val(dst, v, step, "");
        }
        dst.push('}');
    } else {
        let next_indent = format!("{cur_indent}{step}");
        dst.push_str("{\n");
        for (i, (k, v)) in map.iter().enumerate() {
            if i > 0 {
                dst.push_str(",\n");
            }
            dst.push_str(&next_indent);
            write_escaped_json_str(dst, k);
            dst.push_str(": ");
            format_allow_nan_val(dst, v, step, &next_indent);
        }
        dst.push('\n');
        dst.push_str(cur_indent);
        dst.push('}');
    }
}

fn format_allow_nan_val(dst: &mut String, val: &BlindValue, step: &str, cur_indent: &str) {
    match val {
        BlindValue::Bool(b) => dst.push_str(if *b { "true" } else { "false" }),
        BlindValue::Uint(u) => {
            let mut b = itoa::Buffer::new();
            dst.push_str(b.format(*u));
        }
        BlindValue::Int(i) => {
            let mut b = itoa::Buffer::new();
            dst.push_str(b.format(*i));
        }
        BlindValue::Float32(f) => {
            if f.is_nan() {
                dst.push_str("NaN");
            } else if f.is_infinite() {
                dst.push_str(if f.is_sign_positive() {
                    "Infinity"
                } else {
                    "-Infinity"
                });
            } else {
                let mut b = ryu::Buffer::new();
                let s = b.format_finite(*f);
                dst.push_str(s.strip_suffix(".0").unwrap_or(s));
            }
        }
        BlindValue::Float64(f) => {
            if f.is_nan() {
                dst.push_str("NaN");
            } else if f.is_infinite() {
                dst.push_str(if f.is_sign_positive() {
                    "Infinity"
                } else {
                    "-Infinity"
                });
            } else {
                let mut b = ryu::Buffer::new();
                let s = b.format_finite(*f);
                dst.push_str(s.strip_suffix(".0").unwrap_or(s));
            }
        }
        BlindValue::String(s) => write_escaped_json_str(dst, s),
        BlindValue::Bytes(b) => {
            let b64 = encode_base64(b);
            write_escaped_json_str(dst, &b64);
        }
        BlindValue::Array(items) => {
            if items.is_empty() {
                dst.push_str("[]");
                return;
            }
            if step.is_empty() {
                dst.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        dst.push(',');
                    }
                    format_allow_nan_val(dst, item, step, "");
                }
                dst.push(']');
            } else {
                let next_indent = format!("{cur_indent}{step}");
                dst.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        dst.push_str(",\n");
                    }
                    dst.push_str(&next_indent);
                    format_allow_nan_val(dst, item, step, &next_indent);
                }
                dst.push('\n');
                dst.push_str(cur_indent);
                dst.push(']');
            }
        }
        BlindValue::Object(m) => format_allow_nan_object(dst, m, step, cur_indent),
    }
}

#[pyfunction]
pub fn decode_blind_py<'py>(
    py: Python<'py>,
    packet: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let borrowed = BorrowedBytes::extract(py, packet.as_ptr())?;
    let map = decode_blind(borrowed.as_slice()).map_err(|e| decode_err(py, e.to_string()))?;
    blind_map_to_py_dict(py, &map)
}

#[pyfunction]
#[pyo3(signature = (packet, *, allow_nan=false, indent=None))]
pub fn decode_blind_json_py(
    py: Python<'_>,
    packet: &Bound<'_, PyAny>,
    allow_nan: bool,
    indent: Option<usize>,
) -> PyResult<String> {
    let borrowed = BorrowedBytes::extract(py, packet.as_ptr())?;
    let map = decode_blind(borrowed.as_slice()).map_err(|e| decode_err(py, e.to_string()))?;
    if map_has_non_finite(&map) {
        if !allow_nan {
            return Err(PyValueError::new_err(
                "Out of range float values are not JSON compliant",
            ));
        }
        let step = match indent {
            Some(n) if n > 0 => " ".repeat(n.min(10)),
            _ => String::new(),
        };
        let mut dst = String::with_capacity(map.len() * 24 + 2);
        format_allow_nan_object(&mut dst, &map, &step, "");
        return Ok(dst);
    }
    Ok(stringify_blind_json(&map, indent, false))
}
