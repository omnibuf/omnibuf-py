use std::sync::OnceLock;

use omnibuf_core::wire::{
    Encoder, MAX_FIELD_NUMBER, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES,
    WIRE_EXTENDED, WIRE_FIXED32, WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32,
    WIRE_SFIXED64, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint,
    decode_varint, decode_zigzag, encode_zigzag, fast_skip_value, parse_array_header,
    parse_map_header, read_len_slice, read_tag_at, skip_value, validate_utf8,
};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyList, PyString, PyTuple, PyType};

use crate::codec::{
    CompiledCodec, ScalarKind, extract_bool, extract_f64, extract_i64, extract_u64,
    read_scalar_payload,
};
use crate::{
    ByteSliceOwner, DecodeBudget, LeafBytes, create_readonly_memoryview_slice, decode_err,
    encode_err, read_field0_checked, validate_field0_slice, validate_message_slice,
};

#[derive(Clone, Copy)]
struct FieldDirEntry {
    fnum: u32,
    wt: u8,
    f_start: usize,
    val_start: usize,
    f_end: usize,
}

enum FastDirty {
    Cleared(u32),
    Bool(u32, bool),
    Uint(u32, u64),
    Sint(u32, i64, bool),
    Fixed32(u32, u32),
    Sfixed32(u32, i32),
    Fixed64(u32, u64),
    Sfixed64(u32, i64),
    Float32(u32, f32),
    Float64(u32, f64),
    Str(u32, String),
    Bytes(u32, Vec<u8>),
}

impl FastDirty {
    #[inline]
    fn field_num(&self) -> u32 {
        match self {
            Self::Cleared(f)
            | Self::Bool(f, _)
            | Self::Uint(f, _)
            | Self::Sint(f, _, _)
            | Self::Fixed32(f, _)
            | Self::Sfixed32(f, _)
            | Self::Fixed64(f, _)
            | Self::Sfixed64(f, _)
            | Self::Float32(f, _)
            | Self::Float64(f, _)
            | Self::Str(f, _)
            | Self::Bytes(f, _) => *f,
        }
    }

    fn to_py_obj<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match self {
            Self::Cleared(_) => Ok(py.None().into_bound(py)),
            Self::Bool(_, b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
            Self::Uint(_, u) | Self::Fixed64(_, u) => unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(*u))
            },
            Self::Fixed32(_, u) => unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u64::from(*u)))
            },
            Self::Sint(_, i, _) | Self::Sfixed64(_, i) => unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(*i))
            },
            Self::Sfixed32(_, i) => unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i64::from(*i)))
            },
            Self::Float32(_, f) => Ok(PyFloat::new(py, f64::from(*f)).into_any()),
            Self::Float64(_, f) => Ok(PyFloat::new(py, *f).into_any()),
            Self::Str(_, s) => Ok(PyString::new(py, s).into_any()),
            Self::Bytes(_, b) => Ok(PyBytes::new(py, b).into_any()),
        }
    }

    fn write_encoded(&self, dst: &mut Vec<u8>) {
        match self {
            Self::Cleared(_) => {}
            Self::Bool(fnum, b) => {
                append_tag(
                    dst,
                    *fnum,
                    if *b { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE },
                );
            }
            Self::Uint(fnum, u) => {
                append_tag(dst, *fnum, WIRE_UINT);
                append_varint(dst, *u);
            }
            Self::Sint(fnum, i, is_32) => {
                append_tag(dst, *fnum, WIRE_SINT);
                let zz = if *is_32 {
                    let v32 = *i as i32;
                    u64::from(((v32 << 1) ^ (v32 >> 31)) as u32)
                } else {
                    encode_zigzag(*i)
                };
                append_varint(dst, zz);
            }
            Self::Fixed32(fnum, u) => {
                append_tag(dst, *fnum, WIRE_FIXED32);
                dst.extend_from_slice(&u.to_le_bytes());
            }
            Self::Sfixed32(fnum, i) => {
                append_tag(dst, *fnum, WIRE_SFIXED32);
                dst.extend_from_slice(&i.to_le_bytes());
            }
            Self::Fixed64(fnum, u) => {
                append_tag(dst, *fnum, WIRE_FIXED64);
                dst.extend_from_slice(&u.to_le_bytes());
            }
            Self::Sfixed64(fnum, i) => {
                append_tag(dst, *fnum, WIRE_SFIXED64);
                dst.extend_from_slice(&i.to_le_bytes());
            }
            Self::Float32(fnum, f) => {
                append_tag(dst, *fnum, WIRE_FLOAT32);
                dst.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Self::Float64(fnum, f) => {
                append_tag(dst, *fnum, WIRE_FLOAT64);
                dst.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Self::Str(fnum, s) => {
                append_tag(dst, *fnum, WIRE_STRING);
                append_varint(dst, s.len() as u64);
                dst.extend_from_slice(s.as_bytes());
            }
            Self::Bytes(fnum, b) => {
                append_tag(dst, *fnum, WIRE_BYTES);
                append_varint(dst, b.len() as u64);
                dst.extend_from_slice(b);
            }
        }
    }
}

fn parse_sibling_specs(siblings: Option<&Bound<'_, PyTuple>>) -> PyResult<Vec<(u32, u16)>> {
    let Some(tup) = siblings else {
        return Ok(Vec::new());
    };
    let n = tup.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let pair = tup.get_item(i)?;
        let (sf, sm): (u32, u16) = pair.extract()?;
        out.push((sf, sm));
    }
    Ok(out)
}

#[inline]
fn skip_checked_wire_field(
    py: Python<'_>,
    packet: &[u8],
    pos: usize,
    fnum: u32,
    wt: u8,
) -> PyResult<usize> {
    if fnum == 0 {
        if wt != WIRE_SUB_MSG {
            return Err(decode_err(
                py,
                format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
            ));
        }
        return validate_field0_slice(packet, pos, 0).map_err(|m| decode_err(py, m));
    }
    match wt {
        WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED => {
            skip_value(packet, pos, wt).map_err(|e| decode_err(py, e.to_string()))
        }
        _ => fast_skip_value(packet, pos, wt).ok_or_else(|| {
            decode_err(
                py,
                format!("omnibuf: truncated or invalid wire type {wt} at byte {pos}"),
            )
        }),
    }
}

/// Scans cached top-level directory entries for the last matching occurrence of `target_field`
/// (clearing if any `siblings` member appears afterward on the wire).
#[inline]
fn locate_in_dir(
    entries: &[FieldDirEntry],
    target_field: u32,
    exp_mask: u16,
    siblings: &[(u32, u16)],
) -> Option<(usize, u8)> {
    let mut found: Option<(usize, u8)> = None;
    let has_sibs = !siblings.is_empty();
    for entry in entries {
        if entry.fnum == target_field && (exp_mask & (1u16 << entry.wt)) != 0 {
            found = Some((entry.val_start, entry.wt));
        } else if has_sibs
            && siblings
                .iter()
                .any(|&(sf, sm)| sf == entry.fnum && (sm & (1u16 << entry.wt)) != 0)
        {
            found = None;
        }
    }
    found
}

#[inline]
fn locate_field_u32(
    packet: &[u8],
    target_field: u32,
    exp_mask: u16,
) -> Result<Option<(&[u8], u8)>, String> {
    let mut pos = 0usize;
    let n = packet.len();
    let mut found: Option<(&[u8], u8)> = None;
    while pos < n {
        let (fnum, wt, next_pos) = read_tag_at(packet, pos)
            .ok_or_else(|| format!("omnibuf: invalid or truncated tag at byte {pos}"))?;
        pos = next_pos;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(format!(
                    "omnibuf: Field #0 requires WireSubMsg (12), got {wt}"
                ));
            }
            pos = validate_field0_slice(packet, pos, 0)?;
            continue;
        }
        if fnum == target_field && (exp_mask & (1u16 << wt)) != 0 {
            found = Some((&packet[pos..], wt));
        }
        pos = match wt {
            WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED => {
                skip_value(packet, pos, wt).map_err(|e| e.to_string())?
            }
            _ => fast_skip_value(packet, pos, wt).ok_or_else(|| {
                format!("omnibuf: truncated or invalid wire type {wt} at byte {pos}")
            })?,
        };
    }
    Ok(found)
}

#[inline]
fn next_container_u32(
    packet: &[u8],
    mut pos: usize,
    target_field: u32,
    exp_wt: u8,
    min_len: usize,
) -> Result<Option<(usize, usize, usize)>, String> {
    let n = packet.len();
    while pos < n {
        let (fnum, wt, after_tag) = read_tag_at(packet, pos)
            .ok_or_else(|| format!("omnibuf: invalid or truncated tag at byte {pos}"))?;
        pos = after_tag;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(format!(
                    "omnibuf: Field #0 requires WireSubMsg (12), got {wt}"
                ));
            }
            pos = validate_field0_slice(packet, pos, 0)?;
            continue;
        }
        if fnum == target_field && wt == exp_wt {
            let (body, end) = read_len_slice(packet, pos, min_len).map_err(|e| e.to_string())?;
            let start = end - body.len();
            return Ok(Some((start, end, end)));
        }
        pos = if matches!(wt, WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED) {
            skip_value(packet, pos, wt).map_err(|e| e.to_string())?
        } else {
            fast_skip_value(packet, pos, wt).ok_or_else(|| {
                format!("omnibuf: truncated or invalid wire type {wt} at byte {pos}")
            })?
        };
    }
    Ok(None)
}

#[inline]
fn checked_read_uint(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<u64>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_UINT, siblings) else {
        return Ok(None);
    };
    let (v, _) = decode_varint(&slice[val_start..])
        .ok_or_else(|| decode_err(py, "omnibuf: invalid uint varint"))?;
    Ok(Some(v))
}

#[inline]
fn checked_read_sint(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<i64>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_SINT, siblings) else {
        return Ok(None);
    };
    let (v, _) = decode_varint(&slice[val_start..])
        .ok_or_else(|| decode_err(py, "omnibuf: invalid sint varint"))?;
    Ok(Some(decode_zigzag(v)))
}

#[inline]
fn checked_read_bool(
    entries: &[FieldDirEntry],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> Option<bool> {
    let mask = (1u16 << WIRE_BOOL_FALSE) | (1u16 << WIRE_BOOL_TRUE);
    let (_, wt) = locate_in_dir(entries, fnum, mask, siblings)?;
    Some(wt == WIRE_BOOL_TRUE)
}

#[inline]
fn checked_read_fixed32(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<u32>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_FIXED32, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 4] = slice
        .get(val_start..val_start + 4)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated fixed32"))?
        .try_into()
        .unwrap();
    Ok(Some(u32::from_le_bytes(raw)))
}

#[inline]
fn checked_read_sfixed32(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<i32>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_SFIXED32, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 4] = slice
        .get(val_start..val_start + 4)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated sfixed32"))?
        .try_into()
        .unwrap();
    Ok(Some(i32::from_le_bytes(raw)))
}

#[inline]
fn checked_read_fixed64(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<u64>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_FIXED64, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 8] = slice
        .get(val_start..val_start + 8)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated fixed64"))?
        .try_into()
        .unwrap();
    Ok(Some(u64::from_le_bytes(raw)))
}

#[inline]
fn checked_read_sfixed64(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<i64>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_SFIXED64, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 8] = slice
        .get(val_start..val_start + 8)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated sfixed64"))?
        .try_into()
        .unwrap();
    Ok(Some(i64::from_le_bytes(raw)))
}

#[inline]
fn checked_read_float32(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<f32>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_FLOAT32, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 4] = slice
        .get(val_start..val_start + 4)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated float32"))?
        .try_into()
        .unwrap();
    Ok(Some(f32::from_bits(u32::from_le_bytes(raw))))
}

#[inline]
fn checked_read_float64(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<f64>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_FLOAT64, siblings) else {
        return Ok(None);
    };
    let raw: [u8; 8] = slice
        .get(val_start..val_start + 8)
        .ok_or_else(|| decode_err(py, "omnibuf: truncated float64"))?
        .try_into()
        .unwrap();
    Ok(Some(f64::from_bits(u64::from_le_bytes(raw))))
}

#[inline]
fn checked_read_str<'a>(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &'a [u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<&'a str>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_STRING, siblings) else {
        return Ok(None);
    };
    let (bytes, _) =
        read_len_slice(slice, val_start, 0).map_err(|e| decode_err(py, e.to_string()))?;
    let valid_str = validate_utf8(bytes).map_err(|e| decode_err(py, e.to_string()))?;
    Ok(Some(valid_str))
}

#[inline]
fn checked_read_bytes_span(
    py: Python<'_>,
    entries: &[FieldDirEntry],
    slice: &[u8],
    fnum: u32,
    siblings: &[(u32, u16)],
) -> PyResult<Option<(usize, usize)>> {
    let Some((val_start, _)) = locate_in_dir(entries, fnum, 1 << WIRE_BYTES, siblings) else {
        return Ok(None);
    };
    let (bytes, end) =
        read_len_slice(slice, val_start, 0).map_err(|e| decode_err(py, e.to_string()))?;
    Ok(Some((end - bytes.len(), end)))
}

#[inline]
fn slice_read_uint(slice: &[u8], fnum: u32) -> Result<Option<u64>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_UINT)? else {
        return Ok(None);
    };
    let (v, _) = decode_varint(s).ok_or_else(|| "omnibuf: invalid uint varint".to_owned())?;
    Ok(Some(v))
}

#[inline]
fn slice_read_sint(slice: &[u8], fnum: u32) -> Result<Option<i64>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_SINT)? else {
        return Ok(None);
    };
    let (v, _) = decode_varint(s).ok_or_else(|| "omnibuf: invalid sint varint".to_owned())?;
    Ok(Some(decode_zigzag(v)))
}

#[inline]
fn slice_read_bool(slice: &[u8], fnum: u32) -> Result<Option<bool>, String> {
    let Some((_, wt)) =
        locate_field_u32(slice, fnum, (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE))?
    else {
        return Ok(None);
    };
    Ok(Some(wt == WIRE_BOOL_TRUE))
}

#[inline]
fn slice_read_fixed32(slice: &[u8], fnum: u32) -> Result<Option<u32>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_FIXED32)? else {
        return Ok(None);
    };
    let raw: [u8; 4] = s
        .get(..4)
        .ok_or_else(|| "omnibuf: truncated fixed32".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(u32::from_le_bytes(raw)))
}

#[inline]
fn slice_read_sfixed32(slice: &[u8], fnum: u32) -> Result<Option<i32>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_SFIXED32)? else {
        return Ok(None);
    };
    let raw: [u8; 4] = s
        .get(..4)
        .ok_or_else(|| "omnibuf: truncated sfixed32".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(i32::from_le_bytes(raw)))
}

#[inline]
fn slice_read_fixed64(slice: &[u8], fnum: u32) -> Result<Option<u64>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_FIXED64)? else {
        return Ok(None);
    };
    let raw: [u8; 8] = s
        .get(..8)
        .ok_or_else(|| "omnibuf: truncated fixed64".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(u64::from_le_bytes(raw)))
}

#[inline]
fn slice_read_sfixed64(slice: &[u8], fnum: u32) -> Result<Option<i64>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_SFIXED64)? else {
        return Ok(None);
    };
    let raw: [u8; 8] = s
        .get(..8)
        .ok_or_else(|| "omnibuf: truncated sfixed64".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(i64::from_le_bytes(raw)))
}

#[inline]
fn slice_read_float32(slice: &[u8], fnum: u32) -> Result<Option<f32>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_FLOAT32)? else {
        return Ok(None);
    };
    let raw: [u8; 4] = s
        .get(..4)
        .ok_or_else(|| "omnibuf: truncated float32".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(f32::from_bits(u32::from_le_bytes(raw))))
}

#[inline]
fn slice_read_float64(slice: &[u8], fnum: u32) -> Result<Option<f64>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_FLOAT64)? else {
        return Ok(None);
    };
    let raw: [u8; 8] = s
        .get(..8)
        .ok_or_else(|| "omnibuf: truncated float64".to_owned())?
        .try_into()
        .unwrap();
    Ok(Some(f64::from_bits(u64::from_le_bytes(raw))))
}

#[inline]
fn slice_read_str(slice: &[u8], fnum: u32) -> Result<Option<&str>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_STRING)? else {
        return Ok(None);
    };
    let (bytes, _) = read_len_slice(s, 0, 0).map_err(|e| e.to_string())?;
    let valid = validate_utf8(bytes).map_err(|e| e.to_string())?;
    Ok(Some(valid))
}

#[inline]
fn slice_read_bytes(slice: &[u8], fnum: u32) -> Result<Option<&[u8]>, String> {
    let Some((s, _)) = locate_field_u32(slice, fnum, 1 << WIRE_BYTES)? else {
        return Ok(None);
    };
    let (b, _) = read_len_slice(s, 0, 0).map_err(|e| e.to_string())?;
    Ok(Some(b))
}

#[pyclass(subclass)]
pub struct OpaqueView {
    backing: ByteSliceOwner,
    dir: OnceLock<Vec<FieldDirEntry>>,
    dirty_mask: u64,
    fast_dirty: Option<FastDirty>,
    dirty_objs: Vec<(u32, Py<PyAny>)>,
}

impl OpaqueView {
    #[inline]
    fn ensure_dir(&self, py: Python<'_>) -> PyResult<&[FieldDirEntry]> {
        if let Some(entries) = self.dir.get() {
            return Ok(entries.as_slice());
        }
        let slice = self.backing.as_slice(py);
        let n = slice.len();
        let mut entries = Vec::with_capacity((n / 8).clamp(8, 256));
        let mut pos = 0usize;
        let mut step = 0usize;
        while pos < n {
            step += 1;
            if (step & 0xFFF) == 0 {
                py.check_signals()?;
            }
            let f_start = pos;
            let (fnum, wt, val_start) = read_tag_at(slice, pos)
                .ok_or_else(|| decode_err(py, format!("omnibuf: invalid tag at byte {pos}")))?;
            let f_end = skip_checked_wire_field(py, slice, val_start, fnum, wt)?;
            entries.push(FieldDirEntry {
                fnum,
                wt,
                f_start,
                val_start,
                f_end,
            });
            pos = f_end;
        }
        let _ = self.dir.set(entries);
        Ok(self.dir.get().map_or(&[], Vec::as_slice))
    }

    #[inline]
    fn find_dirty<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Option<Bound<'py, PyAny>>> {
        if fnum < 64 && (self.dirty_mask & (1u64 << fnum)) == 0 {
            return Ok(None);
        }
        if let Some(ref fd) = self.fast_dirty
            && fd.field_num() == fnum
        {
            return fd.to_py_obj(py).map(Some);
        }
        for (k, obj) in self.dirty_objs.iter().rev() {
            if *k == fnum {
                return Ok(Some(obj.bind(py).clone()));
            }
        }
        Ok(None)
    }

    fn spill_fast_dirty(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(prev) = self.fast_dirty.take() {
            let fnum = prev.field_num();
            let py_obj = prev.to_py_obj(py)?.unbind();
            if let Some(slot) = self.dirty_objs.iter_mut().find(|(k, _)| *k == fnum) {
                slot.1 = py_obj;
            } else {
                self.dirty_objs.push((fnum, py_obj));
            }
        }
        Ok(())
    }

    fn record_fast_dirty(&mut self, py: Python<'_>, entry: FastDirty) -> PyResult<()> {
        let fnum = entry.field_num();
        if self.dirty_objs.is_empty() && fnum < 64 {
            if let Some(ref prev) = self.fast_dirty
                && prev.field_num() != fnum
            {
                self.spill_fast_dirty(py)?;
                let py_obj = entry.to_py_obj(py)?.unbind();
                return self.record_dirty_obj(py, fnum, py_obj);
            }
            self.dirty_mask |= 1u64 << fnum;
            self.fast_dirty = Some(entry);
            return Ok(());
        }
        let py_obj = entry.to_py_obj(py)?.unbind();
        self.record_dirty_obj(py, fnum, py_obj)
    }

    fn record_dirty_obj(&mut self, py: Python<'_>, fnum: u32, val: Py<PyAny>) -> PyResult<()> {
        if let Some(ref prev) = self.fast_dirty {
            if prev.field_num() == fnum {
                self.fast_dirty = None;
            } else {
                self.spill_fast_dirty(py)?;
            }
        }
        if fnum < 64 {
            self.dirty_mask |= 1u64 << fnum;
        }
        if let Some(slot) = self.dirty_objs.iter_mut().find(|(k, _)| *k == fnum) {
            slot.1 = val;
        } else {
            self.dirty_objs.push((fnum, val));
        }
        Ok(())
    }

    fn collect_submsg_spans_from_dir(
        py: Python<'_>,
        entries: &[FieldDirEntry],
        slice: &[u8],
        fnum: u32,
        siblings: &[(u32, u16)],
    ) -> PyResult<Vec<(usize, usize)>> {
        let mut spans = Vec::new();
        let has_sibs = !siblings.is_empty();
        for entry in entries {
            if entry.fnum == fnum && entry.wt == WIRE_SUB_MSG {
                let (body, end) = read_len_slice(slice, entry.val_start, 0)
                    .map_err(|e| decode_err(py, e.to_string()))?;
                spans.push((end - body.len(), end));
            } else if has_sibs
                && siblings
                    .iter()
                    .any(|&(sf, sm)| sf == entry.fnum && (sm & (1u16 << entry.wt)) != 0)
            {
                spans.clear();
            }
        }
        Ok(spans)
    }

    fn splice_single_fast<'py>(
        &mut self,
        py: Python<'py>,
        validate_all: bool,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let Some(ref fd) = self.fast_dirty else {
            return Ok(None);
        };
        let target_fnum = fd.field_num();
        let mut field_buf = Vec::with_capacity(24);
        fd.write_encoded(&mut field_buf);

        if validate_all {
            let src = self.backing.as_slice(py);
            validate_message_slice(py, src, 0)?;
        }

        let (only_start, only_end, match_count, src_len) = {
            let entries = self.ensure_dir(py)?;
            let src_len = self.backing.as_slice(py).len();
            let mut m_count = 0usize;
            let mut o_start = 0usize;
            let mut o_end = 0usize;
            for entry in entries {
                if entry.fnum == target_fnum {
                    m_count += 1;
                    o_start = entry.f_start;
                    o_end = entry.f_end;
                }
            }
            (o_start, o_end, m_count, src_len)
        };

        if match_count > 1 {
            return Ok(None);
        }

        let total_len = if match_count == 0 {
            src_len + field_buf.len()
        } else {
            only_start + field_buf.len() + (src_len - only_end)
        };

        let out_bytes: Bound<'py, PyBytes> = unsafe {
            let ptr =
                ffi::PyBytes_FromStringAndSize(std::ptr::null(), total_len as ffi::Py_ssize_t);
            let bound = Bound::from_owned_ptr_or_err(py, ptr)?;
            let dst = ffi::PyBytes_AS_STRING(bound.as_ptr())
                .cast::<u8>()
                .cast_mut();
            let src = self.backing.as_slice(py);
            if match_count == 0 {
                if src_len > 0 {
                    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src_len);
                }
                if !field_buf.is_empty() {
                    std::ptr::copy_nonoverlapping(
                        field_buf.as_ptr(),
                        dst.add(src_len),
                        field_buf.len(),
                    );
                }
            } else {
                if only_start > 0 {
                    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, only_start);
                }
                if !field_buf.is_empty() {
                    std::ptr::copy_nonoverlapping(
                        field_buf.as_ptr(),
                        dst.add(only_start),
                        field_buf.len(),
                    );
                }
                let tail_len = src_len - only_end;
                if tail_len > 0 {
                    std::ptr::copy_nonoverlapping(
                        src.as_ptr().add(only_end),
                        dst.add(only_start + field_buf.len()),
                        tail_len,
                    );
                }
            }
            bound.cast_into_unchecked::<PyBytes>()
        };

        self.backing = ByteSliceOwner {
            owner: out_bytes.clone().unbind(),
            start: 0,
            end: total_len,
        };
        self.dir = OnceLock::new();
        self.dirty_mask = 0;
        self.fast_dirty = None;
        Ok(Some(out_bytes))
    }
}

#[pymethods]
impl OpaqueView {
    #[new]
    fn py_new(py: Python<'_>, raw: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            backing: ByteSliceOwner::from_py_any(py, raw)?,
            dir: OnceLock::new(),
            dirty_mask: 0,
            fast_dirty: None,
            dirty_objs: Vec::new(),
        })
    }

    pub fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.backing.to_py_bytes(py)
    }

    pub fn validate(&self, py: Python<'_>) -> PyResult<()> {
        validate_message_slice(py, self.backing.as_slice(py), 0)
    }

    #[pyo3(signature = (fnum, exp_mask, siblings=None))]
    pub fn _has_field(
        &self,
        py: Python<'_>,
        fnum: u32,
        exp_mask: u16,
        siblings: Option<&Bound<'_, PyTuple>>,
    ) -> PyResult<bool> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(!d.is_none());
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        Ok(locate_in_dir(entries, fnum, exp_mask, &sibs).is_some())
    }

    pub fn _which_oneof<'py>(
        &self,
        py: Python<'py>,
        candidates: &Bound<'py, PyTuple>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let n_cand = candidates.len();
        if n_cand == 0 {
            return Ok(py.None().into_bound(py));
        }
        let mut specs: Vec<(u32, u16, Bound<'py, PyAny>)> = Vec::with_capacity(n_cand);
        for i in 0..n_cand {
            let item = candidates.get_item(i)?;
            let t = item.cast::<PyTuple>()?;
            let fn_num: u32 = t.get_item(0)?.extract()?;
            let mask: u16 = t.get_item(1)?.extract()?;
            let name_obj = t.get_item(2)?;
            specs.push((fn_num, mask, name_obj));
        }

        for (cand_fn, _, name_obj) in &specs {
            if let Some(d) = self.find_dirty(py, *cand_fn)?
                && !d.is_none()
            {
                return Ok(name_obj.clone());
            }
        }

        let entries = self.ensure_dir(py)?;
        let mut active: Option<usize> = None;
        for entry in entries {
            for (idx, (cand_fn, cand_mask, _)) in specs.iter().enumerate() {
                if entry.fnum == *cand_fn && (*cand_mask & (1u16 << entry.wt)) != 0 {
                    active = Some(idx);
                    break;
                }
            }
        }

        match active {
            Some(idx) => {
                let (cand_fn, _, ref name_obj) = specs[idx];
                if let Some(d) = self.find_dirty(py, cand_fn)?
                    && d.is_none()
                {
                    return Ok(py.None().into_bound(py));
                }
                Ok(name_obj.clone())
            }
            None => Ok(py.None().into_bound(py)),
        }
    }

    pub fn _get_uint32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = checked_read_uint(py, entries, self.backing.as_slice(py), fnum, &[])?
            .map_or(0, |u| u64::from(u as u32));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_uint32<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(u) = checked_read_uint(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe {
            Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u64::from(u as u32)))
        }
    }

    pub fn _get_uint64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = checked_read_uint(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_uint64<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(u) = checked_read_uint(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u)) }
    }

    pub fn _get_sint32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = checked_read_sint(py, entries, self.backing.as_slice(py), fnum, &[])?
            .map_or(0, |i| i64::from(i as i32));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_sint32<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(i) = checked_read_sint(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i64::from(i as i32))) }
    }

    pub fn _get_sint64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = checked_read_sint(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_sint64<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(i) = checked_read_sint(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i)) }
    }

    pub fn _get_bool<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = checked_read_bool(entries, fnum, &[]).unwrap_or(false);
        Ok(PyBool::new(py, v).to_owned().into_any())
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_bool<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(v) = checked_read_bool(entries, fnum, &sibs) else {
            return Ok(py.None().into_bound(py));
        };
        Ok(PyBool::new(py, v).to_owned().into_any())
    }

    pub fn _get_fixed32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = u64::from(
            checked_read_fixed32(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0),
        );
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_fixed32<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(u) = checked_read_fixed32(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u64::from(u))) }
    }

    pub fn _get_sfixed32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = i64::from(
            checked_read_sfixed32(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0),
        );
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_sfixed32<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(i) = checked_read_sfixed32(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i64::from(i))) }
    }

    pub fn _get_fixed64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v =
            checked_read_fixed64(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_fixed64<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(u) = checked_read_fixed64(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(u)) }
    }

    pub fn _get_sfixed64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v =
            checked_read_sfixed64(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_sfixed64<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(i) = checked_read_sfixed64(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(i)) }
    }

    pub fn _get_float32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v = f64::from(
            checked_read_float32(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0.0),
        );
        Ok(PyFloat::new(py, v).into_any())
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_float32<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(f) = checked_read_float32(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        Ok(PyFloat::new(py, f64::from(f)).into_any())
    }

    pub fn _get_float64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let v =
            checked_read_float64(py, entries, self.backing.as_slice(py), fnum, &[])?.unwrap_or(0.0);
        Ok(PyFloat::new(py, v).into_any())
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_float64<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(f) = checked_read_float64(py, entries, self.backing.as_slice(py), fnum, &sibs)?
        else {
            return Ok(py.None().into_bound(py));
        };
        Ok(PyFloat::new(py, f).into_any())
    }

    pub fn _get_string<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        if let Some(s) = checked_read_str(py, entries, self.backing.as_slice(py), fnum, &[])? {
            unsafe {
                Bound::from_owned_ptr_or_err(
                    py,
                    ffi::PyUnicode_FromStringAndSize(
                        s.as_ptr().cast::<std::os::raw::c_char>(),
                        s.len() as ffi::Py_ssize_t,
                    ),
                )
            }
        } else {
            Ok(PyString::intern(py, "").into_any())
        }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_string<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let Some(s) = checked_read_str(py, entries, self.backing.as_slice(py), fnum, &sibs)? else {
            return Ok(py.None().into_bound(py));
        };
        unsafe {
            Bound::from_owned_ptr_or_err(
                py,
                ffi::PyUnicode_FromStringAndSize(
                    s.as_ptr().cast::<std::os::raw::c_char>(),
                    s.len() as ffi::Py_ssize_t,
                ),
            )
        }
    }

    pub fn _get_bytes<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        if let Some((start, end)) = checked_read_bytes_span(py, entries, slice, fnum, &[])? {
            Ok(PyBytes::new(py, &slice[start..end]).into_any())
        } else {
            Ok(PyBytes::new(py, b"").into_any())
        }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_bytes<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let Some((start, end)) = checked_read_bytes_span(py, entries, slice, fnum, &sibs)? else {
            return Ok(py.None().into_bound(py));
        };
        Ok(PyBytes::new(py, &slice[start..end]).into_any())
    }

    pub fn _get_bytes_view<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            let pb = if unsafe { ffi::PyBytes_CheckExact(d.as_ptr()) != 0 } {
                unsafe { d.cast_into_unchecked::<PyBytes>() }
            } else {
                let leaf = LeafBytes::extract(py, &d)?;
                let v = leaf.as_slice().to_vec();
                drop(leaf);
                PyBytes::new(py, &v)
            };
            let len = pb.as_bytes().len();
            return create_readonly_memoryview_slice(py, &pb, 0, len);
        }
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        if let Some((start, end)) = checked_read_bytes_span(py, entries, slice, fnum, &[])? {
            self.backing.to_readonly_memoryview(py, start, end)
        } else {
            let empty = PyBytes::new(py, b"");
            create_readonly_memoryview_slice(py, &empty, 0, 0)
        }
    }

    #[pyo3(signature = (fnum, siblings=None))]
    pub fn _get_opt_bytes_view<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            if d.is_none() {
                return Ok(py.None().into_bound(py));
            }
            let pb = if unsafe { ffi::PyBytes_CheckExact(d.as_ptr()) != 0 } {
                unsafe { d.cast_into_unchecked::<PyBytes>() }
            } else {
                let leaf = LeafBytes::extract(py, &d)?;
                let v = leaf.as_slice().to_vec();
                drop(leaf);
                PyBytes::new(py, &v)
            };
            let len = pb.as_bytes().len();
            return create_readonly_memoryview_slice(py, &pb, 0, len);
        }
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let Some((start, end)) = checked_read_bytes_span(py, entries, slice, fnum, &sibs)? else {
            return Ok(py.None().into_bound(py));
        };
        self.backing.to_readonly_memoryview(py, start, end)
    }

    #[pyo3(signature = (fnum, sub_codec, siblings=None, *, max_elements=None))]
    pub fn _get_submsg<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        sub_codec: &CompiledCodec,
        siblings: Option<&Bound<'py, PyTuple>>,
        max_elements: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let mut budget = match max_elements {
            Some(obj) => crate::extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let spans = Self::collect_submsg_spans_from_dir(py, entries, slice, fnum, &sibs)?;
        let mut result: Option<Bound<'py, PyAny>> = None;
        for (b_start, b_end) in spans {
            let body = &slice[b_start..b_end];
            let decoded = sub_codec.decode_slice_budget(
                py,
                body,
                result.as_ref(),
                1,
                result.is_some(),
                &mut budget,
                None,
            )?;
            result = Some(decoded);
        }
        Ok(result.unwrap_or_else(|| py.None().into_bound(py)))
    }

    #[pyo3(signature = (fnum, opaque_cls, sub_codec, siblings=None))]
    pub fn _opaque_sub<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        opaque_cls: &Bound<'py, PyType>,
        sub_codec: &CompiledCodec,
        siblings: Option<&Bound<'py, PyTuple>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            if d.is_none() {
                return Ok(py.None().into_bound(py));
            }
            let sub_bytes = sub_codec.marshal(py, &d, false, false)?;
            return opaque_cls.call1((sub_bytes,));
        }

        let sibs = parse_sibling_specs(siblings)?;
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let spans = Self::collect_submsg_spans_from_dir(py, entries, slice, fnum, &sibs)?;
        if spans.is_empty() {
            return Ok(py.None().into_bound(py));
        }
        let sub_backing = if spans.len() == 1 {
            let (b1_start, b1_end) = spans[0];
            self.backing.subslice(py, b1_start, b1_end)
        } else {
            let total: usize = spans.iter().map(|(s, e)| e - s).sum();
            let mut merged = Vec::with_capacity(total);
            for (s, e) in spans {
                merged.extend_from_slice(&slice[s..e]);
            }
            ByteSliceOwner::from_vec(py, &merged)
        };
        let inst = opaque_cls.call1((PyBytes::new(py, b""),))?;
        {
            let mut view_ref = inst.cast::<OpaqueView>()?.borrow_mut();
            view_ref.backing = sub_backing;
            view_ref.dir = OnceLock::new();
        }
        Ok(inst)
    }

    #[pyo3(signature = (fnum, exp_elem_wt, elem_kind_code, *, max_elements=None))]
    pub fn _get_scalar_array<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        exp_elem_wt: u8,
        elem_kind_code: u8,
        max_elements: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let mut budget = match max_elements {
            Some(obj) => crate::extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        let elem_kind = ScalarKind::from_code(elem_kind_code).ok_or_else(|| {
            decode_err(py, format!("omnibuf: unknown kind code {elem_kind_code}"))
        })?;
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let out = PyList::empty(py);
        for entry in entries {
            if entry.fnum != fnum || entry.wt != WIRE_ARRAY {
                continue;
            }
            let (body, _) = read_len_slice(slice, entry.val_start, 2)
                .map_err(|e| decode_err(py, e.to_string()))?;
            let (ewt, count, mut p) = parse_array_header(body).ok_or_else(|| {
                decode_err(
                    py,
                    format!("omnibuf: invalid array header on field #{fnum}"),
                )
            })?;
            if ewt != exp_elem_wt {
                return Err(decode_err(
                    py,
                    format!("omnibuf: mismatched array element wire type on field #{fnum}"),
                ));
            }
            budget.consume(py, count)?;
            for i in 0..count {
                if (i & 0xFFF) == 0xFFF {
                    py.check_signals()?;
                }
                let (val_obj, next_p) = read_scalar_payload(py, body, p, elem_kind, None, None)?;
                p = next_p;
                out.append(val_obj)?;
            }
            if p != body.len() {
                return Err(decode_err(
                    py,
                    format!("omnibuf: trailing array bytes on field #{fnum}"),
                ));
            }
        }
        Ok(out.into_any())
    }

    #[pyo3(signature = (fnum, sub_codec, *, max_elements=None))]
    pub fn _get_submsg_array<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        sub_codec: &CompiledCodec,
        max_elements: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let mut budget = match max_elements {
            Some(obj) => crate::extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let out = PyList::empty(py);
        for entry in entries {
            if entry.fnum != fnum || entry.wt != WIRE_ARRAY {
                continue;
            }
            let (body, _) = read_len_slice(slice, entry.val_start, 2)
                .map_err(|e| decode_err(py, e.to_string()))?;
            let (ewt, count, mut p) = parse_array_header(body).ok_or_else(|| {
                decode_err(
                    py,
                    format!("omnibuf: invalid submsg array header on field #{fnum}"),
                )
            })?;
            if ewt != WIRE_SUB_MSG {
                return Err(decode_err(
                    py,
                    format!("omnibuf: invalid submsg array element wire type on field #{fnum}"),
                ));
            }
            budget.consume(py, count)?;
            for i in 0..count {
                if (i & 0xFFF) == 0xFFF {
                    py.check_signals()?;
                }
                let (elem_slice, next_p) =
                    read_len_slice(body, p, 0).map_err(|e| decode_err(py, e.to_string()))?;
                p = next_p;
                let elem_obj = sub_codec.decode_slice_budget(
                    py,
                    elem_slice,
                    None,
                    2,
                    false,
                    &mut budget,
                    None,
                )?;
                out.append(elem_obj)?;
            }
            if p != body.len() {
                return Err(decode_err(
                    py,
                    format!("omnibuf: trailing submsg array bytes on field #{fnum}"),
                ));
            }
        }
        Ok(out.into_any())
    }

    #[pyo3(signature = (fnum, exp_key_wt, key_kind_code, exp_val_wt, val_kind_code, sub_codec=None, *, max_elements=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn _get_map<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        exp_key_wt: u8,
        key_kind_code: u8,
        exp_val_wt: u8,
        val_kind_code: u8,
        sub_codec: Option<&CompiledCodec>,
        max_elements: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum)? {
            return Ok(d);
        }
        let mut budget = match max_elements {
            Some(obj) => crate::extract_max_elements(py, obj)?,
            None => DecodeBudget::default_budget(),
        };
        let key_kind = ScalarKind::from_code(key_kind_code).ok_or_else(|| {
            decode_err(
                py,
                format!("omnibuf: unknown key kind code {key_kind_code}"),
            )
        })?;
        let val_scalar_kind = if sub_codec.is_none() {
            let vk = ScalarKind::from_code(val_kind_code).ok_or_else(|| {
                decode_err(
                    py,
                    format!("omnibuf: unknown val kind code {val_kind_code}"),
                )
            })?;
            Some(vk)
        } else {
            None
        };

        let entries = self.ensure_dir(py)?;
        let slice = self.backing.as_slice(py);
        let out = PyDict::new(py);
        for entry in entries {
            if entry.fnum != fnum || entry.wt != WIRE_MAP {
                continue;
            }
            let (body, _) = read_len_slice(slice, entry.val_start, 3)
                .map_err(|e| decode_err(py, e.to_string()))?;
            let (kwt, vwt, count, mut p) = parse_map_header(body).ok_or_else(|| {
                decode_err(py, format!("omnibuf: invalid map header on field #{fnum}"))
            })?;
            if kwt != exp_key_wt || vwt != exp_val_wt {
                return Err(decode_err(
                    py,
                    format!("omnibuf: mismatched map header on field #{fnum}"),
                ));
            }
            budget.consume(py, count)?;
            for i in 0..count {
                if (i & 0xFFF) == 0xFFF {
                    py.check_signals()?;
                }
                let (k_obj, after_k) = read_scalar_payload(py, body, p, key_kind, None, None)?;
                let (v_obj, after_v) = if let Some(sc) = sub_codec {
                    let (v_slice, vp) = read_len_slice(body, after_k, 0)
                        .map_err(|e| decode_err(py, e.to_string()))?;
                    let msg_v =
                        sc.decode_slice_budget(py, v_slice, None, 2, false, &mut budget, None)?;
                    (msg_v, vp)
                } else {
                    read_scalar_payload(py, body, after_k, val_scalar_kind.unwrap(), None, None)?
                };
                p = after_v;
                out.set_item(k_obj, v_obj)?;
            }
            if p != body.len() {
                return Err(decode_err(
                    py,
                    format!("omnibuf: trailing map bytes on field #{fnum}"),
                ));
            }
        }
        Ok(out.into_any())
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_uint32(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: uint32 value cannot be None"));
        }
        let v = extract_i64(py, val.as_ptr(), "uint32")?;
        if !(0..=i64::from(u32::MAX)).contains(&v) {
            return Err(encode_err(py, format!("omnibuf: uint32 {v} out of range")));
        }
        self.record_fast_dirty(py, FastDirty::Uint(fnum, v as u64))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_uint64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: uint64 value cannot be None"));
        }
        let v = extract_u64(py, val.as_ptr(), "uint64")?;
        self.record_fast_dirty(py, FastDirty::Uint(fnum, v))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_sint32(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: sint32 value cannot be None"));
        }
        let v = extract_i64(py, val.as_ptr(), "sint32")?;
        if i32::try_from(v).is_err() {
            return Err(encode_err(py, format!("omnibuf: sint32 {v} out of range")));
        }
        self.record_fast_dirty(py, FastDirty::Sint(fnum, v, true))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_sint64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: sint64 value cannot be None"));
        }
        let v = extract_i64(py, val.as_ptr(), "sint64")?;
        self.record_fast_dirty(py, FastDirty::Sint(fnum, v, false))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_bool(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: bool value cannot be None"));
        }
        let b = extract_bool(py, val.as_ptr())?;
        self.record_fast_dirty(py, FastDirty::Bool(fnum, b))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_fixed32(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: fixed32 value cannot be None"));
        }
        let v = extract_i64(py, val.as_ptr(), "fixed32")?;
        let Ok(u) = u32::try_from(v) else {
            return Err(encode_err(py, format!("omnibuf: fixed32 {v} out of range")));
        };
        self.record_fast_dirty(py, FastDirty::Fixed32(fnum, u))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_sfixed32(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: sfixed32 value cannot be None"));
        }
        let v = extract_i64(py, val.as_ptr(), "sfixed32")?;
        let Ok(i) = i32::try_from(v) else {
            return Err(encode_err(
                py,
                format!("omnibuf: sfixed32 {v} out of range"),
            ));
        };
        self.record_fast_dirty(py, FastDirty::Sfixed32(fnum, i))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_fixed64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: fixed64 value cannot be None"));
        }
        let u = extract_u64(py, val.as_ptr(), "fixed64")?;
        self.record_fast_dirty(py, FastDirty::Fixed64(fnum, u))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_sfixed64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: sfixed64 value cannot be None"));
        }
        let i = extract_i64(py, val.as_ptr(), "sfixed64")?;
        self.record_fast_dirty(py, FastDirty::Sfixed64(fnum, i))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_float32(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: float32 value cannot be None"));
        }
        let v = extract_f64(py, val.as_ptr(), "float32")?;
        let f = v as f32;
        if v.is_finite() && !f.is_finite() {
            return Err(encode_err(py, "omnibuf: float32 overflow"));
        }
        self.record_fast_dirty(py, FastDirty::Float32(fnum, f))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_float64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: float64 value cannot be None"));
        }
        let f = extract_f64(py, val.as_ptr(), "float64")?;
        self.record_fast_dirty(py, FastDirty::Float64(fnum, f))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_string(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: string value cannot be None"));
        }
        let s = unsafe {
            let mut size: ffi::Py_ssize_t = 0;
            let utf8_ptr = ffi::PyUnicode_AsUTF8AndSize(val.as_ptr(), &mut size);
            if utf8_ptr.is_null() {
                let err = PyErr::fetch(py);
                return Err(encode_err(
                    py,
                    format!("omnibuf: invalid UTF-8 string: {err}"),
                ));
            }
            let slice = std::slice::from_raw_parts(utf8_ptr.cast::<u8>(), size as usize);
            std::str::from_utf8(slice)
                .map_err(|e| encode_err(py, e.to_string()))?
                .to_owned()
        };
        self.record_fast_dirty(py, FastDirty::Str(fnum, s))
    }

    #[pyo3(signature = (fnum, val, allow_none=false))]
    pub fn _set_bytes(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
        allow_none: bool,
    ) -> PyResult<()> {
        if val.is_none() {
            if allow_none {
                return self.record_fast_dirty(py, FastDirty::Cleared(fnum));
            }
            return Err(encode_err(py, "omnibuf: bytes value cannot be None"));
        }
        let leaf = LeafBytes::extract(py, val)
            .map_err(|e| encode_err(py, format!("omnibuf: invalid bytes buffer: {e}")))?;
        let vec = leaf.as_slice().to_vec();
        drop(leaf);
        self.record_fast_dirty(py, FastDirty::Bytes(fnum, vec))
    }

    pub fn _set_dirty(&mut self, py: Python<'_>, fnum: u32, val: Py<PyAny>) -> PyResult<()> {
        self.record_dirty_obj(py, fnum, val)
    }

    pub fn _set_oneof_dirty(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: Py<PyAny>,
        sibling_fnums: &Bound<'_, PyTuple>,
    ) -> PyResult<()> {
        let clearing = val.is_none(py);
        self.record_dirty_obj(py, fnum, val)?;
        if !clearing {
            let n = sibling_fnums.len();
            for i in 0..n {
                let sib: u32 = sibling_fnums.get_item(i)?.extract()?;
                if sib != fnum {
                    self.record_dirty_obj(py, sib, py.None())?;
                }
            }
        }
        Ok(())
    }

    #[pyo3(signature = (codec, *, dst_prefix=None, self_describing=false, validate_all=false))]
    pub fn _marshal_with_codec<'py>(
        &mut self,
        py: Python<'py>,
        codec: &CompiledCodec,
        dst_prefix: Option<&Bound<'py, PyAny>>,
        self_describing: bool,
        validate_all: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let has_dirty = self.fast_dirty.is_some() || !self.dirty_objs.is_empty();

        if !has_dirty {
            if validate_all {
                validate_message_slice(py, self.backing.as_slice(py), 0)?;
            } else {
                let _ = self.ensure_dir(py)?;
            }
            if dst_prefix.is_none() && !self_describing {
                return Ok(self.backing.to_py_bytes(py));
            }
            let src = self.backing.as_slice(py);
            let mut out = Vec::with_capacity(src.len() + 64);
            if let Some(p_obj) = dst_prefix {
                let pb = LeafBytes::extract(py, p_obj)?;
                out.extend_from_slice(pb.as_slice());
            }
            if self_describing
                && read_field0_checked(src)
                    .map_err(|m| decode_err(py, m))?
                    .is_none()
            {
                out.extend_from_slice(codec.field0_bytes());
            }
            out.extend_from_slice(src);
            return Ok(PyBytes::new(py, &out));
        }

        if self.fast_dirty.is_some()
            && self.dirty_objs.is_empty()
            && dst_prefix.is_none()
            && !self_describing
            && let Some(fast_bytes) = self.splice_single_fast(py, validate_all)?
        {
            return Ok(fast_bytes);
        }

        self.spill_fast_dirty(py)?;
        self.dirty_objs.sort_by_key(|(fnum, _)| *fnum);

        if validate_all {
            validate_message_slice(py, self.backing.as_slice(py), 0)?;
        }

        let spliced_vec = {
            let entries = self.ensure_dir(py)?;
            let src = self.backing.as_slice(py);
            let n = src.len();
            let mut last_idx: Vec<Option<usize>> = vec![None; self.dirty_objs.len()];

            for (span_i, entry) in entries.iter().enumerate() {
                if let Ok(d_idx) = self
                    .dirty_objs
                    .binary_search_by_key(&entry.fnum, |(k, _)| *k)
                {
                    last_idx[d_idx] = Some(span_i);
                }
            }

            let mut enc = Encoder::new(n + 128);
            let mut emitted = vec![false; self.dirty_objs.len()];
            let mut copy_start = 0usize;

            for (idx, entry) in entries.iter().enumerate() {
                let Ok(d_idx) = self
                    .dirty_objs
                    .binary_search_by_key(&entry.fnum, |(k, _)| *k)
                else {
                    continue;
                };
                if copy_start < entry.f_start {
                    enc.write_raw(&src[copy_start..entry.f_start]);
                }
                if last_idx[d_idx] == Some(idx) {
                    let val_bound = self.dirty_objs[d_idx].1.bind(py);
                    codec.encode_single_field(py, &mut enc, entry.fnum, val_bound, true)?;
                    emitted[d_idx] = true;
                }
                copy_start = entry.f_end;
            }

            if copy_start < n {
                enc.write_raw(&src[copy_start..n]);
            }

            for (d_idx, was_emitted) in emitted.into_iter().enumerate() {
                if !was_emitted {
                    let (fnum, ref obj) = self.dirty_objs[d_idx];
                    codec.encode_single_field(py, &mut enc, fnum, obj.bind(py), true)?;
                }
            }
            enc.into_vec()
        };

        let spliced_py = PyBytes::new(py, &spliced_vec);
        self.backing = ByteSliceOwner {
            owner: spliced_py.clone().unbind(),
            start: 0,
            end: spliced_vec.len(),
        };
        self.dir = OnceLock::new();
        self.dirty_mask = 0;
        self.dirty_objs.clear();

        if dst_prefix.is_none() && !self_describing {
            return Ok(spliced_py);
        }

        let mut prefix_out = Vec::with_capacity(spliced_vec.len() + 64);
        if let Some(p_obj) = dst_prefix {
            let pb = LeafBytes::extract(py, p_obj)?;
            prefix_out.extend_from_slice(pb.as_slice());
        }
        if self_describing
            && read_field0_checked(&spliced_vec)
                .map_err(|m| decode_err(py, m))?
                .is_none()
        {
            prefix_out.extend_from_slice(codec.field0_bytes());
        }
        if prefix_out.is_empty() {
            return Ok(spliced_py);
        }
        prefix_out.extend_from_slice(&spliced_vec);
        Ok(PyBytes::new(py, &prefix_out))
    }
}

// ============================================================================
// Standalone Rust Opaque Header-Hop Readers for `omnibuf.opaque`
// ============================================================================

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_uint32_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: u32,
) -> PyResult<u32> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_uint(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.map_or(default, |v| v as u32))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_uint64_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: u64,
) -> PyResult<u64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_uint(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_sint32_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: i32,
) -> PyResult<i32> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_sint(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.map_or(default, |v| v as i32))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_sint64_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: i64,
) -> PyResult<i64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_sint(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=false))]
pub fn opaque_get_bool_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: bool,
) -> PyResult<bool> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_bool(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_fixed32_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: u32,
) -> PyResult<u32> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_fixed32(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_sfixed32_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: i32,
) -> PyResult<i32> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_sfixed32(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_fixed64_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: u64,
) -> PyResult<u64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_fixed64(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0))]
pub fn opaque_get_sfixed64_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: i64,
) -> PyResult<i64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_sfixed64(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0.0))]
pub fn opaque_get_float32_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: f64,
) -> PyResult<f64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_float32(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.map_or(default, f64::from))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=0.0))]
pub fn opaque_get_float64_py(
    py: Python<'_>,
    raw: &Bound<'_, PyAny>,
    field_num: i64,
    default: f64,
) -> PyResult<f64> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(default);
    }
    let b = LeafBytes::extract(py, raw)?;
    let opt = slice_read_float64(b.as_slice(), field_num as u32).map_err(|m| decode_err(py, m))?;
    Ok(opt.unwrap_or(default))
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=""))]
pub fn opaque_get_string_py<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyAny>,
    field_num: i64,
    default: &str,
) -> PyResult<Bound<'py, PyString>> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(PyString::new(py, default));
    }
    let out_opt = {
        let b = LeafBytes::extract(py, raw)?;
        slice_read_str(b.as_slice(), field_num as u32)
            .map_err(|m| decode_err(py, m))?
            .map(str::to_owned)
    };
    if let Some(s) = out_opt {
        Ok(PyString::new(py, &s))
    } else {
        Ok(PyString::new(py, default))
    }
}

#[pyfunction]
#[pyo3(signature = (raw, field_num, default=None))]
pub fn opaque_get_bytes_py<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyAny>,
    field_num: i64,
    default: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let make_default = || -> PyResult<Bound<'py, PyBytes>> {
        if let Some(d) = default {
            let db = LeafBytes::extract(py, d)?;
            let vec = db.as_slice().to_vec();
            drop(db);
            Ok(PyBytes::new(py, &vec))
        } else {
            Ok(PyBytes::new(py, b""))
        }
    };
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return make_default();
    }
    let out_opt = {
        let b = LeafBytes::extract(py, raw)?;
        slice_read_bytes(b.as_slice(), field_num as u32)
            .map_err(|m| decode_err(py, m))?
            .map(|s| s.to_vec())
    };
    if let Some(found) = out_opt {
        Ok(PyBytes::new(py, &found))
    } else {
        make_default()
    }
}

#[pyfunction]
pub fn opaque_get_submsg_slice_py<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyAny>,
    field_num: i64,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return Ok(None);
    }
    let found_vec: Option<Vec<u8>> = {
        let b = LeafBytes::extract(py, raw)?;
        let slice = b.as_slice();
        let first = next_container_u32(slice, 0, field_num as u32, WIRE_SUB_MSG, 0)
            .map_err(|m| decode_err(py, m))?;
        if let Some((b1_s, b1_e, mut pos)) = first {
            let mut merged: Option<Vec<u8>> = None;
            while pos < slice.len() {
                let nxt = next_container_u32(slice, pos, field_num as u32, WIRE_SUB_MSG, 0)
                    .map_err(|m| decode_err(py, m))?;
                let Some((bn_s, bn_e, next_p)) = nxt else {
                    break;
                };
                pos = next_p;
                let vec = merged.get_or_insert_with(|| slice[b1_s..b1_e].to_vec());
                vec.extend_from_slice(&slice[bn_s..bn_e]);
            }
            Some(merged.unwrap_or_else(|| slice[b1_s..b1_e].to_vec()))
        } else {
            None
        }
    };
    Ok(found_vec.map(|v| PyBytes::new(py, &v)))
}
