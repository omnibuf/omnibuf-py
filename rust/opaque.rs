use omnibuf_core::field0::{read_field0_schema_meta, validate_field0};
use omnibuf_core::wire::{
    Encoder, MAX_FIELD_NUMBER, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES,
    WIRE_EXTENDED, WIRE_FIXED32, WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32,
    WIRE_SFIXED64, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint,
    decode_varint, decode_zigzag, fast_skip_value, parse_array_header, parse_map_header, read_bool,
    read_bytes, read_fixed32, read_fixed64, read_float32, read_float64, read_len_slice,
    read_sfixed32, read_sfixed64, read_sint, read_str, read_sub_msg, read_tag_at, read_uint,
    skip_value, validate_message,
};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyList, PyString, PyType};

use crate::codec::{CompiledCodec, ScalarKind, extract_u64, read_scalar_payload};
use crate::{BorrowedBytes, decode_err};

enum RawBacking {
    PyBytes {
        owner: Py<PyBytes>,
        start: usize,
        end: usize,
    },
    Owned(Vec<u8>),
}

impl RawBacking {
    #[inline]
    fn from_py_any(py: Python<'_>, raw: &Bound<'_, PyAny>) -> PyResult<Self> {
        unsafe {
            if ffi::PyBytes_CheckExact(raw.as_ptr()) != 0 {
                let len = ffi::PyBytes_Size(raw.as_ptr()) as usize;
                let pb = raw.cast_unchecked::<PyBytes>().clone().unbind();
                return Ok(Self::PyBytes {
                    owner: pb,
                    start: 0,
                    end: len,
                });
            }
        }
        let borrowed = BorrowedBytes::extract(py, raw.as_ptr())?;
        Ok(Self::Owned(borrowed.as_slice().to_vec()))
    }

    #[inline]
    fn as_slice<'a>(&'a self, py: Python<'a>) -> &'a [u8] {
        match self {
            Self::PyBytes { owner, start, end } => &owner.as_bytes(py)[*start..*end],
            Self::Owned(vec) => vec.as_slice(),
        }
    }

    fn to_py_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match self {
            Self::PyBytes { owner, start, end } => {
                let full = owner.bind(py);
                if *start == 0 && *end == full.as_bytes().len() {
                    full.clone()
                } else {
                    PyBytes::new(py, &full.as_bytes()[*start..*end])
                }
            }
            Self::Owned(vec) => PyBytes::new(py, vec),
        }
    }
}

#[inline]
fn locate_field_u32(packet: &[u8], target_field: u32, exp_mask: u16) -> Option<(&[u8], u8)> {
    let mut pos = 0usize;
    let n = packet.len();
    let mut found: Option<(&[u8], u8)> = None;
    while pos < n {
        let (fnum, wt, next_pos) = read_tag_at(packet, pos)?;
        pos = next_pos;
        if fnum == 0 && wt != WIRE_SUB_MSG {
            return None;
        }
        if fnum == target_field && (exp_mask & (1u16 << wt)) != 0 {
            found = Some((&packet[pos..], wt));
        }
        pos = match wt {
            WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED => skip_value(packet, pos, wt).ok()?,
            _ => fast_skip_value(packet, pos, wt)?,
        };
    }
    found
}

#[inline]
fn next_container_u32(
    packet: &[u8],
    mut pos: usize,
    target_field: u32,
    exp_wt: u8,
    min_len: usize,
) -> (Option<(usize, usize, usize)>, bool) {
    let n = packet.len();
    while pos < n {
        let Some((fnum, wt, after_tag)) = read_tag_at(packet, pos) else {
            return (None, false);
        };
        pos = after_tag;
        if fnum == 0 && wt != WIRE_SUB_MSG {
            return (None, false);
        }
        if fnum == target_field && wt == exp_wt {
            let Ok((body, end)) = read_len_slice(packet, pos, min_len) else {
                return (None, false);
            };
            let start = end - body.len();
            return (Some((start, end, end)), true);
        }
        let next = if matches!(wt, WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED) {
            skip_value(packet, pos, wt).ok()
        } else {
            fast_skip_value(packet, pos, wt)
        };
        let Some(next_pos) = next else {
            return (None, false);
        };
        pos = next_pos;
    }
    (None, true)
}

#[inline]
fn slice_read_uint(slice: &[u8], fnum: u32) -> Option<u64> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_uint(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_UINT)?;
        decode_varint(s).map(|(v, _)| v)
    }
}

#[inline]
fn slice_read_sint(slice: &[u8], fnum: u32) -> Option<i64> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_sint(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_SINT)?;
        decode_varint(s).map(|(v, _)| decode_zigzag(v))
    }
}

#[inline]
fn slice_read_bool(slice: &[u8], fnum: u32) -> Option<bool> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_bool(slice, f16)
    } else {
        let (_, wt) =
            locate_field_u32(slice, fnum, (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE))?;
        Some(wt == WIRE_BOOL_TRUE)
    }
}

#[inline]
fn slice_read_fixed32(slice: &[u8], fnum: u32) -> Option<u32> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_fixed32(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_FIXED32)?;
        Some(u32::from_le_bytes(s.get(..4)?.try_into().ok()?))
    }
}

#[inline]
fn slice_read_sfixed32(slice: &[u8], fnum: u32) -> Option<i32> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_sfixed32(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_SFIXED32)?;
        Some(i32::from_le_bytes(s.get(..4)?.try_into().ok()?))
    }
}

#[inline]
fn slice_read_fixed64(slice: &[u8], fnum: u32) -> Option<u64> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_fixed64(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_FIXED64)?;
        Some(u64::from_le_bytes(s.get(..8)?.try_into().ok()?))
    }
}

#[inline]
fn slice_read_sfixed64(slice: &[u8], fnum: u32) -> Option<i64> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_sfixed64(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_SFIXED64)?;
        Some(i64::from_le_bytes(s.get(..8)?.try_into().ok()?))
    }
}

#[inline]
fn slice_read_float32(slice: &[u8], fnum: u32) -> Option<f32> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_float32(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_FLOAT32)?;
        Some(f32::from_bits(u32::from_le_bytes(
            s.get(..4)?.try_into().ok()?,
        )))
    }
}

#[inline]
fn slice_read_float64(slice: &[u8], fnum: u32) -> Option<f64> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_float64(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_FLOAT64)?;
        Some(f64::from_bits(u64::from_le_bytes(
            s.get(..8)?.try_into().ok()?,
        )))
    }
}

#[inline]
fn slice_read_str(slice: &[u8], fnum: u32) -> Option<&str> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_str(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_STRING)?;
        read_str_slice_opt(s)
    }
}

#[inline]
fn read_str_slice_opt(s: &[u8]) -> Option<&str> {
    let (bytes, _) = read_len_slice(s, 0, 0).ok()?;
    omnibuf_core::wire::validate_utf8(bytes).ok()
}

#[inline]
fn slice_read_bytes(slice: &[u8], fnum: u32) -> Option<&[u8]> {
    if let Ok(f16) = u16::try_from(fnum) {
        read_bytes(slice, f16)
    } else {
        let (s, _) = locate_field_u32(slice, fnum, 1 << WIRE_BYTES)?;
        let (b, _) = read_len_slice(s, 0, 0).ok()?;
        Some(b)
    }
}

#[pyclass(subclass)]
pub struct OpaqueView {
    backing: RawBacking,
    dirty_mask: u64,
    fast_u64: Option<(u32, u64)>,
    dirty_objs: Vec<(u32, Py<PyAny>)>,
}

impl OpaqueView {
    #[inline]
    fn find_dirty<'py>(&self, py: Python<'py>, fnum: u32) -> Option<Bound<'py, PyAny>> {
        if fnum < 64 && (self.dirty_mask & (1u64 << fnum)) == 0 {
            return None;
        }
        if let Some((fn_u64, val_u64)) = self.fast_u64
            && fn_u64 == fnum
        {
            return unsafe {
                Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(val_u64)).ok()
            };
        }
        for (k, obj) in self.dirty_objs.iter().rev() {
            if *k == fnum {
                return Some(obj.bind(py).clone());
            }
        }
        None
    }

    fn record_dirty_obj(&mut self, py: Python<'_>, fnum: u32, val: Py<PyAny>) {
        if let Some((prev_fnum, prev_u64)) = self.fast_u64.take()
            && prev_fnum != fnum
        {
            unsafe {
                let p = ffi::PyLong_FromUnsignedLongLong(prev_u64);
                if let Ok(bound) = Bound::from_owned_ptr_or_err(py, p) {
                    self.dirty_objs.push((prev_fnum, bound.unbind()));
                }
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
    }

    fn splice_single_u64_fast<'py>(
        &mut self,
        py: Python<'py>,
        target_fnum: u32,
        val_u64: u64,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let mut field_buf = Vec::with_capacity(14);
        append_tag(&mut field_buf, target_fnum, WIRE_UINT);
        append_varint(&mut field_buf, val_u64);

        let (only_start, only_end, match_count, src_len) = {
            let src = self.backing.as_slice(py);
            let n = src.len();
            let mut pos = 0usize;
            let mut m_count = 0usize;
            let mut o_start = 0usize;
            let mut o_end = 0usize;

            while pos < n {
                let f_start = pos;
                let (fnum, wt, after_tag) = read_tag_at(src, pos)
                    .ok_or_else(|| decode_err(py, format!("omnibuf: invalid tag at byte {pos}")))?;
                pos = after_tag;

                let next_pos = if fnum == 0 {
                    if wt != WIRE_SUB_MSG {
                        return Err(decode_err(
                            py,
                            format!("omnibuf: Field #0 requires WireSubMsg (12), got {wt}"),
                        ));
                    }
                    validate_field0(src, pos, 0).map_err(|e| decode_err(py, e.to_string()))?
                } else if matches!(wt, WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED) {
                    skip_value(src, pos, wt).map_err(|e| decode_err(py, e.to_string()))?
                } else {
                    fast_skip_value(src, pos, wt).ok_or_else(|| {
                        decode_err(
                            py,
                            format!("omnibuf: truncated field payload at byte {pos}"),
                        )
                    })?
                };

                if fnum == target_fnum {
                    m_count += 1;
                    o_start = f_start;
                    o_end = next_pos;
                }
                pos = next_pos;
            }
            (o_start, o_end, m_count, n)
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
                std::ptr::copy_nonoverlapping(
                    field_buf.as_ptr(),
                    dst.add(src_len),
                    field_buf.len(),
                );
            } else {
                if only_start > 0 {
                    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, only_start);
                }
                std::ptr::copy_nonoverlapping(
                    field_buf.as_ptr(),
                    dst.add(only_start),
                    field_buf.len(),
                );
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

        self.backing = RawBacking::PyBytes {
            owner: out_bytes.clone().unbind(),
            start: 0,
            end: total_len,
        };
        self.dirty_mask = 0;
        self.fast_u64 = None;
        Ok(Some(out_bytes))
    }
}

#[pymethods]
impl OpaqueView {
    #[new]
    fn py_new(py: Python<'_>, raw: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            backing: RawBacking::from_py_any(py, raw)?,
            dirty_mask: 0,
            fast_u64: None,
            dirty_objs: Vec::new(),
        })
    }

    pub fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.backing.to_py_bytes(py)
    }

    pub fn _get_uint32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_uint(self.backing.as_slice(py), fnum).map_or(0, |u| u64::from(u as u32));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    pub fn _get_uint64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_uint(self.backing.as_slice(py), fnum).unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    pub fn _get_sint32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_sint(self.backing.as_slice(py), fnum).map_or(0, |i| i64::from(i as i32));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    pub fn _get_sint64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_sint(self.backing.as_slice(py), fnum).unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    pub fn _get_bool<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_bool(self.backing.as_slice(py), fnum).unwrap_or(false);
        Ok(PyBool::new(py, v).to_owned().into_any())
    }

    pub fn _get_fixed32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = u64::from(slice_read_fixed32(self.backing.as_slice(py), fnum).unwrap_or(0));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    pub fn _get_sfixed32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = i64::from(slice_read_sfixed32(self.backing.as_slice(py), fnum).unwrap_or(0));
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    pub fn _get_fixed64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_fixed64(self.backing.as_slice(py), fnum).unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromUnsignedLongLong(v)) }
    }

    pub fn _get_sfixed64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_sfixed64(self.backing.as_slice(py), fnum).unwrap_or(0);
        unsafe { Bound::from_owned_ptr_or_err(py, ffi::PyLong_FromLongLong(v)) }
    }

    pub fn _get_float32<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = f64::from(slice_read_float32(self.backing.as_slice(py), fnum).unwrap_or(0.0));
        Ok(PyFloat::new(py, v).into_any())
    }

    pub fn _get_float64<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let v = slice_read_float64(self.backing.as_slice(py), fnum).unwrap_or(0.0);
        Ok(PyFloat::new(py, v).into_any())
    }

    pub fn _get_string<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        if let Some(s) = slice_read_str(self.backing.as_slice(py), fnum) {
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

    pub fn _get_bytes<'py>(&self, py: Python<'py>, fnum: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        if let Some(b) = slice_read_bytes(self.backing.as_slice(py), fnum) {
            Ok(PyBytes::new(py, b).into_any())
        } else {
            Ok(PyBytes::new(py, b"").into_any())
        }
    }

    pub fn _get_submsg<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        sub_codec: &CompiledCodec,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let slice = self.backing.as_slice(py);
        let mut pos = 0usize;
        let mut result: Option<Bound<'py, PyAny>> = None;
        loop {
            let (matched, valid) = next_container_u32(slice, pos, fnum, WIRE_SUB_MSG, 0);
            if !valid {
                return Ok(py.None().into_bound(py));
            }
            let Some((b_start, b_end, next_pos)) = matched else {
                break;
            };
            pos = next_pos;
            let body = &slice[b_start..b_end];
            match sub_codec.decode_slice(py, body, result.as_ref(), 1, result.is_some()) {
                Ok(decoded) => result = Some(decoded),
                Err(_) => return Ok(py.None().into_bound(py)),
            }
        }
        Ok(result.unwrap_or_else(|| py.None().into_bound(py)))
    }

    pub fn _opaque_sub<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        opaque_cls: &Bound<'py, PyType>,
        sub_codec: &CompiledCodec,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            if d.is_none() {
                return Ok(py.None().into_bound(py));
            }
            let sub_bytes = sub_codec.marshal(py, &d, false, false)?;
            return opaque_cls.call1((sub_bytes,));
        }

        let slice = self.backing.as_slice(py);
        let (first, valid1) = next_container_u32(slice, 0, fnum, WIRE_SUB_MSG, 0);
        if !valid1 {
            return Ok(py.None().into_bound(py));
        }
        let Some((b1_start, b1_end, pos1)) = first else {
            return Ok(py.None().into_bound(py));
        };
        let (second, valid2) = next_container_u32(slice, pos1, fnum, WIRE_SUB_MSG, 0);
        if !valid2 {
            return Ok(py.None().into_bound(py));
        }

        if let Some((b2_start, b2_end, mut pos)) = second {
            let mut merged = Vec::with_capacity((b1_end - b1_start) + (b2_end - b2_start) + 32);
            merged.extend_from_slice(&slice[b1_start..b1_end]);
            merged.extend_from_slice(&slice[b2_start..b2_end]);
            while pos < slice.len() {
                let (nxt, ok) = next_container_u32(slice, pos, fnum, WIRE_SUB_MSG, 0);
                if !ok {
                    return Ok(py.None().into_bound(py));
                }
                let Some((bn_start, bn_end, next_p)) = nxt else {
                    break;
                };
                pos = next_p;
                merged.extend_from_slice(&slice[bn_start..bn_end]);
            }
            let inst = opaque_cls.call1((PyBytes::new(py, b""),))?;
            inst.cast::<OpaqueView>()?.borrow_mut().backing = RawBacking::Owned(merged);
            Ok(inst)
        } else {
            let sub_backing = match &self.backing {
                RawBacking::PyBytes { owner, start, .. } => RawBacking::PyBytes {
                    owner: owner.clone_ref(py),
                    start: start + b1_start,
                    end: start + b1_end,
                },
                RawBacking::Owned(vec) => RawBacking::Owned(vec[b1_start..b1_end].to_vec()),
            };
            let inst = opaque_cls.call1((PyBytes::new(py, b""),))?;
            inst.cast::<OpaqueView>()?.borrow_mut().backing = sub_backing;
            Ok(inst)
        }
    }

    pub fn _get_scalar_array<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        exp_elem_wt: u8,
        elem_kind_code: u8,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let Some(elem_kind) = ScalarKind::from_code(elem_kind_code) else {
            return Ok(PyList::empty(py).into_any());
        };
        let slice = self.backing.as_slice(py);
        let out = PyList::empty(py);
        let mut pos = 0usize;
        while pos < slice.len() {
            let (matched, valid) = next_container_u32(slice, pos, fnum, WIRE_ARRAY, 2);
            if !valid {
                return Ok(PyList::empty(py).into_any());
            }
            let Some((b_start, b_end, next_pos)) = matched else {
                break;
            };
            pos = next_pos;
            let body = &slice[b_start..b_end];
            let Some((ewt, count, mut p)) = parse_array_header(body) else {
                return Ok(PyList::empty(py).into_any());
            };
            if ewt != exp_elem_wt {
                return Ok(PyList::empty(py).into_any());
            }
            for _ in 0..count {
                let Ok((val_obj, next_p)) = read_scalar_payload(py, body, p, elem_kind, None)
                else {
                    return Ok(PyList::empty(py).into_any());
                };
                p = next_p;
                out.append(val_obj)?;
            }
            if p != body.len() {
                return Ok(PyList::empty(py).into_any());
            }
        }
        Ok(out.into_any())
    }

    pub fn _get_submsg_array<'py>(
        &self,
        py: Python<'py>,
        fnum: u32,
        sub_codec: &CompiledCodec,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let slice = self.backing.as_slice(py);
        let out = PyList::empty(py);
        let mut pos = 0usize;
        while pos < slice.len() {
            let (matched, valid) = next_container_u32(slice, pos, fnum, WIRE_ARRAY, 2);
            if !valid {
                return Ok(PyList::empty(py).into_any());
            }
            let Some((b_start, b_end, next_pos)) = matched else {
                break;
            };
            pos = next_pos;
            let body = &slice[b_start..b_end];
            let Some((ewt, count, mut p)) = parse_array_header(body) else {
                return Ok(PyList::empty(py).into_any());
            };
            if ewt != WIRE_SUB_MSG {
                return Ok(PyList::empty(py).into_any());
            }
            for _ in 0..count {
                let Ok((elem_slice, next_p)) = read_len_slice(body, p, 0) else {
                    return Ok(PyList::empty(py).into_any());
                };
                p = next_p;
                let Ok(elem_obj) = sub_codec.decode_slice(py, elem_slice, None, 2, false) else {
                    return Ok(PyList::empty(py).into_any());
                };
                out.append(elem_obj)?;
            }
            if p != body.len() {
                return Ok(PyList::empty(py).into_any());
            }
        }
        Ok(out.into_any())
    }

    #[pyo3(signature = (fnum, exp_key_wt, key_kind_code, exp_val_wt, val_kind_code, sub_codec=None))]
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
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(d) = self.find_dirty(py, fnum) {
            return Ok(d);
        }
        let Some(key_kind) = ScalarKind::from_code(key_kind_code) else {
            return Ok(PyDict::new(py).into_any());
        };
        let val_scalar_kind = if sub_codec.is_none() {
            let Some(vk) = ScalarKind::from_code(val_kind_code) else {
                return Ok(PyDict::new(py).into_any());
            };
            Some(vk)
        } else {
            None
        };

        let slice = self.backing.as_slice(py);
        let out = PyDict::new(py);
        let mut pos = 0usize;
        while pos < slice.len() {
            let (matched, valid) = next_container_u32(slice, pos, fnum, WIRE_MAP, 3);
            if !valid {
                return Ok(PyDict::new(py).into_any());
            }
            let Some((b_start, b_end, next_pos)) = matched else {
                break;
            };
            pos = next_pos;
            let body = &slice[b_start..b_end];
            let Some((kwt, vwt, count, mut p)) = parse_map_header(body) else {
                return Ok(PyDict::new(py).into_any());
            };
            if kwt != exp_key_wt || vwt != exp_val_wt {
                return Ok(PyDict::new(py).into_any());
            }
            for _ in 0..count {
                let Ok((k_obj, after_k)) = read_scalar_payload(py, body, p, key_kind, None) else {
                    return Ok(PyDict::new(py).into_any());
                };
                let (v_obj, after_v) = if let Some(sc) = sub_codec {
                    let Ok((v_slice, vp)) = read_len_slice(body, after_k, 0) else {
                        return Ok(PyDict::new(py).into_any());
                    };
                    let Ok(msg_v) = sc.decode_slice(py, v_slice, None, 2, false) else {
                        return Ok(PyDict::new(py).into_any());
                    };
                    (msg_v, vp)
                } else {
                    let Ok(res) =
                        read_scalar_payload(py, body, after_k, val_scalar_kind.unwrap(), None)
                    else {
                        return Ok(PyDict::new(py).into_any());
                    };
                    res
                };
                p = after_v;
                out.set_item(k_obj, v_obj)?;
            }
            if p != body.len() {
                return Ok(PyDict::new(py).into_any());
            }
        }
        Ok(out.into_any())
    }

    pub fn _set_uint64(
        &mut self,
        py: Python<'_>,
        fnum: u32,
        val: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        if self.dirty_objs.is_empty() && fnum < 64 {
            let v = extract_u64(py, val.as_ptr(), "uint64")?;
            if let Some((prev_fnum, prev_u64)) = self.fast_u64.take()
                && prev_fnum != fnum
            {
                unsafe {
                    let p = ffi::PyLong_FromUnsignedLongLong(prev_u64);
                    let bound = Bound::from_owned_ptr_or_err(py, p)?;
                    self.dirty_objs.push((prev_fnum, bound.unbind()));
                }
                self.record_dirty_obj(py, fnum, val.clone().unbind());
                return Ok(());
            }
            self.dirty_mask |= 1u64 << fnum;
            self.fast_u64 = Some((fnum, v));
            return Ok(());
        }
        self.record_dirty_obj(py, fnum, val.clone().unbind());
        Ok(())
    }

    pub fn _set_dirty(&mut self, py: Python<'_>, fnum: u32, val: Py<PyAny>) {
        self.record_dirty_obj(py, fnum, val);
    }

    #[pyo3(signature = (codec, *, dst_prefix=None, self_describing=false))]
    pub fn _marshal_with_codec<'py>(
        &mut self,
        py: Python<'py>,
        codec: &CompiledCodec,
        dst_prefix: Option<&Bound<'py, PyAny>>,
        self_describing: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let has_dirty = self.fast_u64.is_some() || !self.dirty_objs.is_empty();

        if !has_dirty {
            let src = self.backing.as_slice(py);
            validate_message(src, 0).map_err(|e| decode_err(py, e.to_string()))?;
            if dst_prefix.is_none() && !self_describing {
                return Ok(self.backing.to_py_bytes(py));
            }
            let mut out = Vec::with_capacity(src.len() + 64);
            if let Some(p_obj) = dst_prefix {
                let pb = BorrowedBytes::extract(py, p_obj.as_ptr())?;
                out.extend_from_slice(pb.as_slice());
            }
            if self_describing && read_field0_schema_meta(src).is_none() {
                out.extend_from_slice(codec.field0_bytes());
            }
            out.extend_from_slice(src);
            return Ok(PyBytes::new(py, &out));
        }

        if let Some((target_fnum, val_u64)) = self.fast_u64
            && self.dirty_objs.is_empty()
            && dst_prefix.is_none()
            && !self_describing
            && let Some(fast_bytes) = self.splice_single_u64_fast(py, target_fnum, val_u64)?
        {
            return Ok(fast_bytes);
        }

        if let Some((fnum_u64, val_u64)) = self.fast_u64.take() {
            unsafe {
                let p = ffi::PyLong_FromUnsignedLongLong(val_u64);
                let bound = Bound::from_owned_ptr_or_err(py, p)?;
                self.dirty_objs.push((fnum_u64, bound.unbind()));
            }
        }
        self.dirty_objs.sort_by_key(|(fnum, _)| *fnum);

        let spliced_vec = {
            let src = self.backing.as_slice(py);
            let n = src.len();
            let mut spans: Vec<(u32, usize, usize)> = Vec::with_capacity(16);
            let mut last_idx: Vec<Option<usize>> = vec![None; self.dirty_objs.len()];
            let mut pos = 0usize;

            while pos < n {
                let f_start = pos;
                let (fnum, wt, after_tag) = read_tag_at(src, pos)
                    .ok_or_else(|| decode_err(py, format!("omnibuf: invalid tag at byte {pos}")))?;
                pos = after_tag;

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

                let span_i = spans.len();
                spans.push((fnum, f_start, next_pos));
                if let Ok(d_idx) = self.dirty_objs.binary_search_by_key(&fnum, |(k, _)| *k) {
                    last_idx[d_idx] = Some(span_i);
                }
                pos = next_pos;
            }

            let mut enc = Encoder::new(n + 128);
            let mut emitted = vec![false; self.dirty_objs.len()];
            let mut copy_start = 0usize;

            for (idx, &(fnum, f_start, f_end)) in spans.iter().enumerate() {
                let Ok(d_idx) = self.dirty_objs.binary_search_by_key(&fnum, |(k, _)| *k) else {
                    continue;
                };
                if copy_start < f_start {
                    enc.write_raw(&src[copy_start..f_start]);
                }
                if last_idx[d_idx] == Some(idx) {
                    let val_bound = self.dirty_objs[d_idx].1.bind(py);
                    codec.encode_single_field(py, &mut enc, fnum, val_bound, true)?;
                    emitted[d_idx] = true;
                }
                copy_start = f_end;
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
        self.backing = RawBacking::PyBytes {
            owner: spliced_py.clone().unbind(),
            start: 0,
            end: spliced_vec.len(),
        };
        self.dirty_mask = 0;
        self.dirty_objs.clear();

        if dst_prefix.is_none() && !self_describing {
            return Ok(spliced_py);
        }

        let mut prefix_out = Vec::with_capacity(spliced_vec.len() + 64);
        if let Some(p_obj) = dst_prefix {
            let pb = BorrowedBytes::extract(py, p_obj.as_ptr())?;
            prefix_out.extend_from_slice(pb.as_slice());
        }
        if self_describing && read_field0_schema_meta(&spliced_vec).is_none() {
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_uint(b.as_slice(), field_num as u32).map_or(default, |v| v as u32))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_uint(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_sint(b.as_slice(), field_num as u32).map_or(default, |v| v as i32))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_sint(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_bool(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_fixed32(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_sfixed32(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_fixed64(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_sfixed64(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_float32(b.as_slice(), field_num as u32).map_or(default, f64::from))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    Ok(slice_read_float64(b.as_slice(), field_num as u32).unwrap_or(default))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    if let Some(s) = slice_read_str(b.as_slice(), field_num as u32) {
        Ok(PyString::new(py, s))
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
            let db = BorrowedBytes::extract(py, d.as_ptr())?;
            Ok(PyBytes::new(py, db.as_slice()))
        } else {
            Ok(PyBytes::new(py, b""))
        }
    };
    if field_num <= 0 || field_num > MAX_FIELD_NUMBER as i64 {
        return make_default();
    }
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    if let Some(found) = slice_read_bytes(b.as_slice(), field_num as u32) {
        Ok(PyBytes::new(py, found))
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
    let b = BorrowedBytes::extract(py, raw.as_ptr())?;
    let slice = b.as_slice();
    if let Ok(f16) = u16::try_from(field_num as u32) {
        return Ok(read_sub_msg(slice, f16).map(|cow| PyBytes::new(py, &cow)));
    }
    let (first, ok1) = next_container_u32(slice, 0, field_num as u32, WIRE_SUB_MSG, 0);
    if !ok1 {
        return Ok(None);
    }
    let Some((b1_s, b1_e, mut pos)) = first else {
        return Ok(None);
    };
    let mut merged: Option<Vec<u8>> = None;
    while pos < slice.len() {
        let (nxt, ok) = next_container_u32(slice, pos, field_num as u32, WIRE_SUB_MSG, 0);
        if !ok {
            return Ok(None);
        }
        let Some((bn_s, bn_e, next_p)) = nxt else {
            break;
        };
        pos = next_p;
        let vec = merged.get_or_insert_with(|| slice[b1_s..b1_e].to_vec());
        vec.extend_from_slice(&slice[bn_s..bn_e]);
    }
    if let Some(m) = merged {
        Ok(Some(PyBytes::new(py, &m)))
    } else {
        Ok(Some(PyBytes::new(py, &slice[b1_s..b1_e])))
    }
}
