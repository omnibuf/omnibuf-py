"""Runtime helpers for generated Opaque<Message> lazy views and in-place field splicing."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Any, TypeVar

from . import _omnibuf_ext
from ._omnibuf_ext import OpaqueView
from .wire import (
    DEFAULT_MAX_ELEMENTS,
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    WIRE_ARRAY,
    WIRE_BYTES,
    WIRE_MAP,
    WIRE_SUB_MSG,
    Buffer,
    OmniBufDecodeError,
    OmniBufEncodeError,
    SpliceField,
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    next_container_span,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    splice_fields,
    to_uint32,
    validate_field0_at,
    validate_message,
    validate_value,
)

_U32_UNPACK = struct.Struct("<I").unpack_from
_I32_UNPACK = struct.Struct("<i").unpack_from
_U64_UNPACK = struct.Struct("<Q").unpack_from
_I64_UNPACK = struct.Struct("<q").unpack_from
_F32_UNPACK = struct.Struct("<f").unpack_from
_F64_UNPACK = struct.Struct("<d").unpack_from

_T = TypeVar("_T")

opaque_get_uint32 = _omnibuf_ext.opaque_get_uint32_py
opaque_get_uint64 = _omnibuf_ext.opaque_get_uint64_py
opaque_get_sint32 = _omnibuf_ext.opaque_get_sint32_py
opaque_get_sint64 = _omnibuf_ext.opaque_get_sint64_py
opaque_get_bool = _omnibuf_ext.opaque_get_bool_py
opaque_get_fixed32 = _omnibuf_ext.opaque_get_fixed32_py
opaque_get_sfixed32 = _omnibuf_ext.opaque_get_sfixed32_py
opaque_get_fixed64 = _omnibuf_ext.opaque_get_fixed64_py
opaque_get_sfixed64 = _omnibuf_ext.opaque_get_sfixed64_py
opaque_get_float32 = _omnibuf_ext.opaque_get_float32_py
opaque_get_float64 = _omnibuf_ext.opaque_get_float64_py
opaque_get_string = _omnibuf_ext.opaque_get_string_py


def opaque_get_bytes(raw: Buffer, field_num: int, default: bytes = b"") -> bytes:
    return _omnibuf_ext.opaque_get_bytes_py(raw, field_num, default)


def opaque_get_bytes_view(raw: Buffer, field_num: int) -> memoryview:
    """Returns a zero-copy read-only memoryview slice over a WireBytes field payload."""
    if isinstance(field_num, bool) or field_num <= 0 or field_num > MAX_FIELD_NUMBER:
        return memoryview(b"")
    pos = 0
    n = len(raw)
    last_start = -1
    last_end = 0
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_BYTES, 0)
        if b_start == -2:
            raise OmniBufDecodeError(
                f"omnibuf: malformed packet while reading bytes field #{field_num}"
            )
        if b_start == -1:
            break
        last_start = b_start
        last_end = b_end
    if last_start < 0:
        return memoryview(b"")
    return memoryview(raw)[last_start:last_end].toreadonly()


def opaque_get_submsg_slice(raw: Buffer, field_num: int) -> Buffer | None:
    """Returns the sub-message payload slice (concatenating if multiple occurrences exist)."""
    return _omnibuf_ext.opaque_get_submsg_slice_py(raw, field_num)


def opaque_get_submsg(
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, _T | None, int, bool], _T],
) -> _T | None:
    """Lazily decodes all occurrences of a singular sub-message field (merging duplicates)."""
    pos = 0
    n = len(raw)
    result: _T | None = None
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_SUB_MSG, 0)
        if b_start == -2:
            raise OmniBufDecodeError(
                f"omnibuf: malformed packet while reading submsg field #{field_num}"
            )
        if b_start == -1:
            break
        result = decode_fn(raw[b_start:b_end], result, 1, result is not None)
    return result


def _read_scalar_elem(mv: memoryview, pos: int, end: int, kind: str) -> tuple[Any, int]:
    if kind == "bool":
        if pos >= end or mv[pos] > 1:
            raise OmniBufDecodeError("omnibuf: invalid bool element")
        return (mv[pos] == 1), pos + 1
    if kind == "uint32":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError("omnibuf: invalid uint32 element")
        return to_uint32(v), pos + w
    if kind == "uint64":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError("omnibuf: invalid uint64 element")
        return v, pos + w
    if kind == "sint32":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError("omnibuf: invalid sint32 element")
        return decode_zigzag32(v), pos + w
    if kind == "sint64":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError("omnibuf: invalid sint64 element")
        return decode_zigzag(v), pos + w
    if kind == "fixed32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated fixed32 element")
        (u32,) = _U32_UNPACK(mv, pos)
        return int(u32), pos + 4
    if kind == "sfixed32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated sfixed32 element")
        (i32,) = _I32_UNPACK(mv, pos)
        return int(i32), pos + 4
    if kind == "fixed64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated fixed64 element")
        (u64,) = _U64_UNPACK(mv, pos)
        return int(u64), pos + 8
    if kind == "sfixed64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated sfixed64 element")
        (i64,) = _I64_UNPACK(mv, pos)
        return int(i64), pos + 8
    if kind == "float32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated float32 element")
        (f32,) = _F32_UNPACK(mv, pos)
        return float(f32), pos + 4
    if kind == "float64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated float64 element")
        (f64,) = _F64_UNPACK(mv, pos)
        return float(f64), pos + 8
    if kind == "string":
        s_pos = pos
        s_mv, next_pos = read_len_slice(mv, pos, 0, end)
        return decode_utf8_strict(s_mv, s_pos), next_pos
    if kind == "bytes":
        b_mv, next_pos = read_len_slice(mv, pos, 0, end)
        return bytes(b_mv), next_pos
    raise OmniBufDecodeError(f"omnibuf: unsupported element kind {kind!r}")


def opaque_get_scalar_array(
    raw: Buffer,
    field_num: int,
    exp_elem_wt: int,
    elem_kind: str,
    *,
    max_elements: int = DEFAULT_MAX_ELEMENTS,
) -> list[Any]:
    out: list[Any] = []
    pos = 0
    n = len(raw)
    total_elems = 0
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_ARRAY, 2)
        if b_start == -2:
            raise OmniBufDecodeError(
                f"omnibuf: malformed packet while reading array field #{field_num}"
            )
        if b_start == -1:
            break
        body_mv = memoryview(raw)[b_start:b_end]
        elem_wt, count, p, ok = parse_array_header(body_mv)
        if not ok or elem_wt != exp_elem_wt:
            raise OmniBufDecodeError(f"omnibuf: invalid WireArray header on field #{field_num}")
        total_elems += count
        if total_elems > max_elements:
            raise OmniBufDecodeError(
                f"omnibuf: container element count {total_elems} exceeds max_elements {max_elements}"
            )
        end = len(body_mv)
        for _ in range(count):
            val, p = _read_scalar_elem(body_mv, p, end, elem_kind)
            out.append(val)
        if p != end:
            raise OmniBufDecodeError(f"omnibuf: trailing WireArray bytes on field #{field_num}")
    return out


def opaque_get_submsg_array(
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, _T | None, int, bool], _T],
    *,
    max_elements: int = DEFAULT_MAX_ELEMENTS,
) -> list[_T]:
    out: list[_T] = []
    pos = 0
    n = len(raw)
    total_elems = 0
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_ARRAY, 2)
        if b_start == -2:
            raise OmniBufDecodeError(
                f"omnibuf: malformed packet while reading submsg array field #{field_num}"
            )
        if b_start == -1:
            break
        body = raw[b_start:b_end]
        elem_wt, count, p, ok = parse_array_header(body)
        if not ok or elem_wt != WIRE_SUB_MSG:
            raise OmniBufDecodeError(
                f"omnibuf: invalid WireArray<WireSubMsg> header on field #{field_num}"
            )
        total_elems += count
        if total_elems > max_elements:
            raise OmniBufDecodeError(
                f"omnibuf: container element count {total_elems} exceeds max_elements {max_elements}"
            )
        end = len(body)
        for _ in range(count):
            elem_mv, p = read_len_slice(body, p, 0, end)
            out.append(decode_fn(elem_mv, None, 2, False))
        if p != end:
            raise OmniBufDecodeError(
                f"omnibuf: trailing WireArray<WireSubMsg> bytes on field #{field_num}"
            )
    return out


def opaque_get_map(
    raw: Buffer,
    field_num: int,
    exp_key_wt: int,
    key_kind: str,
    exp_val_wt: int,
    val_kind: str,
    sub_decode_fn: Callable[[Buffer, Any, int, bool], Any] | None = None,
    *,
    max_elements: int = DEFAULT_MAX_ELEMENTS,
) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    pos = 0
    n = len(raw)
    total_elems = 0
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_MAP, 3)
        if b_start == -2:
            raise OmniBufDecodeError(
                f"omnibuf: malformed packet while reading map field #{field_num}"
            )
        if b_start == -1:
            break
        body_mv = memoryview(raw)[b_start:b_end]
        key_wt, val_wt, count, p, ok = parse_map_header(body_mv)
        if not ok or key_wt != exp_key_wt or val_wt != exp_val_wt:
            raise OmniBufDecodeError(f"omnibuf: invalid WireMap header on field #{field_num}")
        total_elems += count
        if total_elems > max_elements:
            raise OmniBufDecodeError(
                f"omnibuf: container element count {total_elems} exceeds max_elements {max_elements}"
            )
        end = len(body_mv)
        for _ in range(count):
            k, p = _read_scalar_elem(body_mv, p, end, key_kind)
            if val_kind == "submsg":
                assert sub_decode_fn is not None
                v_mv, p = read_len_slice(body_mv, p, 0, end)
                out[k] = sub_decode_fn(v_mv, None, 2, False)
            else:
                v, p = _read_scalar_elem(body_mv, p, end, val_kind)
                out[k] = v
        if p != end:
            raise OmniBufDecodeError(f"omnibuf: trailing WireMap bytes on field #{field_num}")
    return out


def _normalize_dirty_set(dirty_nums: set[int] | int) -> set[int]:
    if isinstance(dirty_nums, bool):
        raise OmniBufEncodeError("omnibuf: dirty_nums cannot be bool")
    if isinstance(dirty_nums, int):
        if dirty_nums < 0:
            raise OmniBufEncodeError(f"omnibuf: negative dirty_nums bitmask {dirty_nums}")
        if dirty_nums & 1:
            raise OmniBufEncodeError("omnibuf: Field #0 cannot be spliced via dirty_nums")
        if dirty_nums == 0:
            return set()
        if (dirty_nums.bit_length() - 1) > MAX_FIELD_NUMBER:
            raise OmniBufEncodeError("omnibuf: dirty_nums field number exceeds MAX_FIELD_NUMBER")
        out: set[int] = set()
        rem = dirty_nums
        while rem:
            lsb = rem & -rem
            out.add(lsb.bit_length() - 1)
            rem ^= lsb
        return out
    out_set: set[int] = set()
    for item in dirty_nums:
        if isinstance(item, bool) or not isinstance(item, int):
            raise OmniBufEncodeError(f"omnibuf: invalid splice field number {item!r}")
        if item <= 0 or item > MAX_FIELD_NUMBER:
            raise OmniBufEncodeError(f"omnibuf: invalid splice field number {item}")
        out_set.add(item)
    return out_set


def splice_dirty_fields(
    dst_prefix: Buffer | None,
    src_packet: Buffer,
    dirty_nums: set[int] | int,
    encode_one_field: Callable[[bytearray, int], None],
) -> bytes:
    """Fast single-pass field splicer used by Opaque<Message>.marshal()."""
    dirty_set = _normalize_dirty_set(dirty_nums)
    if not dirty_set:
        validate_message(src_packet)
        if dst_prefix is None:
            return bytes(src_packet)
        out = bytearray(dst_prefix)
        out.extend(src_packet)
        return bytes(out)

    n = len(src_packet)
    out = bytearray(dst_prefix) if dst_prefix is not None else bytearray()
    spans: list[tuple[int, int, int]] = []
    last_idx: dict[int, int] = {}
    pos = 0
    while pos < n:
        f_start = pos
        b0 = src_packet[pos]
        if b0 & 1:
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
            pos += 1
        elif b0 & 2:
            if pos + 2 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated tag at byte {pos}")
            u16 = (b0 | (src_packet[pos + 1] << 8)) >> 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
            pos += 2
        else:
            tag, tn = decode_varint(src_packet, pos, n)
            if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {pos}")
            fnum = tag >> 4
            wt = tag & 0x0F
            pos += tn

        if fnum == 0:
            next_pos = validate_field0_at(src_packet, pos, wt, 0, MAX_NESTING_DEPTH, n)
        else:
            next_pos = validate_value(src_packet, pos, wt, 0, MAX_NESTING_DEPTH, n, check_utf8=True)
        idx = len(spans)
        spans.append((fnum, f_start, next_pos))
        if fnum in dirty_set:
            last_idx[fnum] = idx
        pos = next_pos

    emitted: set[int] = set()
    copy_start = 0
    for idx, (fnum, f_start, f_end) in enumerate(spans):
        if fnum not in dirty_set:
            continue
        if copy_start < f_start:
            out.extend(src_packet[copy_start:f_start])
        if last_idx.get(fnum) == idx:
            encode_one_field(out, fnum)
            emitted.add(fnum)
        copy_start = f_end

    if copy_start < n:
        out.extend(src_packet[copy_start:n])

    for fnum in sorted(dirty_set):
        if fnum not in emitted:
            encode_one_field(out, fnum)

    return bytes(out)


__all__ = [
    "OpaqueView",
    "SpliceField",
    "opaque_get_bool",
    "opaque_get_bytes",
    "opaque_get_bytes_view",
    "opaque_get_fixed32",
    "opaque_get_fixed64",
    "opaque_get_float32",
    "opaque_get_float64",
    "opaque_get_map",
    "opaque_get_scalar_array",
    "opaque_get_sfixed32",
    "opaque_get_sfixed64",
    "opaque_get_sint32",
    "opaque_get_sint64",
    "opaque_get_string",
    "opaque_get_submsg",
    "opaque_get_submsg_array",
    "opaque_get_submsg_slice",
    "opaque_get_uint32",
    "opaque_get_uint64",
    "splice_dirty_fields",
    "splice_fields",
]
