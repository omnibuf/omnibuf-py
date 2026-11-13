"""Runtime helpers for generated Opaque<Message> lazy views and in-place field splicing."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Any

from .wire import (
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_BOOL_TRUE,
    WIRE_BYTES,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_FLOAT32,
    WIRE_FLOAT64,
    WIRE_MAP,
    WIRE_SFIXED32,
    WIRE_SFIXED64,
    WIRE_SINT,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Buffer,
    OmniBufDecodeError,
    SpliceField,
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    locate_field,
    next_container_field,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    skip_value,
    splice_fields,
    to_uint32,
    validate_field0_at,
    validate_message,
)

_U32_UNPACK = struct.Struct("<I").unpack_from
_I32_UNPACK = struct.Struct("<i").unpack_from
_U64_UNPACK = struct.Struct("<Q").unpack_from
_I64_UNPACK = struct.Struct("<q").unpack_from
_F32_UNPACK = struct.Struct("<f").unpack_from
_F64_UNPACK = struct.Struct("<d").unpack_from

_MASK_UINT = 1 << WIRE_UINT
_MASK_SINT = 1 << WIRE_SINT
_MASK_BOOL = (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE)
_MASK_FIXED32 = 1 << WIRE_FIXED32
_MASK_SFIXED32 = 1 << WIRE_SFIXED32
_MASK_FIXED64 = 1 << WIRE_FIXED64
_MASK_SFIXED64 = 1 << WIRE_SFIXED64
_MASK_FLOAT32 = 1 << WIRE_FLOAT32
_MASK_FLOAT64 = 1 << WIRE_FLOAT64
_MASK_STRING = 1 << WIRE_STRING
_MASK_BYTES = 1 << WIRE_BYTES
_MASK_SUBMSG = 1 << WIRE_SUB_MSG


def opaque_get_uint32(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_UINT)
    if not loc.ok:
        return default
    v, w = decode_varint(loc.val_slice, 0)
    return to_uint32(v) if w > 0 else default


def opaque_get_uint64(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_UINT)
    if not loc.ok:
        return default
    v, w = decode_varint(loc.val_slice, 0)
    return v if w > 0 else default


def opaque_get_sint32(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_SINT)
    if not loc.ok:
        return default
    v, w = decode_varint(loc.val_slice, 0)
    return decode_zigzag32(v) if w > 0 else default


def opaque_get_sint64(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_SINT)
    if not loc.ok:
        return default
    v, w = decode_varint(loc.val_slice, 0)
    return decode_zigzag(v) if w > 0 else default


def opaque_get_bool(raw: Buffer, field_num: int, default: bool = False) -> bool:
    loc = locate_field(raw, field_num, _MASK_BOOL)
    if not loc.ok:
        return default
    return loc.wire_type == WIRE_BOOL_TRUE


def opaque_get_fixed32(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_FIXED32)
    if not loc.ok or len(loc.val_slice) < 4:
        return default
    (u32,) = _U32_UNPACK(loc.val_slice, 0)
    return int(u32)


def opaque_get_sfixed32(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_SFIXED32)
    if not loc.ok or len(loc.val_slice) < 4:
        return default
    (i32,) = _I32_UNPACK(loc.val_slice, 0)
    return int(i32)


def opaque_get_fixed64(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_FIXED64)
    if not loc.ok or len(loc.val_slice) < 8:
        return default
    (u64,) = _U64_UNPACK(loc.val_slice, 0)
    return int(u64)


def opaque_get_sfixed64(raw: Buffer, field_num: int, default: int = 0) -> int:
    loc = locate_field(raw, field_num, _MASK_SFIXED64)
    if not loc.ok or len(loc.val_slice) < 8:
        return default
    (i64,) = _I64_UNPACK(loc.val_slice, 0)
    return int(i64)


def opaque_get_float32(raw: Buffer, field_num: int, default: float = 0.0) -> float:
    loc = locate_field(raw, field_num, _MASK_FLOAT32)
    if not loc.ok or len(loc.val_slice) < 4:
        return default
    (f32,) = _F32_UNPACK(loc.val_slice, 0)
    return float(f32)


def opaque_get_float64(raw: Buffer, field_num: int, default: float = 0.0) -> float:
    loc = locate_field(raw, field_num, _MASK_FLOAT64)
    if not loc.ok or len(loc.val_slice) < 8:
        return default
    (f64,) = _F64_UNPACK(loc.val_slice, 0)
    return float(f64)


def opaque_get_string(raw: Buffer, field_num: int, default: str = "") -> str:
    loc = locate_field(raw, field_num, _MASK_STRING)
    if not loc.ok:
        return default
    try:
        s_slice, _ = read_len_slice(loc.val_slice, 0, 0)
        return decode_utf8_strict(s_slice, loc.val_pos)
    except OmniBufDecodeError:
        return default


def opaque_get_bytes(raw: Buffer, field_num: int, default: bytes = b"") -> bytes:
    loc = locate_field(raw, field_num, _MASK_BYTES)
    if not loc.ok:
        return default
    try:
        b_slice, _ = read_len_slice(loc.val_slice, 0, 0)
        return bytes(b_slice)
    except OmniBufDecodeError:
        return default


def opaque_get_submsg_slice(raw: Buffer, field_num: int) -> Buffer | None:
    """Returns the sub-message payload slice (concatenating if multiple occurrences exist)."""
    first = next_container_field(raw, 0, field_num, WIRE_SUB_MSG, 0)
    if not first.valid or not first.matched:
        return None
    second = next_container_field(raw, first.next_pos, field_num, WIRE_SUB_MSG, 0)
    if not second.valid:
        return None
    if not second.matched:
        return first.body
    merged = bytearray(first.body)
    merged.extend(second.body)
    pos = second.next_pos
    while pos < len(raw):
        nxt = next_container_field(raw, pos, field_num, WIRE_SUB_MSG, 0)
        if not nxt.valid:
            return None
        if not nxt.matched:
            break
        merged.extend(nxt.body)
        pos = nxt.next_pos
    return merged


def opaque_get_submsg[T](
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, T | None, int, bool], T],
) -> T | None:
    """Lazily decodes all occurrences of a singular sub-message field (merging duplicates)."""
    pos = 0
    result: T | None = None
    while pos < len(raw):
        res = next_container_field(raw, pos, field_num, WIRE_SUB_MSG, 0)
        if not res.valid:
            return None
        if not res.matched:
            break
        try:
            result = decode_fn(res.body, result, 1, result is not None)
        except OmniBufDecodeError:
            return None
        pos = res.next_pos
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
) -> list[Any]:
    out: list[Any] = []
    pos = 0
    while pos < len(raw):
        res = next_container_field(raw, pos, field_num, WIRE_ARRAY, 2)
        if not res.valid:
            return []
        if not res.matched:
            break
        elem_wt, count, p, ok = parse_array_header(res.body)
        if not ok or elem_wt != exp_elem_wt:
            return []
        end = len(res.body)
        try:
            for _ in range(count):
                val, p = _read_scalar_elem(res.body, p, end, elem_kind)
                out.append(val)
        except OmniBufDecodeError:
            return []
        if p != end:
            return []
        pos = res.next_pos
    return out


def opaque_get_submsg_array[T](
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, T | None, int, bool], T],
) -> list[T]:
    out: list[T] = []
    pos = 0
    while pos < len(raw):
        res = next_container_field(raw, pos, field_num, WIRE_ARRAY, 2)
        if not res.valid:
            return []
        if not res.matched:
            break
        elem_wt, count, p, ok = parse_array_header(res.body)
        if not ok or elem_wt != WIRE_SUB_MSG:
            return []
        end = len(res.body)
        try:
            for _ in range(count):
                elem_mv, p = read_len_slice(res.body, p, 0, end)
                out.append(decode_fn(elem_mv, None, 2, False))
        except OmniBufDecodeError:
            return []
        if p != end:
            return []
        pos = res.next_pos
    return out


def opaque_get_map(
    raw: Buffer,
    field_num: int,
    exp_key_wt: int,
    key_kind: str,
    exp_val_wt: int,
    val_kind: str,
    sub_decode_fn: Callable[[Buffer, Any, int, bool], Any] | None = None,
) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    pos = 0
    while pos < len(raw):
        res = next_container_field(raw, pos, field_num, WIRE_MAP, 3)
        if not res.valid:
            return {}
        if not res.matched:
            break
        key_wt, val_wt, count, p, ok = parse_map_header(res.body)
        if not ok or key_wt != exp_key_wt or val_wt != exp_val_wt:
            return {}
        end = len(res.body)
        try:
            for _ in range(count):
                k, p = _read_scalar_elem(res.body, p, end, key_kind)
                if val_kind == "submsg":
                    assert sub_decode_fn is not None
                    v_mv, p = read_len_slice(res.body, p, 0, end)
                    out[k] = sub_decode_fn(v_mv, None, 2, False)
                else:
                    v, p = _read_scalar_elem(res.body, p, end, val_kind)
                    out[k] = v
        except OmniBufDecodeError:
            return {}
        if p != end:
            return {}
        pos = res.next_pos
    return out


def splice_dirty_fields(
    dst_prefix: Buffer | None,
    src_packet: Buffer,
    dirty_nums: set[int],
    encode_one_field: Callable[[bytearray, int], None],
) -> bytes:
    """Fast single-pass field splicer used by Opaque<Message>.marshal()."""
    if not dirty_nums:
        validate_message(src_packet)
        if dst_prefix is None:
            return bytes(src_packet)
        out = bytearray(dst_prefix)
        out.extend(src_packet)
        return bytes(out)

    # Fast single-pass scan tracking spans to replace at last matching occurrence.
    mv = memoryview(src_packet)
    n = len(mv)
    out = bytearray(dst_prefix) if dst_prefix is not None else bytearray()

    spans: list[tuple[int, int, int]] = []
    last_idx: dict[int, int] = {}
    pos = 0
    while pos < n:
        f_start = pos
        b0 = mv[pos]
        if b0 & 1:
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
            pos += 1
        elif b0 & 2:
            if pos + 2 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated tag at byte {pos}")
            u16 = (b0 | (mv[pos + 1] << 8)) >> 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
            pos += 2
        else:
            tag, tn = decode_varint(mv, pos, n)
            if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {pos}")
            fnum = tag >> 4
            wt = tag & 0x0F
            pos += tn

        if fnum == 0:
            next_pos = validate_field0_at(mv, pos, wt, 0, MAX_NESTING_DEPTH, n)
        else:
            next_pos = skip_value(mv, pos, wt, n)
        idx = len(spans)
        spans.append((fnum, f_start, next_pos))
        if fnum in dirty_nums:
            last_idx[fnum] = idx
        pos = next_pos

    emitted: set[int] = set()
    copy_start = 0
    for idx, (fnum, f_start, f_end) in enumerate(spans):
        if fnum not in dirty_nums:
            continue
        if copy_start < f_start:
            out.extend(mv[copy_start:f_start])
        if last_idx.get(fnum) == idx:
            encode_one_field(out, fnum)
            emitted.add(fnum)
        copy_start = f_end

    if copy_start < n:
        out.extend(mv[copy_start:n])

    for fnum in sorted(dirty_nums):
        if fnum not in emitted:
            encode_one_field(out, fnum)

    return bytes(out)


__all__ = [
    "SpliceField",
    "opaque_get_bool",
    "opaque_get_bytes",
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
