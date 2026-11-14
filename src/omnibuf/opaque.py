"""Runtime helpers for generated Opaque<Message> lazy views and in-place field splicing."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Any

from .wire import (
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    TZCNT_WIDTH_TABLE,
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
    locate_field_offset,
    next_container_span,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    skip_validated_value,
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
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_UINT)
    if val_pos < 0:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        return b0 >> 1
    v, w = decode_varint(raw, val_pos)
    return to_uint32(v) if w > 0 else default


def opaque_get_uint64(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_UINT)
    if val_pos < 0:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        return b0 >> 1
    v, w = decode_varint(raw, val_pos)
    return v if w > 0 else default


def opaque_get_sint32(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_SINT)
    if val_pos < 0:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        u = b0 >> 1
        return (u >> 1) ^ -(u & 1)
    v, w = decode_varint(raw, val_pos)
    return decode_zigzag32(v) if w > 0 else default


def opaque_get_sint64(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_SINT)
    if val_pos < 0:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        u = b0 >> 1
        return (u >> 1) ^ -(u & 1)
    v, w = decode_varint(raw, val_pos)
    return decode_zigzag(v) if w > 0 else default


def opaque_get_bool(raw: Buffer, field_num: int, default: bool = False) -> bool:
    val_pos, wt = locate_field_offset(raw, field_num, _MASK_BOOL)
    if val_pos < 0:
        return default
    return wt == WIRE_BOOL_TRUE


def opaque_get_fixed32(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_FIXED32)
    if val_pos < 0 or len(raw) - val_pos < 4:
        return default
    (u32,) = _U32_UNPACK(raw, val_pos)
    return int(u32)


def opaque_get_sfixed32(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_SFIXED32)
    if val_pos < 0 or len(raw) - val_pos < 4:
        return default
    (i32,) = _I32_UNPACK(raw, val_pos)
    return int(i32)


def opaque_get_fixed64(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_FIXED64)
    if val_pos < 0 or len(raw) - val_pos < 8:
        return default
    (u64,) = _U64_UNPACK(raw, val_pos)
    return int(u64)


def opaque_get_sfixed64(raw: Buffer, field_num: int, default: int = 0) -> int:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_SFIXED64)
    if val_pos < 0 or len(raw) - val_pos < 8:
        return default
    (i64,) = _I64_UNPACK(raw, val_pos)
    return int(i64)


def opaque_get_float32(raw: Buffer, field_num: int, default: float = 0.0) -> float:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_FLOAT32)
    if val_pos < 0 or len(raw) - val_pos < 4:
        return default
    (f32,) = _F32_UNPACK(raw, val_pos)
    return float(f32)


def opaque_get_float64(raw: Buffer, field_num: int, default: float = 0.0) -> float:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_FLOAT64)
    if val_pos < 0 or len(raw) - val_pos < 8:
        return default
    (f64,) = _F64_UNPACK(raw, val_pos)
    return float(f64)


def opaque_get_string(raw: Buffer, field_num: int, default: str = "") -> str:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_STRING)
    if val_pos < 0:
        return default
    n = len(raw)
    if val_pos >= n:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        s_len = b0 >> 1
        s_start = val_pos + 1
    else:
        s_len, sn = decode_varint(raw, val_pos, n)
        if sn == 0:
            return default
        s_start = val_pos + sn
    s_end = s_start + s_len
    if s_end > n:
        return default
    chunk = raw[s_start:s_end]
    try:
        if isinstance(chunk, (bytes, bytearray)):
            return chunk.decode("utf-8")
        return bytes(chunk).decode("utf-8")
    except UnicodeDecodeError:
        return default


def opaque_get_bytes(raw: Buffer, field_num: int, default: bytes = b"") -> bytes:
    val_pos, _ = locate_field_offset(raw, field_num, _MASK_BYTES)
    if val_pos < 0:
        return default
    n = len(raw)
    if val_pos >= n:
        return default
    b0 = raw[val_pos]
    if b0 & 1:
        b_len = b0 >> 1
        b_start = val_pos + 1
    else:
        b_len, bn = decode_varint(raw, val_pos, n)
        if bn == 0:
            return default
        b_start = val_pos + bn
    b_end = b_start + b_len
    if b_end > n:
        return default
    return bytes(raw[b_start:b_end])


def opaque_get_submsg_slice(raw: Buffer, field_num: int) -> Buffer | None:
    """Returns the sub-message payload slice (concatenating if multiple occurrences exist)."""
    b1_start, b1_end, next_pos = next_container_span(raw, 0, field_num, WIRE_SUB_MSG, 0)
    if b1_start < 0:
        return None
    b2_start, b2_end, pos = next_container_span(raw, next_pos, field_num, WIRE_SUB_MSG, 0)
    if b2_start == -2:
        return None
    if b2_start == -1:
        return raw[b1_start:b1_end]
    merged = bytearray(raw[b1_start:b1_end])
    merged.extend(raw[b2_start:b2_end])
    n = len(raw)
    while pos < n:
        bn_start, bn_end, pos = next_container_span(raw, pos, field_num, WIRE_SUB_MSG, 0)
        if bn_start == -2:
            return None
        if bn_start == -1:
            break
        merged.extend(raw[bn_start:bn_end])
    return merged


def opaque_get_submsg[T](
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, T | None, int, bool], T],
) -> T | None:
    """Lazily decodes all occurrences of a singular sub-message field (merging duplicates)."""
    pos = 0
    n = len(raw)
    result: T | None = None
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_SUB_MSG, 0)
        if b_start == -2:
            return None
        if b_start == -1:
            break
        try:
            result = decode_fn(raw[b_start:b_end], result, 1, result is not None)
        except OmniBufDecodeError:
            return None
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
    n = len(raw)
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_ARRAY, 2)
        if b_start == -2:
            return []
        if b_start == -1:
            break
        body_mv = memoryview(raw)[b_start:b_end]
        elem_wt, count, p, ok = parse_array_header(body_mv)
        if not ok or elem_wt != exp_elem_wt:
            return []
        end = len(body_mv)
        try:
            for _ in range(count):
                val, p = _read_scalar_elem(body_mv, p, end, elem_kind)
                out.append(val)
        except OmniBufDecodeError:
            return []
        if p != end:
            return []
    return out


def opaque_get_submsg_array[T](
    raw: Buffer,
    field_num: int,
    decode_fn: Callable[[Buffer, T | None, int, bool], T],
) -> list[T]:
    out: list[T] = []
    pos = 0
    n = len(raw)
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_ARRAY, 2)
        if b_start == -2:
            return []
        if b_start == -1:
            break
        body = raw[b_start:b_end]
        elem_wt, count, p, ok = parse_array_header(body)
        if not ok or elem_wt != WIRE_SUB_MSG:
            return []
        end = len(body)
        try:
            for _ in range(count):
                elem_mv, p = read_len_slice(body, p, 0, end)
                out.append(decode_fn(elem_mv, None, 2, False))
        except OmniBufDecodeError:
            return []
        if p != end:
            return []
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
    n = len(raw)
    while pos < n:
        b_start, b_end, pos = next_container_span(raw, pos, field_num, WIRE_MAP, 3)
        if b_start == -2:
            return {}
        if b_start == -1:
            break
        body_mv = memoryview(raw)[b_start:b_end]
        key_wt, val_wt, count, p, ok = parse_map_header(body_mv)
        if not ok or key_wt != exp_key_wt or val_wt != exp_val_wt:
            return {}
        end = len(body_mv)
        try:
            for _ in range(count):
                k, p = _read_scalar_elem(body_mv, p, end, key_kind)
                if val_kind == "submsg":
                    assert sub_decode_fn is not None
                    v_mv, p = read_len_slice(body_mv, p, 0, end)
                    out[k] = sub_decode_fn(v_mv, None, 2, False)
                else:
                    v, p = _read_scalar_elem(body_mv, p, end, val_kind)
                    out[k] = v
        except OmniBufDecodeError:
            return {}
        if p != end:
            return {}
    return out


def splice_dirty_fields(
    dst_prefix: Buffer | None,
    src_packet: Buffer,
    dirty_nums: set[int] | int,
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

    n = len(src_packet)
    tz_widths = TZCNT_WIDTH_TABLE

    single_fnum = -1
    if isinstance(dirty_nums, int):
        if (dirty_nums & (dirty_nums - 1)) == 0:
            single_fnum = dirty_nums.bit_length() - 1
    elif len(dirty_nums) == 1:
        single_fnum = next(iter(dirty_nums))

    # Zero-list/dict/set fast path when mutating a single field (the common case).
    if single_fnum >= 0:
        target_fnum = single_fnum
        pos = 0
        match_count = 0
        only_start = -1
        only_end = -1
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
            elif wt <= 1:
                if pos >= n:
                    raise OmniBufDecodeError(f"omnibuf: truncated varint at byte {pos}")
                w = tz_widths[src_packet[pos]]
                if w == 0 or pos + w > n:
                    raise OmniBufDecodeError(f"omnibuf: invalid varint at byte {pos}")
                next_pos = pos + w
            elif wt <= 3:
                next_pos = pos
            elif wt <= 9:
                next_pos = pos + (4 << (wt & 1))
                if next_pos > n:
                    raise OmniBufDecodeError(f"omnibuf: truncated fixed value at byte {pos}")
            elif wt <= 12:
                if pos >= n:
                    raise OmniBufDecodeError(f"omnibuf: truncated length at byte {pos}")
                lb0 = src_packet[pos]
                if lb0 & 1:
                    next_pos = pos + 1 + (lb0 >> 1)
                elif lb0 & 2:
                    if pos + 2 > n:
                        raise OmniBufDecodeError(f"omnibuf: truncated length at byte {pos}")
                    next_pos = pos + 2 + ((lb0 | (src_packet[pos + 1] << 8)) >> 2)
                else:
                    b_len, bn = decode_varint(src_packet, pos, n)
                    if bn == 0:
                        raise OmniBufDecodeError(f"omnibuf: invalid length at byte {pos}")
                    next_pos = pos + bn + b_len
                if next_pos > n:
                    raise OmniBufDecodeError(f"omnibuf: payload out of bounds at byte {pos}")
            else:
                next_pos = skip_validated_value(src_packet, pos, wt, n)
                if next_pos < 0:
                    raise OmniBufDecodeError(f"omnibuf: invalid container header at byte {pos}")

            if fnum == target_fnum:
                match_count += 1
                only_start = f_start
                only_end = next_pos
            pos = next_pos

        if match_count == 0:
            out = bytearray(dst_prefix) if dst_prefix is not None else bytearray()
            out.extend(src_packet)
            encode_one_field(out, target_fnum)
            return bytes(out)
        if match_count == 1:
            out = bytearray(dst_prefix) if dst_prefix is not None else bytearray()
            if only_start > 0:
                out.extend(src_packet[:only_start])
            encode_one_field(out, target_fnum)
            if only_end < n:
                out.extend(src_packet[only_end:])
            return bytes(out)

    dirty_set: set[int]
    if isinstance(dirty_nums, int):
        dirty_set = set()
        rem_mask = dirty_nums
        while rem_mask:
            lsb = rem_mask & -rem_mask
            dirty_set.add(lsb.bit_length() - 1)
            rem_mask ^= lsb
    else:
        dirty_set = dirty_nums

    # Multi-field or duplicate-field fallback scan tracking spans to replace at last occurrence.
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
            next_pos = skip_value(src_packet, pos, wt, n)
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
