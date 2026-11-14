"""Low-level OmniBuf v2.1 Prefix-Varint (TZCNT) primitives, wire constants, and O(1) skipping."""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from . import _omnibuf_ext

type Buffer = bytes | bytearray | memoryview


class OmniBufError(ValueError):
    """Base error raised by OmniBuf encoding or decoding operations."""


class OmniBufDecodeError(OmniBufError):
    """Raised when an OmniBuf wire payload is truncated, malformed, or out of bounds."""


class OmniBufEncodeError(OmniBufError):
    """Raised when a value cannot be serialized to the OmniBuf wire format."""


_omnibuf_ext.init_exceptions(OmniBufEncodeError, OmniBufDecodeError)


WIRE_UINT = 0
WIRE_SINT = 1
WIRE_BOOL_FALSE = 2
WIRE_BOOL_TRUE = 3
WIRE_FIXED32 = 4
WIRE_FIXED64 = 5
WIRE_SFIXED32 = 6
WIRE_SFIXED64 = 7
WIRE_FLOAT32 = 8
WIRE_FLOAT64 = 9
WIRE_STRING = 10
WIRE_BYTES = 11
WIRE_SUB_MSG = 12
WIRE_ARRAY = 13
WIRE_MAP = 14
WIRE_EXTENDED = 15

# Cross-language CamelCase aliases
WireUint = WIRE_UINT
WireSint = WIRE_SINT
WireBoolFalse = WIRE_BOOL_FALSE
WireBoolTrue = WIRE_BOOL_TRUE
WireFixed32 = WIRE_FIXED32
WireFixed64 = WIRE_FIXED64
WireSfixed32 = WIRE_SFIXED32
WireSfixed64 = WIRE_SFIXED64
WireFloat32 = WIRE_FLOAT32
WireFloat64 = WIRE_FLOAT64
WireString = WIRE_STRING
WireBytes = WIRE_BYTES
WireSubMsg = WIRE_SUB_MSG
WireArray = WIRE_ARRAY
WireMap = WIRE_MAP
WireExtended = WIRE_EXTENDED

MAX_NESTING_DEPTH = 32
MAX_CONTAINER_DEPTH = 32
MAX_FIELD_NUMBER = 536_870_911
FIELD0_TAG = 0x19

MAX_1B_VARINT = 127
MAX_2B_VARINT = 16_383
MAX_4B_VARINT = 536_870_911
UINT32_MAX = 0xFFFF_FFFF
UINT64_MAX = 0xFFFF_FFFF_FFFF_FFFF
INT32_MIN = -0x8000_0000
INT32_MAX = 0x7FFF_FFFF
INT64_MIN = -0x8000_0000_0000_0000
INT64_MAX = 0x7FFF_FFFF_FFFF_FFFF

_U16_LE = struct.Struct("<H")
_U32_LE = struct.Struct("<I")
_I32_LE = struct.Struct("<i")
_U64_LE = struct.Struct("<Q")
_I64_LE = struct.Struct("<q")
_F32_LE = struct.Struct("<f")
_F64_LE = struct.Struct("<d")
_VARINT9_LE = struct.Struct("<BQ")


def _build_tzcnt_width_table() -> tuple[int, ...]:
    table: list[int] = []
    for b in range(256):
        if b == 0:
            table.append(9)
        else:
            tz = (b & -b).bit_length() - 1
            if tz == 0:
                table.append(1)
            elif tz == 1:
                table.append(2)
            elif tz == 2:
                table.append(4)
            else:
                # Reserved marker: (b & 0x07) == 0 and b != 0
                table.append(0)
    return tuple(table)


TZCNT_WIDTH_TABLE: tuple[int, ...] = _build_tzcnt_width_table()

VALID_MAP_KEY_TYPES: frozenset[int] = frozenset(
    {
        WIRE_UINT,
        WIRE_SINT,
        WIRE_BOOL_FALSE,
        WIRE_FIXED32,
        WIRE_FIXED64,
        WIRE_SFIXED32,
        WIRE_SFIXED64,
        WIRE_STRING,
    }
)


def to_uint32(v: int) -> int:
    return v & UINT32_MAX


def to_int32(v: int) -> int:
    u = v & UINT32_MAX
    return u - 0x1_0000_0000 if u >= 0x8000_0000 else u


def to_uint64(v: int) -> int:
    return v & UINT64_MAX


def to_int64(v: int) -> int:
    u = v & UINT64_MAX
    return u - 0x1_0000_0000_0000_0000 if u >= 0x8000_0000_0000_0000 else u


def encode_zigzag(n: int) -> int:
    """Encodes a signed 64-bit integer using ZigZag mapping."""
    if n < INT64_MIN or n > INT64_MAX:
        raise OmniBufEncodeError(f"omnibuf: sint64 value {n} out of int64 range")
    return ((n << 1) ^ (n >> 63)) & UINT64_MAX


def encode_zigzag32(n: int) -> int:
    """Encodes a signed 32-bit integer using ZigZag mapping."""
    if n < INT32_MIN or n > INT32_MAX:
        raise OmniBufEncodeError(f"omnibuf: sint32 value {n} out of int32 range")
    return ((n << 1) ^ (n >> 31)) & UINT32_MAX


def decode_zigzag(u: int) -> int:
    """Decodes an unsigned 64-bit ZigZag value into a signed 64-bit integer."""
    return (u >> 1) ^ -(u & 1)


def decode_zigzag32(u: int) -> int:
    """Decodes an unsigned ZigZag value into a signed 32-bit integer."""
    return to_int32((u >> 1) ^ -(u & 1))


def varint_byte_length(v: int) -> int:
    """Returns the Prefix-Varint byte width (1, 2, 4, or 9) for unsigned uint64 v."""
    if v < 0 or v > UINT64_MAX:
        raise OmniBufEncodeError(f"omnibuf: varint value {v} out of uint64 range")
    if v <= MAX_1B_VARINT:
        return 1
    if v <= MAX_2B_VARINT:
        return 2
    if v <= MAX_4B_VARINT:
        return 4
    return 9


varint_size = varint_byte_length

_WIRE_TYPE_NAMES: dict[int, str] = {
    WIRE_UINT: "WireUint",
    WIRE_SINT: "WireSint",
    WIRE_BOOL_FALSE: "WireBoolFalse",
    WIRE_BOOL_TRUE: "WireBoolTrue",
    WIRE_FIXED32: "WireFixed32",
    WIRE_FIXED64: "WireFixed64",
    WIRE_SFIXED32: "WireSfixed32",
    WIRE_SFIXED64: "WireSfixed64",
    WIRE_FLOAT32: "WireFloat32",
    WIRE_FLOAT64: "WireFloat64",
    WIRE_STRING: "WireString",
    WIRE_BYTES: "WireBytes",
    WIRE_SUB_MSG: "WireSubMsg",
    WIRE_ARRAY: "WireArray",
    WIRE_MAP: "WireMap",
    WIRE_EXTENDED: "WireExtended",
}


def wire_type_name(wt: int) -> str:
    """Returns the canonical wire-type name for a 4-bit wire type tag."""
    return _WIRE_TYPE_NAMES.get(wt, f"WireUnknown({wt})")


def append_varint(dst: bytearray, v: int) -> None:
    """Appends an unsigned 64-bit Prefix-Varint to dst."""
    if v < 0 or v > UINT64_MAX:
        raise OmniBufEncodeError(f"omnibuf: varint value {v} out of uint64 range")
    if v <= MAX_1B_VARINT:
        dst.append((v << 1) | 1)
    elif v <= MAX_2B_VARINT:
        u16 = (v << 2) | 2
        dst.append(u16 & 0xFF)
        dst.append((u16 >> 8) & 0xFF)
    elif v <= MAX_4B_VARINT:
        u32 = (v << 3) | 4
        dst.extend(_U32_LE.pack(u32))
    else:
        dst.extend(_VARINT9_LE.pack(0, v))


def encode_varint(v: int) -> bytes:
    """Encodes an unsigned 64-bit integer as Prefix-Varint bytes."""
    out = bytearray()
    append_varint(out, v)
    return bytes(out)


def append_tag(dst: bytearray, field_num: int, wire_type: int) -> None:
    """Appends an OmniBuf field tag (field_num << 4) | wire_type."""
    if field_num < 0 or field_num > MAX_FIELD_NUMBER:
        raise OmniBufEncodeError(f"omnibuf: field number {field_num} out of range")
    if wire_type < 0 or wire_type > WIRE_EXTENDED:
        raise OmniBufEncodeError(f"omnibuf: wire type {wire_type} out of range")
    if field_num == 0 and wire_type != WIRE_SUB_MSG:
        raise OmniBufEncodeError("omnibuf: Field #0 requires WireSubMsg")
    append_varint(dst, (field_num << 4) | wire_type)


def encode_tag(field_num: int, wire_type: int) -> bytes:
    """Encodes an OmniBuf field tag to bytes."""
    out = bytearray()
    append_tag(out, field_num, wire_type)
    return bytes(out)


def decode_varint(buf: Buffer, pos: int = 0, end: int | None = None) -> tuple[int, int]:
    """Decodes a Prefix-Varint from buf[pos:end]. Returns (value, bytes_read), or (0, 0) if invalid."""
    limit = len(buf) if end is None else end
    rem = limit - pos
    if rem <= 0:
        return 0, 0
    b0 = buf[pos]
    if b0 & 1:
        return b0 >> 1, 1
    if b0 & 2:
        if rem < 2:
            return 0, 0
        u16 = b0 | (buf[pos + 1] << 8)
        return u16 >> 2, 2
    if b0 & 4:
        if rem < 4:
            return 0, 0
        (u32,) = _U32_LE.unpack_from(buf, pos)
        return u32 >> 3, 4
    if b0 != 0 or rem < 9:
        return 0, 0
    (u64,) = _U64_LE.unpack_from(buf, pos + 1)
    return u64, 9


def decode_tag(buf: Buffer, pos: int = 0, end: int | None = None) -> tuple[int, int, int]:
    """Decodes a field tag from buf[pos:end]. Returns (field_num, wire_type, bytes_read)."""
    raw, width = decode_varint(buf, pos, end)
    if width == 0 or (raw >> 4) > MAX_FIELD_NUMBER:
        return 0, 0, 0
    return raw >> 4, raw & 0x0F, width


def read_varint(buf: Buffer, pos: int = 0, end: int | None = None) -> tuple[int, int]:
    """Reads a Prefix-Varint from buf[pos:end] and returns (value, next_pos), raising on failure."""
    val, width = decode_varint(buf, pos, end)
    if width == 0:
        raise OmniBufDecodeError(f"omnibuf: invalid or truncated Prefix-Varint at byte {pos}")
    return val, pos + width


def put_overlong_2b_varint(dst: bytearray, pos: int, v: int) -> None:
    """Writes a 2-byte Prefix-Varint (0..16383) at dst[pos:pos+2]."""
    u16 = ((v << 2) | 2) & 0xFFFF
    dst[pos] = u16 & 0xFF
    dst[pos + 1] = (u16 >> 8) & 0xFF


def backpatch_container_len(dst: bytearray, len_pos: int) -> None:
    """Backpatches the reserved 2-byte length slot at dst[len_pos:len_pos+2], expanding if > 16383."""
    sub_len = len(dst) - (len_pos + 2)
    if sub_len <= MAX_2B_VARINT:
        u16 = (sub_len << 2) | 2
        dst[len_pos] = u16 & 0xFF
        dst[len_pos + 1] = (u16 >> 8) & 0xFF
    elif sub_len <= MAX_4B_VARINT:
        w32 = (sub_len << 3) | 4
        dst[len_pos : len_pos + 2] = _U32_LE.pack(w32)
    else:
        dst[len_pos : len_pos + 2] = _VARINT9_LE.pack(0, sub_len)


def encode_utf8_strict(value: str, field_name: str = "") -> bytes:
    """Encodes a Python str to strict UTF-8 bytes, rejecting lone surrogates."""
    try:
        return value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        label = f" in field {field_name}" if field_name else ""
        raise OmniBufEncodeError(f"omnibuf: invalid UTF-8{label}: {exc}") from exc


def decode_utf8_strict(raw: Buffer, pos: int = 0) -> str:
    """Decodes raw bytes into a Python str using strict UTF-8 validation."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            return raw.decode("utf-8", "strict")
        return bytes(raw).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise OmniBufDecodeError(f"omnibuf: invalid UTF-8 at byte {pos}: {exc}") from exc


def round_float32_shortest(raw4: Buffer) -> float:
    """Unpacks 4 LE float32 bytes and rounds to the shortest round-tripping decimal float."""
    b4 = bytes(raw4)
    (f32,) = _F32_LE.unpack(b4)
    if not math.isfinite(f32) or f32 == 0.0:
        return float(f32)
    for precision in range(1, 10):
        candidate = float(f"{f32:.{precision}g}")
        try:
            if _F32_LE.pack(candidate) == b4:
                return candidate
        except OverflowError:
            continue
    return float(f32)


def normalize_float32(val: float) -> float:
    """Quantizes a Python float to single-precision IEEE-754 float32."""
    if math.isnan(val) or math.isinf(val):
        return val
    try:
        raw4 = _F32_LE.pack(val)
    except OverflowError as exc:
        raise OmniBufEncodeError(f"omnibuf: float32 overflow for {val}") from exc
    (out,) = _F32_LE.unpack(raw4)
    return float(out)


def read_len_slice(
    data: Buffer,
    pos: int,
    min_len: int = 0,
    end: int | None = None,
) -> tuple[memoryview, int]:
    """Reads [ByteLen (Prefix-Varint)][Payload] at data[pos:end], enforcing min_len and bounds."""
    limit = len(data) if end is None else end
    if pos >= limit:
        raise OmniBufDecodeError(f"omnibuf: truncated length varint at byte {pos}")
    byte_len, width = decode_varint(data, pos, limit)
    if width == 0:
        raise OmniBufDecodeError(f"omnibuf: invalid length varint at byte {pos}")
    pos += width
    if byte_len < min_len or byte_len > limit - pos:
        raise OmniBufDecodeError(f"omnibuf: invalid byte length {byte_len} at byte {pos}")
    mv = memoryview(data)
    return mv[pos : pos + byte_len], pos + byte_len


def read_len_bytes(
    data: bytes | bytearray,
    pos: int,
    min_len: int = 0,
    end: int | None = None,
) -> tuple[bytes | bytearray, int]:
    """Reads [ByteLen (Prefix-Varint)][Payload] from bytes/bytearray without memoryview allocation."""
    limit = len(data) if end is None else end
    if pos >= limit:
        raise OmniBufDecodeError(f"omnibuf: truncated length varint at byte {pos}")
    b0 = data[pos]
    if b0 & 1:
        byte_len = b0 >> 1
        pos += 1
    elif b0 & 2:
        if pos + 2 > limit:
            raise OmniBufDecodeError(f"omnibuf: truncated length varint at byte {pos}")
        byte_len = (b0 | (data[pos + 1] << 8)) >> 2
        pos += 2
    else:
        byte_len, width = decode_varint(data, pos, limit)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid length varint at byte {pos}")
        pos += width
    if byte_len < min_len or byte_len > limit - pos:
        raise OmniBufDecodeError(f"omnibuf: invalid byte length {byte_len} at byte {pos}")
    return data[pos : pos + byte_len], pos + byte_len


def is_valid_map_types(key_wt: int, val_wt: int) -> bool:
    """Checks whether (key_wt, val_wt) are valid OmniBuf v2.1 WireMap header types."""
    return (
        key_wt in VALID_MAP_KEY_TYPES and 0 <= val_wt <= WIRE_EXTENDED and val_wt != WIRE_BOOL_TRUE
    )


def parse_array_header(body: Buffer) -> tuple[int, int, int, bool]:
    """Parses a WireArray body header [ElemWT (1B)][Count (Prefix-Varint)].

    Returns (elem_wt, count, elem_start_pos, ok).
    """
    n = len(body)
    if n < 2:
        return 0, 0, 0, False
    elem_wt = body[0]
    if elem_wt > WIRE_EXTENDED or elem_wt == WIRE_BOOL_TRUE:
        return 0, 0, 0, False
    count, cn = decode_varint(body, 1, n)
    if cn == 0:
        return 0, 0, 0, False
    pos = 1 + cn
    remaining = n - pos
    if remaining < 0:
        return 0, 0, 0, False
    if elem_wt == WIRE_BOOL_FALSE:
        ok = count == remaining
    elif elem_wt in (WIRE_FIXED32, WIRE_SFIXED32, WIRE_FLOAT32):
        ok = (remaining & 3) == 0 and count == (remaining >> 2)
    elif elem_wt in (WIRE_FIXED64, WIRE_SFIXED64, WIRE_FLOAT64):
        ok = (remaining & 7) == 0 and count == (remaining >> 3)
    else:
        ok = (remaining == 0) if count == 0 else (count <= remaining)
    if not ok:
        return 0, 0, 0, False
    return elem_wt, count, pos, True


def parse_map_header(body: Buffer) -> tuple[int, int, int, int, bool]:
    """Parses a WireMap body header [KeyWT (1B)][ValWT (1B)][Count (Prefix-Varint)].

    Returns (key_wt, val_wt, count, entry_start_pos, ok).
    """
    n = len(body)
    if n < 3:
        return 0, 0, 0, 0, False
    key_wt = body[0]
    val_wt = body[1]
    if not is_valid_map_types(key_wt, val_wt):
        return 0, 0, 0, 0, False
    count, cn = decode_varint(body, 2, n)
    if cn == 0:
        return 0, 0, 0, 0, False
    pos = 2 + cn
    remaining = n - pos
    if remaining < 0:
        return 0, 0, 0, 0, False
    ok = (remaining == 0) if count == 0 else (count <= (remaining >> 1))
    if not ok:
        return 0, 0, 0, 0, False
    return key_wt, val_wt, count, pos, True


def fast_skip_value(packet: Buffer, pos: int, wt: int, end: int | None = None) -> int:
    """Advances pos past a single field value of wire type wt in O(1) time.

    Returns next_pos, or -1 if truncated or invalid.
    """
    limit = len(packet) if end is None else end
    if pos < 0 or pos > limit:
        return -1
    if wt <= 1:
        if pos >= limit:
            return -1
        width = TZCNT_WIDTH_TABLE[packet[pos]]
        if width == 0 or pos + width > limit:
            return -1
        return pos + width
    if wt <= 3:
        return pos
    if wt <= 9:
        nxt = pos + (4 << (wt & 1))
        return nxt if nxt <= limit else -1
    if wt <= 15:
        if pos >= limit:
            return -1
        b0 = packet[pos]
        if b0 & 1:
            b_len = b0 >> 1
            bn = 1
        elif b0 & 2:
            if pos + 2 > limit:
                return -1
            b_len = (b0 | (packet[pos + 1] << 8)) >> 2
            bn = 2
        else:
            b_len, bn = decode_varint(packet, pos, limit)
            if bn == 0:
                return -1
        min_len = 0 if wt <= 12 else (2 if wt == 13 else (3 if wt == 14 else 1))
        if b_len < min_len:
            return -1
        next_pos = pos + bn + b_len
        return next_pos if next_pos <= limit else -1
    return -1


def skip_validated_value(packet: Buffer, pos: int, wt: int, end: int | None = None) -> int:
    """Advances pos past a field value, checking array/map header alignment in O(1) time."""
    limit = len(packet) if end is None else end
    if pos < 0 or pos > limit:
        return -1
    if wt <= 1:
        if pos >= limit:
            return -1
        width = TZCNT_WIDTH_TABLE[packet[pos]]
        return pos + width if (width > 0 and pos + width <= limit) else -1
    if wt <= 3:
        return pos
    if wt <= 9:
        nxt = pos + (4 << (wt & 1))
        return nxt if nxt <= limit else -1
    if wt <= 12:
        if pos >= limit:
            return -1
        b0 = packet[pos]
        if b0 & 1:
            nxt = pos + 1 + (b0 >> 1)
            return nxt if nxt <= limit else -1
        if b0 & 2:
            if pos + 2 > limit:
                return -1
            nxt = pos + 2 + ((b0 | (packet[pos + 1] << 8)) >> 2)
            return nxt if nxt <= limit else -1
        b_len, bn = decode_varint(packet, pos, limit)
        if bn == 0:
            return -1
        nxt = pos + bn + b_len
        return nxt if nxt <= limit else -1
    if wt <= 15:
        if pos >= limit:
            return -1
        b0 = packet[pos]
        if b0 & 1:
            b_len = b0 >> 1
            bn = 1
        elif b0 & 2:
            if pos + 2 > limit:
                return -1
            b_len = (b0 | (packet[pos + 1] << 8)) >> 2
            bn = 2
        else:
            b_len, bn = decode_varint(packet, pos, limit)
            if bn == 0:
                return -1
        body_start = pos + bn
        body_end = body_start + b_len
        if body_end > limit:
            return -1
        if wt == WIRE_ARRAY:
            if b_len < 2:
                return -1
            ewt = packet[body_start]
            if ewt > WIRE_EXTENDED or ewt == WIRE_BOOL_TRUE:
                return -1
            cb = packet[body_start + 1]
            if cb & 1:
                cnt = cb >> 1
                cw = 1
            else:
                cnt, cw = decode_varint(packet, body_start + 1, body_end)
                if cw == 0:
                    return -1
            rem = b_len - 1 - cw
            if rem < 0:
                return -1
            ok = (rem == 0) if cnt == 0 else (cnt <= rem)
            return body_end if ok else -1
        if wt == WIRE_MAP:
            if b_len < 3:
                return -1
            kwt = packet[body_start]
            vwt = packet[body_start + 1]
            if kwt not in VALID_MAP_KEY_TYPES or vwt > WIRE_EXTENDED or vwt == WIRE_BOOL_TRUE:
                return -1
            cb = packet[body_start + 2]
            if cb & 1:
                cnt = cb >> 1
                cw = 1
            else:
                cnt, cw = decode_varint(packet, body_start + 2, body_end)
                if cw == 0:
                    return -1
            rem = b_len - 2 - cw
            if rem < 0:
                return -1
            ok = (rem == 0) if cnt == 0 else (cnt <= (rem >> 1))
            return body_end if ok else -1
        return body_end if (b_len >= 1 and packet[body_start] < 0x80) else -1
    return -1


def skip_value(packet: Buffer, pos: int, wt: int, end: int | None = None) -> int:
    """Advances pos past a field value, raising OmniBufDecodeError if invalid."""
    next_pos = skip_validated_value(packet, pos, wt, end)
    if next_pos < 0:
        raise OmniBufDecodeError(f"omnibuf: truncated or invalid wire type {wt} at byte {pos}")
    return next_pos


def _validate_container_entry(
    body: memoryview,
    pos: int,
    wt: int,
    depth: int,
    limit_depth: int,
) -> int:
    if wt == WIRE_BOOL_FALSE:
        if pos >= len(body) or body[pos] > 1:
            raise OmniBufDecodeError(f"omnibuf: invalid bool byte in container at byte {pos}")
        return pos + 1
    return validate_value(body, pos, wt, depth, limit_depth)


def validate_value(
    data: Buffer,
    pos: int,
    wt: int,
    depth: int = 0,
    limit_depth: int = MAX_NESTING_DEPTH,
    end: int | None = None,
) -> int:
    """Recursively validates a field payload at data[pos] enforcing MAX_NESTING_DEPTH."""
    if depth > limit_depth:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds limit {limit_depth}")
    limit = len(data) if end is None else end
    if pos < 0 or pos > limit:
        raise OmniBufDecodeError(f"omnibuf: position {pos} out of bounds")

    if wt == WIRE_SUB_MSG:
        body, next_pos = read_len_slice(data, pos, 0, limit)
        validate_message(body, depth + 1, limit_depth)
        return next_pos

    if wt == WIRE_ARRAY:
        if depth + 1 > limit_depth:
            raise OmniBufDecodeError(
                f"omnibuf: array nesting depth {depth + 1} exceeds limit {limit_depth}"
            )
        body, next_pos = read_len_slice(data, pos, 2, limit)
        elem_wt, count, p, ok = parse_array_header(body)
        if not ok:
            raise OmniBufDecodeError(f"omnibuf: invalid WireArray header at byte {pos}")
        if elem_wt == WIRE_BOOL_FALSE:
            if len(body) - p != count:
                raise OmniBufDecodeError("omnibuf: invalid WireArray bool byte length")
            for i in range(count):
                if body[p + i] > 1:
                    raise OmniBufDecodeError("omnibuf: invalid bool byte in WireArray")
            return next_pos
        if elem_wt in (WIRE_FIXED32, WIRE_SFIXED32, WIRE_FLOAT32):
            if len(body) - p != count * 4:
                raise OmniBufDecodeError("omnibuf: invalid WireArray 32-bit byte length")
            return next_pos
        if elem_wt in (WIRE_FIXED64, WIRE_SFIXED64, WIRE_FLOAT64):
            if len(body) - p != count * 8:
                raise OmniBufDecodeError("omnibuf: invalid WireArray 64-bit byte length")
            return next_pos
        for _ in range(count):
            p = _validate_container_entry(body, p, elem_wt, depth + 1, limit_depth)
        if p != len(body):
            raise OmniBufDecodeError("omnibuf: trailing bytes in WireArray")
        return next_pos

    if wt == WIRE_MAP:
        if depth + 1 > limit_depth:
            raise OmniBufDecodeError(
                f"omnibuf: map nesting depth {depth + 1} exceeds limit {limit_depth}"
            )
        body, next_pos = read_len_slice(data, pos, 3, limit)
        key_wt, val_wt, count, p, ok = parse_map_header(body)
        if not ok:
            raise OmniBufDecodeError(f"omnibuf: invalid WireMap header at byte {pos}")
        for _ in range(count):
            p = _validate_container_entry(body, p, key_wt, depth + 1, limit_depth)
            p = _validate_container_entry(body, p, val_wt, depth + 1, limit_depth)
        if p != len(body):
            raise OmniBufDecodeError("omnibuf: trailing bytes in WireMap")
        return next_pos

    if wt == WIRE_EXTENDED:
        ext_body, next_pos = read_len_slice(data, pos, 1, limit)
        if ext_body[0] >= 0x80:
            raise OmniBufDecodeError(
                f"omnibuf: invalid WireExtended subtype 0x{ext_body[0]:02x} at byte {pos}"
            )
        return next_pos

    next_pos = fast_skip_value(data, pos, wt, limit)
    if next_pos < 0:
        raise OmniBufDecodeError(f"omnibuf: truncated or invalid wire type {wt} at byte {pos}")
    return next_pos


def validate_field0_at(
    data: Buffer,
    pos: int,
    wt: int,
    depth: int = 0,
    limit_depth: int = MAX_NESTING_DEPTH,
    end: int | None = None,
) -> int:
    """Validates a Field #0 (SchemaMeta) block starting at value offset pos."""
    if wt != WIRE_SUB_MSG:
        raise OmniBufDecodeError(f"omnibuf: Field #0 requires WireSubMsg (12), got {wt}")
    if depth + 1 > limit_depth:
        raise OmniBufDecodeError(f"omnibuf: Field #0 depth {depth + 1} exceeds limit {limit_depth}")
    body, next_pos = read_len_slice(data, pos, 0, end)
    _validate_schema_meta_body(body, depth + 1, limit_depth)
    return next_pos


def _validate_schema_meta_body(body: memoryview, depth: int, limit_depth: int) -> None:
    if depth > limit_depth:
        raise OmniBufDecodeError(f"omnibuf: SchemaMeta depth {depth} exceeds limit {limit_depth}")
    pos = 0
    n = len(body)
    while pos < n:
        tag, width = decode_varint(body, pos, n)
        if width == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
            raise OmniBufDecodeError("omnibuf: invalid tag in Field #0 SchemaMeta")
        pos += width
        fnum = tag >> 4
        wt = tag & 0x0F
        if fnum == 0:
            raise OmniBufDecodeError("omnibuf: nested Field #0 forbidden inside SchemaMeta")
        if fnum == 1:
            if wt != WIRE_STRING:
                raise OmniBufDecodeError("omnibuf: SchemaMeta.type_name must be WireString")
            raw_str, pos = read_len_slice(body, pos, 0, n)
            decode_utf8_strict(raw_str, pos)
        elif fnum == 2:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError("omnibuf: SchemaMeta.fields must be WireMap")
            if depth + 1 > limit_depth:
                raise OmniBufDecodeError("omnibuf: SchemaMeta.fields exceeds depth limit")
            map_body, pos = read_len_slice(body, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(map_body)
            if not ok or key_wt != WIRE_UINT or val_wt != WIRE_STRING:
                raise OmniBufDecodeError("omnibuf: invalid SchemaMeta.fields map header")
            for _ in range(count):
                k, kw = decode_varint(map_body, p, len(map_body))
                if kw == 0 or k == 0 or k > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError("omnibuf: invalid field number in SchemaMeta.fields")
                p += kw
                v_slice, p = read_len_slice(map_body, p, 0, len(map_body))
                decode_utf8_strict(v_slice, p)
            if p != len(map_body):
                raise OmniBufDecodeError("omnibuf: trailing bytes in SchemaMeta.fields")
        elif fnum == 3:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError("omnibuf: SchemaMeta.children must be WireMap")
            if depth + 1 > limit_depth:
                raise OmniBufDecodeError("omnibuf: SchemaMeta.children exceeds depth limit")
            map_body, pos = read_len_slice(body, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(map_body)
            if not ok or key_wt != WIRE_UINT or val_wt != WIRE_SUB_MSG:
                raise OmniBufDecodeError("omnibuf: invalid SchemaMeta.children map header")
            for _ in range(count):
                k, kw = decode_varint(map_body, p, len(map_body))
                if kw == 0 or k == 0 or k > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError("omnibuf: invalid field number in SchemaMeta.children")
                p += kw
                child_slice, p = read_len_slice(map_body, p, 0, len(map_body))
                _validate_schema_meta_body(child_slice, depth + 1, limit_depth)
            if p != len(map_body):
                raise OmniBufDecodeError("omnibuf: trailing bytes in SchemaMeta.children")
        else:
            pos = validate_value(body, pos, wt, depth, limit_depth, n)


def validate_message(
    data: Buffer,
    depth: int = 0,
    limit_depth: int = MAX_NESTING_DEPTH,
) -> None:
    """Validates an entire OmniBuf message buffer without allocating decoded objects."""
    if depth == 0 and limit_depth == MAX_NESTING_DEPTH:
        _omnibuf_ext.validate_message_py(data)
        return
    if depth > limit_depth:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds limit {limit_depth}")
    pos = 0
    n = len(data)
    mv = memoryview(data)
    while pos < n:
        tag, width = decode_varint(mv, pos, n)
        if width == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
            raise OmniBufDecodeError(f"omnibuf: invalid or truncated tag at byte {pos}")
        pos += width
        fnum = tag >> 4
        wt = tag & 0x0F
        if fnum == 0:
            pos = validate_field0_at(mv, pos, wt, depth, limit_depth, n)
        else:
            pos = validate_value(mv, pos, wt, depth, limit_depth, n)


@dataclass(slots=True, frozen=True)
class LocateFieldResult:
    """Result of an O(1) header-hop field lookup inside an OmniBuf packet."""

    val_slice: memoryview
    val_pos: int
    wire_type: int
    ok: bool


_EMPTY_MV = memoryview(b"")
_NOT_FOUND = LocateFieldResult(val_slice=_EMPTY_MV, val_pos=0, wire_type=0, ok=False)


def locate_field_offset(
    packet: Buffer,
    target_field: int,
    exp_mask: int = 0xFFFF,
) -> tuple[int, int]:
    """Locates the last matching occurrence of target_field without allocating memoryviews.

    Returns (val_pos, wire_type), or (-1, 0) if missing or malformed.
    """
    n = len(packet)
    pos = 0
    last_pos = -1
    last_wt = 0
    tz_widths = TZCNT_WIDTH_TABLE

    while pos < n:
        b0 = packet[pos]
        if b0 & 1:
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
            pos += 1
        elif b0 & 2:
            if pos + 2 > n:
                return -1, 0
            u16 = (b0 | (packet[pos + 1] << 8)) >> 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
            pos += 2
        else:
            tag, tn = decode_varint(packet, pos, n)
            if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                return -1, 0
            fnum = tag >> 4
            wt = tag & 0x0F
            pos += tn

        if fnum == 0 and wt != WIRE_SUB_MSG:
            return -1, 0

        if fnum == target_field and ((exp_mask >> wt) & 1) != 0:
            last_pos = pos
            last_wt = wt

        if wt <= 1:
            if pos >= n:
                return -1, 0
            w = tz_widths[packet[pos]]
            if w == 0 or pos + w > n:
                return -1, 0
            pos += w
        elif wt <= 3:
            pass
        elif wt <= 9:
            pos += 4 << (wt & 1)
            if pos > n:
                return -1, 0
        elif wt <= 12:
            if pos >= n:
                return -1, 0
            lb0 = packet[pos]
            if lb0 & 1:
                pos += 1 + (lb0 >> 1)
            elif lb0 & 2:
                if pos + 2 > n:
                    return -1, 0
                pos += 2 + ((lb0 | (packet[pos + 1] << 8)) >> 2)
            else:
                b_len, bn = decode_varint(packet, pos, n)
                if bn == 0:
                    return -1, 0
                pos += bn + b_len
            if pos > n:
                return -1, 0
        else:
            next_pos = skip_validated_value(packet, pos, wt, n)
            if next_pos < 0:
                return -1, 0
            pos = next_pos

    return last_pos, last_wt


def locate_field(
    packet: Buffer,
    target_field: int,
    exp_mask: int = 0xFFFF,
) -> LocateFieldResult:
    """Locates the last matching occurrence of target_field by hopping across headers in O(1) time."""
    last_pos, last_wt = locate_field_offset(packet, target_field, exp_mask)
    if last_pos < 0:
        return _NOT_FOUND
    mv = memoryview(packet)
    return LocateFieldResult(
        val_slice=mv[last_pos:],
        val_pos=last_pos,
        wire_type=last_wt,
        ok=True,
    )


@dataclass(slots=True, frozen=True)
class NextContainerResult:
    """Result of scanning for the next matching container occurrence of target_field."""

    body: memoryview
    next_pos: int
    matched: bool
    valid: bool


def next_container_span(
    packet: Buffer,
    pos: int,
    target_field: int,
    exp_wt: int,
    min_len: int = 0,
) -> tuple[int, int, int]:
    """Scans packet starting at pos for the next container occurrence without memoryview slicing.

    Returns (body_start, body_end, next_pos):
    - (body_start, body_end, next_pos) with body_start >= 0 when matched;
    - (-1, n, n) when end of packet is reached cleanly without match;
    - (-2, 0, 0) when packet is malformed/truncated.
    """
    n = len(packet)
    tz_widths = TZCNT_WIDTH_TABLE
    while pos < n:
        b0 = packet[pos]
        if b0 & 1:
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
            pos += 1
        elif b0 & 2:
            if pos + 2 > n:
                return -2, 0, 0
            u16 = (b0 | (packet[pos + 1] << 8)) >> 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
            pos += 2
        else:
            tag, tn = decode_varint(packet, pos, n)
            if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                return -2, 0, 0
            fnum = tag >> 4
            wt = tag & 0x0F
            pos += tn

        if fnum == 0 and wt != WIRE_SUB_MSG:
            return -2, 0, 0

        if fnum == target_field and wt == exp_wt:
            if pos >= n:
                return -2, 0, 0
            lb0 = packet[pos]
            if lb0 & 1:
                b_len = lb0 >> 1
                bn = 1
            elif lb0 & 2:
                if pos + 2 > n:
                    return -2, 0, 0
                b_len = (lb0 | (packet[pos + 1] << 8)) >> 2
                bn = 2
            else:
                b_len, bn = decode_varint(packet, pos, n)
                if bn == 0:
                    return -2, 0, 0
            end_pos = pos + bn + b_len
            if b_len < min_len or end_pos > n:
                return -2, 0, 0
            return pos + bn, end_pos, end_pos

        if wt <= 1:
            if pos >= n:
                return -2, 0, 0
            w = tz_widths[packet[pos]]
            if w == 0 or pos + w > n:
                return -2, 0, 0
            pos += w
        elif wt <= 3:
            pass
        elif wt <= 9:
            pos += 4 << (wt & 1)
            if pos > n:
                return -2, 0, 0
        elif wt <= 12:
            if pos >= n:
                return -2, 0, 0
            lb0 = packet[pos]
            if lb0 & 1:
                pos += 1 + (lb0 >> 1)
            elif lb0 & 2:
                if pos + 2 > n:
                    return -2, 0, 0
                pos += 2 + ((lb0 | (packet[pos + 1] << 8)) >> 2)
            else:
                b_len, bn = decode_varint(packet, pos, n)
                if bn == 0:
                    return -2, 0, 0
                pos += bn + b_len
            if pos > n:
                return -2, 0, 0
        else:
            next_pos = skip_validated_value(packet, pos, wt, n)
            if next_pos < 0:
                return -2, 0, 0
            pos = next_pos

    return -1, n, n


def next_container_field(
    packet: Buffer,
    pos: int,
    target_field: int,
    exp_wt: int,
    min_len: int = 0,
) -> NextContainerResult:
    """Scans packet starting at pos for the next container occurrence of target_field."""
    b_start, b_end, next_pos = next_container_span(packet, pos, target_field, exp_wt, min_len)
    if b_start == -2:
        return NextContainerResult(_EMPTY_MV, 0, False, False)
    if b_start == -1:
        return NextContainerResult(_EMPTY_MV, next_pos, False, True)
    mv = memoryview(packet)
    return NextContainerResult(mv[b_start:b_end], next_pos, True, True)


@dataclass(slots=True, frozen=True)
class SpliceField:
    """Replacement specification for splice_fields.

    When encoded_field is empty (b""), all occurrences of field_num are removed.
    Otherwise encoded_field must contain the complete [Tag][Payload] wire bytes.
    """

    field_num: int
    encoded_field: bytes = b""


def splice_fields(
    dst_prefix: Buffer | None,
    src_packet: Buffer,
    replacements: Sequence[SpliceField],
) -> bytes:
    """Splices updated or deleted fields into src_packet without decoding untouched fields.

    Preserves dst_prefix bytes at the front of the returned buffer without mutating
    dst_prefix or src_packet in place, even when dst_prefix aliases src_packet.
    """
    return _omnibuf_ext.splice_fields_py(dst_prefix, src_packet, replacements)
