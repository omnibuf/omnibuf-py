"""Schema-less blind decoding (decode_blind / decode_blind_json) with Field #0 support."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from typing import Any

from .field0 import SchemaMeta, decode_schema_meta, merge_schema_meta
from .wire import (
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_BOOL_TRUE,
    WIRE_BYTES,
    WIRE_EXTENDED,
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
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    fast_skip_value,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    round_float32_shortest,
)

_U32_UNPACK = struct.Struct("<I").unpack_from
_I32_UNPACK = struct.Struct("<i").unpack_from
_U64_UNPACK = struct.Struct("<Q").unpack_from
_I64_UNPACK = struct.Struct("<q").unpack_from
_F64_UNPACK = struct.Struct("<d").unpack_from


@dataclass(slots=True, frozen=True)
class _BlindSchemaChain:
    local: SchemaMeta
    parent: _BlindSchemaChain | None = None

    def field_name(self, field_num: int) -> str:
        cur: _BlindSchemaChain | None = self
        while cur is not None:
            name = cur.local.fields.get(field_num)
            if name is not None:
                return name
            cur = cur.parent
        return ""

    def child(self, field_num: int) -> _BlindSchemaChain | None:
        parent_child = self.parent.child(field_num) if self.parent is not None else None
        local_child = self.local.children.get(field_num)
        if local_child is not None:
            return _BlindSchemaChain(local=local_child, parent=parent_child)
        return parent_child


def _blind_field_shape(mv: memoryview, pos: int, wt: int, end: int) -> int:
    if wt == WIRE_BOOL_TRUE:
        return WIRE_BOOL_FALSE
    if wt == WIRE_ARRAY:
        body, _ = read_len_slice(mv, pos, 2, end)
        return WIRE_ARRAY | (body[0] << 8)
    if wt == WIRE_MAP:
        body, _ = read_len_slice(mv, pos, 3, end)
        return WIRE_MAP | (body[0] << 8) | (body[1] << 16)
    return wt


def _decode_map_key_blind(body: memoryview, pos: int, key_wt: int) -> tuple[str, int]:
    limit = len(body)
    if key_wt == WIRE_STRING:
        s_pos = pos
        raw, next_pos = read_len_slice(body, pos, 0, limit)
        return decode_utf8_strict(raw, s_pos), next_pos
    if key_wt == WIRE_UINT:
        val, width = decode_varint(body, pos, limit)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: truncated uint map key at byte {pos}")
        return str(val), pos + width
    if key_wt == WIRE_SINT:
        val, width = decode_varint(body, pos, limit)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: truncated sint map key at byte {pos}")
        return str(decode_zigzag(val)), pos + width
    if key_wt == WIRE_BOOL_FALSE:
        if pos >= limit or body[pos] > 1:
            raise OmniBufDecodeError(f"omnibuf: invalid bool map key byte at byte {pos}")
        return ("true" if body[pos] == 1 else "false"), pos + 1
    if key_wt == WIRE_FIXED32:
        if pos + 4 > limit:
            raise OmniBufDecodeError("omnibuf: truncated fixed32 map key")
        (u32,) = _U32_UNPACK(body, pos)
        return str(u32), pos + 4
    if key_wt == WIRE_SFIXED32:
        if pos + 4 > limit:
            raise OmniBufDecodeError("omnibuf: truncated sfixed32 map key")
        (i32,) = _I32_UNPACK(body, pos)
        return str(i32), pos + 4
    if key_wt == WIRE_FIXED64:
        if pos + 8 > limit:
            raise OmniBufDecodeError("omnibuf: truncated fixed64 map key")
        (u64,) = _U64_UNPACK(body, pos)
        return str(u64), pos + 8
    if key_wt == WIRE_SFIXED64:
        if pos + 8 > limit:
            raise OmniBufDecodeError("omnibuf: truncated sfixed64 map key")
        (i64,) = _I64_UNPACK(body, pos)
        return str(i64), pos + 8
    raise OmniBufDecodeError(f"omnibuf: unsupported WireMap key wire type {key_wt}")


def _decode_elem_blind(
    body: memoryview,
    pos: int,
    wt: int,
    schema: _BlindSchemaChain | None,
    depth: int,
    *,
    json_mode: bool,
) -> tuple[Any, int]:
    limit = len(body)
    if wt == WIRE_UINT:
        val, width = decode_varint(body, pos, limit)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: truncated WireUint at byte {pos}")
        return val, pos + width
    if wt == WIRE_SINT:
        val, width = decode_varint(body, pos, limit)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: truncated WireSint at byte {pos}")
        return decode_zigzag(val), pos + width
    if wt == WIRE_BOOL_FALSE:
        if pos >= limit or body[pos] > 1:
            raise OmniBufDecodeError(f"omnibuf: invalid bool byte at byte {pos}")
        return (body[pos] == 1), pos + 1
    if wt == WIRE_STRING:
        s_pos = pos
        raw, next_pos = read_len_slice(body, pos, 0, limit)
        return decode_utf8_strict(raw, s_pos), next_pos
    if wt == WIRE_BYTES:
        raw, next_pos = read_len_slice(body, pos, 0, limit)
        raw_bytes = bytes(raw)
        if json_mode:
            return base64.b64encode(raw_bytes).decode("ascii"), next_pos
        return raw_bytes, next_pos
    if wt == WIRE_FIXED32:
        if pos + 4 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireFixed32")
        (u32,) = _U32_UNPACK(body, pos)
        return int(u32), pos + 4
    if wt == WIRE_SFIXED32:
        if pos + 4 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireSfixed32")
        (i32,) = _I32_UNPACK(body, pos)
        return int(i32), pos + 4
    if wt == WIRE_FLOAT32:
        if pos + 4 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireFloat32")
        return round_float32_shortest(body[pos : pos + 4]), pos + 4
    if wt == WIRE_FIXED64:
        if pos + 8 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireFixed64")
        (u64,) = _U64_UNPACK(body, pos)
        return int(u64), pos + 8
    if wt == WIRE_SFIXED64:
        if pos + 8 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireSfixed64")
        (i64,) = _I64_UNPACK(body, pos)
        return int(i64), pos + 8
    if wt == WIRE_FLOAT64:
        if pos + 8 > limit:
            raise OmniBufDecodeError("omnibuf: truncated WireFloat64")
        (f64,) = _F64_UNPACK(body, pos)
        return float(f64), pos + 8
    if wt == WIRE_SUB_MSG:
        sub_slice, next_pos = read_len_slice(body, pos, 0, limit)
        sub_obj = _decode_blind_with_schema(sub_slice, schema, depth + 1, json_mode=json_mode)
        return sub_obj, next_pos
    if wt == WIRE_ARRAY:
        arr_slice, next_pos = read_len_slice(body, pos, 2, limit)
        arr_val = _decode_array_blind(arr_slice, schema, depth + 1, json_mode=json_mode)
        return arr_val, next_pos
    if wt == WIRE_MAP:
        map_slice, next_pos = read_len_slice(body, pos, 3, limit)
        map_val = _decode_map_blind(map_slice, schema, depth + 1, None, json_mode=json_mode)
        return map_val, next_pos
    if wt == WIRE_EXTENDED:
        raise OmniBufDecodeError("omnibuf: unknown WireExtended payload in blind decode")
    raise OmniBufDecodeError(f"omnibuf: unsupported element wire type {wt}")


def _decode_array_blind(
    body: memoryview,
    schema: _BlindSchemaChain | None,
    depth: int,
    *,
    json_mode: bool,
) -> list[Any]:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(
            f"omnibuf: array nesting depth {depth} exceeds {MAX_NESTING_DEPTH}"
        )
    elem_wt, count, pos, ok = parse_array_header(body)
    if not ok:
        raise OmniBufDecodeError("omnibuf: invalid WireArray header")
    out: list[Any] = []
    for _ in range(count):
        val, pos = _decode_elem_blind(body, pos, elem_wt, schema, depth, json_mode=json_mode)
        out.append(val)
    if pos != len(body):
        raise OmniBufDecodeError("omnibuf: trailing bytes in WireArray")
    return out


def _decode_map_blind(
    body: memoryview,
    schema: _BlindSchemaChain | None,
    depth: int,
    existing: dict[str, Any] | None,
    *,
    json_mode: bool,
) -> dict[str, Any]:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: map nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    key_wt, val_wt, count, pos, ok = parse_map_header(body)
    if not ok:
        raise OmniBufDecodeError("omnibuf: invalid WireMap header")
    out = existing if existing is not None else {}
    for _ in range(count):
        key_str, pos = _decode_map_key_blind(body, pos, key_wt)
        val, pos = _decode_elem_blind(body, pos, val_wt, schema, depth, json_mode=json_mode)
        out[key_str] = val
    if pos != len(body):
        raise OmniBufDecodeError("omnibuf: trailing bytes in WireMap")
    return out


def _decode_blind_with_schema(
    data: Buffer,
    inherited: _BlindSchemaChain | None,
    depth: int,
    *,
    json_mode: bool,
) -> dict[str, Any]:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    mv = memoryview(data)
    n = len(mv)
    if n == 0:
        return {}

    # Pass 1: Scan all tags and merge any Field #0 SchemaMeta blocks (supporting late
    # Field #0 blocks and concatenated messages).
    local_schema: SchemaMeta | None = None
    scan = 0
    while scan < n:
        tag, tn = decode_varint(mv, scan, n)
        if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
            raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {scan}")
        scan += tn
        fnum = tag >> 4
        wt = tag & 0x0F
        if fnum == 0:
            if wt != WIRE_SUB_MSG:
                raise OmniBufDecodeError(f"omnibuf: invalid Field #0 wire type {wt}")
            meta_body, scan = read_len_slice(mv, scan, 0, n)
            parsed = decode_schema_meta(meta_body, depth + 1, MAX_NESTING_DEPTH)
            local_schema = merge_schema_meta(local_schema, parsed)
        else:
            next_scan = fast_skip_value(mv, scan, wt, n)
            if next_scan < 0:
                raise OmniBufDecodeError(f"omnibuf: invalid field payload at byte {scan}")
            scan = next_scan

    active_schema = (
        _BlindSchemaChain(local=local_schema, parent=inherited)
        if local_schema is not None
        else inherited
    )

    # Pass 2: Decode values, checking name collisions and wire-shape stability.
    out: dict[str, Any] = {}
    sub_packets: dict[str, bytearray] = {}
    sub_schemas: dict[str, _BlindSchemaChain | None] = {}
    shapes: dict[int, int] = {}
    owners: dict[str, int] = {}

    pos = 0
    while pos < n:
        tag, tn = decode_varint(mv, pos, n)
        if tn == 0:
            raise OmniBufDecodeError(f"omnibuf: truncated tag at byte {pos}")
        pos += tn
        fnum = tag >> 4
        wt = tag & 0x0F

        if fnum == 0:
            _, pos = read_len_slice(mv, pos, 0, n)
            continue

        name = active_schema.field_name(fnum) if active_schema is not None else ""
        if not name:
            name = f"field_{fnum}"

        prev_owner = owners.get(name)
        if prev_owner is not None and prev_owner != fnum:
            raise OmniBufDecodeError(
                f"omnibuf: fields #{prev_owner} and #{fnum} collide on name {name!r}"
            )
        owners[name] = fnum

        shape = _blind_field_shape(mv, pos, wt, n)
        prev_shape = shapes.get(fnum)
        if prev_shape is not None and prev_shape != shape:
            raise OmniBufDecodeError(
                f"omnibuf: field #{fnum} changed wire shape (0x{prev_shape:x} -> 0x{shape:x})"
            )
        shapes[fnum] = shape

        child_schema = active_schema.child(fnum) if active_schema is not None else None

        if wt == WIRE_UINT:
            val, width = decode_varint(mv, pos, n)
            if width == 0:
                raise OmniBufDecodeError(f"omnibuf: truncated WireUint at byte {pos}")
            pos += width
            out[name] = val
        elif wt == WIRE_SINT:
            val, width = decode_varint(mv, pos, n)
            if width == 0:
                raise OmniBufDecodeError(f"omnibuf: truncated WireSint at byte {pos}")
            pos += width
            out[name] = decode_zigzag(val)
        elif wt == WIRE_BOOL_FALSE:
            out[name] = False
        elif wt == WIRE_BOOL_TRUE:
            out[name] = True
        elif wt == WIRE_STRING:
            s_pos = pos
            raw_str, pos = read_len_slice(mv, pos, 0, n)
            out[name] = decode_utf8_strict(raw_str, s_pos)
        elif wt == WIRE_BYTES:
            raw_bytes_mv, pos = read_len_slice(mv, pos, 0, n)
            raw_b = bytes(raw_bytes_mv)
            out[name] = base64.b64encode(raw_b).decode("ascii") if json_mode else raw_b
        elif wt == WIRE_SUB_MSG:
            sub_mv, pos = read_len_slice(mv, pos, 0, n)
            buf = sub_packets.get(name)
            if buf is None:
                buf = bytearray(sub_mv)
                sub_packets[name] = buf
            else:
                buf.extend(sub_mv)
            sub_schemas[name] = child_schema
        elif wt == WIRE_ARRAY:
            arr_mv, pos = read_len_slice(mv, pos, 2, n)
            elems = _decode_array_blind(arr_mv, child_schema, depth + 1, json_mode=json_mode)
            prev_arr = out.get(name)
            if isinstance(prev_arr, list):
                prev_arr.extend(elems)
            else:
                out[name] = elems
        elif wt == WIRE_MAP:
            map_mv, pos = read_len_slice(mv, pos, 3, n)
            prev_map = out.get(name)
            target_map = prev_map if isinstance(prev_map, dict) else None
            out[name] = _decode_map_blind(
                map_mv, child_schema, depth + 1, target_map, json_mode=json_mode
            )
        elif wt == WIRE_FIXED32:
            if pos + 4 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireFixed32 at byte {pos}")
            (u32,) = _U32_UNPACK(mv, pos)
            out[name] = int(u32)
            pos += 4
        elif wt == WIRE_SFIXED32:
            if pos + 4 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireSfixed32 at byte {pos}")
            (i32,) = _I32_UNPACK(mv, pos)
            out[name] = int(i32)
            pos += 4
        elif wt == WIRE_FLOAT32:
            if pos + 4 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireFloat32 at byte {pos}")
            out[name] = round_float32_shortest(mv[pos : pos + 4])
            pos += 4
        elif wt == WIRE_FIXED64:
            if pos + 8 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireFixed64 at byte {pos}")
            (u64,) = _U64_UNPACK(mv, pos)
            out[name] = int(u64)
            pos += 8
        elif wt == WIRE_SFIXED64:
            if pos + 8 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireSfixed64 at byte {pos}")
            (i64,) = _I64_UNPACK(mv, pos)
            out[name] = int(i64)
            pos += 8
        elif wt == WIRE_FLOAT64:
            if pos + 8 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated WireFloat64 at byte {pos}")
            (f64,) = _F64_UNPACK(mv, pos)
            out[name] = float(f64)
            pos += 8
        elif wt == WIRE_EXTENDED:
            raise OmniBufDecodeError("omnibuf: unknown WireExtended field in blind decode")
        else:
            raise OmniBufDecodeError(f"omnibuf: unsupported wire type {wt}")

    for name, packet_buf in sub_packets.items():
        out[name] = _decode_blind_with_schema(
            packet_buf, sub_schemas[name], depth + 1, json_mode=json_mode
        )

    return out


def decode_blind(packet: Buffer) -> dict[str, Any]:
    """Decodes any OmniBuf packet without a schema into a Python dict.

    Raw WireBytes payloads are returned as Python bytes objects.
    """
    return _decode_blind_with_schema(packet, None, 0, json_mode=False)


def decode_blind_json(
    packet: Buffer,
    *,
    allow_nan: bool = False,
    indent: int | None = None,
) -> str:
    """Decodes any OmniBuf packet without a schema and formats it as JSON.

    WireBytes values are encoded as standard Base64 strings. Float32 values use
    shortest round-tripping decimal formatting, and uint64/sint64 preserve full
    64-bit integer precision. When allow_nan is False and a float field contains
    NaN or Inf, raises ValueError unless handled by the caller.
    """
    tree = _decode_blind_with_schema(packet, None, 0, json_mode=True)
    return json.dumps(tree, allow_nan=allow_nan, indent=indent, separators=(",", ":"))


__all__ = [
    "decode_blind",
    "decode_blind_json",
]
