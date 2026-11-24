"""Field #0 (omnibuf.v1.SchemaMeta) self-describing metadata encoder, decoder, and merger."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import _omnibuf_ext
from .encoder import Encoder
from .wire import (
    FIELD0_TAG,
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    WIRE_MAP,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Buffer,
    OmniBufDecodeError,
    OmniBufEncodeError,
    decode_utf8_strict,
    decode_varint,
    parse_map_header,
    read_len_slice,
    validate_value,
)


@dataclass(slots=True)
class SchemaMeta:
    """In-memory representation of omnibuf.v1.SchemaMeta carried in Field #0 (Tag = 0x19)."""

    type_name: str = ""
    fields: dict[int, str] = field(default_factory=dict)
    children: dict[int, SchemaMeta] = field(default_factory=dict)

    def copy(self) -> SchemaMeta:
        return SchemaMeta(
            type_name=self.type_name,
            fields=dict(self.fields),
            children={k: v.copy() for k, v in self.children.items()},
        )


def merge_schema_meta(base: SchemaMeta | None, overlay: SchemaMeta | None) -> SchemaMeta | None:
    """Merges overlay onto a copy/existing SchemaMeta without mutating overlay."""
    if overlay is None:
        return base
    if base is None:
        return overlay.copy()
    if overlay.type_name:
        base.type_name = overlay.type_name
    if overlay.fields:
        base.fields.update(overlay.fields)
    if overlay.children:
        for fnum, child in overlay.children.items():
            existing = base.children.get(fnum)
            merged = merge_schema_meta(existing, child)
            if merged is not None:
                base.children[fnum] = merged
    return base


def write_schema_meta_body(enc: Encoder, meta: SchemaMeta, depth: int = 1) -> None:
    """Serializes the inner fields of SchemaMeta into enc."""
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufEncodeError(
            f"omnibuf: SchemaMeta nesting depth {depth} exceeds {MAX_NESTING_DEPTH}"
        )
    if meta.type_name:
        enc.write_string(1, meta.type_name)
    if meta.fields:
        if depth + 1 > MAX_NESTING_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: SchemaMeta fields depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
            )
        enc.begin_map(2, WIRE_UINT, WIRE_STRING, len(meta.fields))
        for fnum in sorted(meta.fields):
            if fnum <= 0 or fnum > MAX_FIELD_NUMBER:
                raise OmniBufEncodeError(f"omnibuf: invalid SchemaMeta field number {fnum}")
            enc.write_elem_uint(fnum)
            enc.write_elem_string(meta.fields[fnum])
        enc.end_map()
    if meta.children:
        if depth + 1 > MAX_NESTING_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: SchemaMeta children depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
            )
        enc.begin_map(3, WIRE_UINT, WIRE_SUB_MSG, len(meta.children))
        for fnum in sorted(meta.children):
            if fnum <= 0 or fnum > MAX_FIELD_NUMBER:
                raise OmniBufEncodeError(f"omnibuf: invalid SchemaMeta child field number {fnum}")
            enc.write_elem_uint(fnum)
            enc.begin_container()
            write_schema_meta_body(enc, meta.children[fnum], depth + 2)
            enc.end_container()
        enc.end_map()


def write_field0_schema_meta(enc: Encoder, meta: SchemaMeta) -> None:
    """Writes Field #0 (Tag = 0x19, WireSubMsg = 12) containing SchemaMeta to enc."""
    enc.begin_submsg(0)
    write_schema_meta_body(enc, meta, 1)
    enc.end_submsg()


def encode_field0_schema_meta(meta: SchemaMeta) -> bytes:
    """Encodes a standalone Field #0 SchemaMeta block to bytes (beginning with 0x19)."""
    enc = Encoder()
    write_field0_schema_meta(enc, meta)
    out = enc.finish()
    assert out[0] == FIELD0_TAG
    return out


def decode_schema_meta(
    data: Buffer,
    depth: int = 1,
    max_depth: int = MAX_NESTING_DEPTH,
) -> SchemaMeta:
    """Decodes an inner SchemaMeta payload from data."""
    if depth > max_depth:
        raise OmniBufDecodeError(f"omnibuf: SchemaMeta nesting depth {depth} exceeds {max_depth}")
    mv = memoryview(data)
    n = len(mv)
    pos = 0
    meta = SchemaMeta()

    while pos < n:
        tag, width = decode_varint(mv, pos, n)
        if width == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
            raise OmniBufDecodeError(f"omnibuf: invalid tag in SchemaMeta at byte {pos}")
        pos += width
        fnum = tag >> 4
        wt = tag & 0x0F

        if fnum == 0:
            raise OmniBufDecodeError("omnibuf: invalid nested Field #0 inside SchemaMeta")
        if fnum == 1:
            if wt != WIRE_STRING:
                raise OmniBufDecodeError(
                    f"omnibuf: SchemaMeta field #1 (type_name) must be WireString, got {wt}"
                )
            s_pos = pos
            s_slice, pos = read_len_slice(mv, pos, 0, n)
            meta.type_name = decode_utf8_strict(s_slice, s_pos)
        elif fnum == 2:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError(
                    f"omnibuf: SchemaMeta field #2 (fields) must be WireMap, got {wt}"
                )
            if depth + 1 > max_depth:
                raise OmniBufDecodeError(
                    f"omnibuf: SchemaMeta fields map depth {depth + 1} exceeds {max_depth}"
                )
            body, pos = read_len_slice(mv, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(body)
            if not ok or key_wt != WIRE_UINT or val_wt != WIRE_STRING:
                raise OmniBufDecodeError("omnibuf: invalid SchemaMeta fields map header")
            body_len = len(body)
            for _ in range(count):
                k64, kn = decode_varint(body, p, body_len)
                if kn == 0 or k64 == 0 or k64 > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError(
                        f"omnibuf: invalid SchemaMeta field number {k64} at byte {p}"
                    )
                p += kn
                v_pos = p
                v_slice, p = read_len_slice(body, p, 0, body_len)
                meta.fields[k64] = decode_utf8_strict(v_slice, v_pos)
            if p != body_len:
                raise OmniBufDecodeError("omnibuf: trailing bytes in SchemaMeta fields map")
        elif fnum == 3:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError(
                    f"omnibuf: SchemaMeta field #3 (children) must be WireMap, got {wt}"
                )
            if depth + 1 > max_depth:
                raise OmniBufDecodeError(
                    f"omnibuf: SchemaMeta children map depth {depth + 1} exceeds {max_depth}"
                )
            body, pos = read_len_slice(mv, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(body)
            if not ok or key_wt != WIRE_UINT or val_wt != WIRE_SUB_MSG:
                raise OmniBufDecodeError("omnibuf: invalid SchemaMeta children map header")
            body_len = len(body)
            local_children: dict[int, SchemaMeta] = {}
            for _ in range(count):
                k64, kn = decode_varint(body, p, body_len)
                if kn == 0 or k64 == 0 or k64 > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError(
                        f"omnibuf: invalid SchemaMeta child field number {k64} at byte {p}"
                    )
                p += kn
                child_slice, p = read_len_slice(body, p, 0, body_len)
                local_children[k64] = decode_schema_meta(child_slice, depth + 2, max_depth)
            if p != body_len:
                raise OmniBufDecodeError("omnibuf: trailing bytes in SchemaMeta children map")
            for k64, child_meta in local_children.items():
                merged = merge_schema_meta(meta.children.get(k64), child_meta)
                if merged is not None:
                    meta.children[k64] = merged
        else:
            pos = validate_value(mv, pos, wt, depth, max_depth, n, check_utf8=True)

    return meta


def read_field0_schema_meta(packet: Buffer) -> SchemaMeta | None:
    """Scans top-level fields of packet and returns merged Field #0 SchemaMeta, if present."""
    return _omnibuf_ext.read_field0_py(packet, SchemaMeta)


__all__ = [
    "SchemaMeta",
    "decode_schema_meta",
    "encode_field0_schema_meta",
    "merge_schema_meta",
    "read_field0_schema_meta",
    "write_field0_schema_meta",
    "write_schema_meta_body",
]
