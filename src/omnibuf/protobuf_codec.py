"""OmniBuf codec for protobuf-py (primary) and google.protobuf (compatibility) messages (Tier 2)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, overload

import protobuf as pbpy
from google.protobuf.descriptor import FieldDescriptor as GpbFieldDescriptor
from google.protobuf.message import Message as GpbMessage

from .field0 import SchemaMeta, encode_field0_schema_meta
from .wire import (
    INT32_MAX,
    INT32_MIN,
    INT64_MAX,
    INT64_MIN,
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
    UINT32_MAX,
    UINT64_MAX,
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
    OmniBufEncodeError,
    append_varint,
    backpatch_container_len,
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    encode_tag,
    encode_utf8_strict,
    encode_zigzag,
    encode_zigzag32,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    to_uint32,
    validate_field0_at,
    validate_value,
)

_U32_PACK = struct.Struct("<I").pack
_I32_PACK = struct.Struct("<i").pack
_U64_PACK = struct.Struct("<Q").pack
_I64_PACK = struct.Struct("<q").pack
_F32_PACK = struct.Struct("<f").pack
_F64_PACK = struct.Struct("<d").pack

_U32_UNPACK = struct.Struct("<I").unpack_from
_I32_UNPACK = struct.Struct("<i").unpack_from
_U64_UNPACK = struct.Struct("<Q").unpack_from
_I64_UNPACK = struct.Struct("<q").unpack_from
_F32_UNPACK = struct.Struct("<f").unpack_from
_F64_UNPACK = struct.Struct("<d").unpack_from


# ============================================================================
# Shared scalar wire helpers
# ============================================================================

_PBPY_SCALAR_SPEC: dict[pbpy.ScalarType, tuple[str, int]] = {
    pbpy.ScalarType.DOUBLE: ("float64", WIRE_FLOAT64),
    pbpy.ScalarType.FLOAT: ("float32", WIRE_FLOAT32),
    pbpy.ScalarType.INT64: ("sint64", WIRE_SINT),
    pbpy.ScalarType.UINT64: ("uint64", WIRE_UINT),
    pbpy.ScalarType.INT32: ("sint32", WIRE_SINT),
    pbpy.ScalarType.FIXED64: ("fixed64", WIRE_FIXED64),
    pbpy.ScalarType.FIXED32: ("fixed32", WIRE_FIXED32),
    pbpy.ScalarType.BOOL: ("bool", WIRE_BOOL_FALSE),
    pbpy.ScalarType.STRING: ("string", WIRE_STRING),
    pbpy.ScalarType.BYTES: ("bytes", WIRE_BYTES),
    pbpy.ScalarType.UINT32: ("uint32", WIRE_UINT),
    pbpy.ScalarType.SFIXED32: ("sfixed32", WIRE_SFIXED32),
    pbpy.ScalarType.SFIXED64: ("sfixed64", WIRE_SFIXED64),
    pbpy.ScalarType.SINT32: ("sint32", WIRE_SINT),
    pbpy.ScalarType.SINT64: ("sint64", WIRE_SINT),
}

_GPB_SCALAR_SPEC: dict[int, tuple[str, int]] = {
    GpbFieldDescriptor.TYPE_DOUBLE: ("float64", WIRE_FLOAT64),
    GpbFieldDescriptor.TYPE_FLOAT: ("float32", WIRE_FLOAT32),
    GpbFieldDescriptor.TYPE_INT64: ("sint64", WIRE_SINT),
    GpbFieldDescriptor.TYPE_UINT64: ("uint64", WIRE_UINT),
    GpbFieldDescriptor.TYPE_INT32: ("sint32", WIRE_SINT),
    GpbFieldDescriptor.TYPE_FIXED64: ("fixed64", WIRE_FIXED64),
    GpbFieldDescriptor.TYPE_FIXED32: ("fixed32", WIRE_FIXED32),
    GpbFieldDescriptor.TYPE_BOOL: ("bool", WIRE_BOOL_FALSE),
    GpbFieldDescriptor.TYPE_STRING: ("string", WIRE_STRING),
    GpbFieldDescriptor.TYPE_BYTES: ("bytes", WIRE_BYTES),
    GpbFieldDescriptor.TYPE_UINT32: ("uint32", WIRE_UINT),
    GpbFieldDescriptor.TYPE_ENUM: ("enum", WIRE_SINT),
    GpbFieldDescriptor.TYPE_SFIXED32: ("sfixed32", WIRE_SFIXED32),
    GpbFieldDescriptor.TYPE_SFIXED64: ("sfixed64", WIRE_SFIXED64),
    GpbFieldDescriptor.TYPE_SINT32: ("sint32", WIRE_SINT),
    GpbFieldDescriptor.TYPE_SINT64: ("sint64", WIRE_SINT),
}


def _write_proto_scalar(dst: bytearray, kind: str, val: Any, field_name: str) -> None:
    if kind == "bool":
        dst.append(1 if val else 0)
    elif kind == "uint32":
        iv = int(val)
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} uint32 {iv} out of range")
        append_varint(dst, iv)
    elif kind == "uint64":
        iv = int(val)
        if iv < 0 or iv > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} uint64 {iv} out of range")
        append_varint(dst, iv)
    elif kind in ("sint32", "enum"):
        append_varint(dst, encode_zigzag32(int(val)))
    elif kind == "sint64":
        append_varint(dst, encode_zigzag(int(val)))
    elif kind == "fixed32":
        iv = int(val)
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} fixed32 {iv} out of range")
        dst.extend(_U32_PACK(iv))
    elif kind == "sfixed32":
        iv = int(val)
        if iv < INT32_MIN or iv > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} sfixed32 {iv} out of range")
        dst.extend(_I32_PACK(iv))
    elif kind == "fixed64":
        iv = int(val)
        if iv < 0 or iv > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} fixed64 {iv} out of range")
        dst.extend(_U64_PACK(iv))
    elif kind == "sfixed64":
        iv = int(val)
        if iv < INT64_MIN or iv > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} sfixed64 {iv} out of range")
        dst.extend(_I64_PACK(iv))
    elif kind == "float32":
        try:
            dst.extend(_F32_PACK(float(val)))
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} float32 overflow") from exc
    elif kind == "float64":
        dst.extend(_F64_PACK(float(val)))
    elif kind == "string":
        raw = encode_utf8_strict(val, field_name)
        append_varint(dst, len(raw))
        dst.extend(raw)
    elif kind == "bytes":
        append_varint(dst, len(val))
        dst.extend(val)
    else:
        raise OmniBufEncodeError(f"omnibuf: unsupported proto scalar kind {kind!r}")


def _read_proto_scalar(
    mv: memoryview,
    pos: int,
    end: int,
    kind: str,
    enum_cls: Any = None,
) -> tuple[Any, int]:
    if kind == "bool":
        if pos >= end:
            raise OmniBufDecodeError("omnibuf: truncated bool element")
        b = mv[pos]
        if b > 1:
            raise OmniBufDecodeError(f"omnibuf: invalid bool byte 0x{b:02x}")
        return (b == 1), pos + 1
    if kind == "uint32":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid uint32 varint at byte {pos}")
        return to_uint32(v), pos + w
    if kind == "uint64":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid uint64 varint at byte {pos}")
        return v, pos + w
    if kind == "sint32":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid sint32 varint at byte {pos}")
        return decode_zigzag32(v), pos + w
    if kind == "enum":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid enum varint at byte {pos}")
        ev = decode_zigzag32(v)
        return (enum_cls(ev) if enum_cls is not None else ev), pos + w
    if kind == "sint64":
        v, w = decode_varint(mv, pos, end)
        if w == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid sint64 varint at byte {pos}")
        return decode_zigzag(v), pos + w
    if kind == "fixed32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated fixed32")
        (u32,) = _U32_UNPACK(mv, pos)
        return int(u32), pos + 4
    if kind == "sfixed32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated sfixed32")
        (i32,) = _I32_UNPACK(mv, pos)
        return int(i32), pos + 4
    if kind == "fixed64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated fixed64")
        (u64,) = _U64_UNPACK(mv, pos)
        return int(u64), pos + 8
    if kind == "sfixed64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated sfixed64")
        (i64,) = _I64_UNPACK(mv, pos)
        return int(i64), pos + 8
    if kind == "float32":
        if pos + 4 > end:
            raise OmniBufDecodeError("omnibuf: truncated float32")
        (f32,) = _F32_UNPACK(mv, pos)
        return float(f32), pos + 4
    if kind == "float64":
        if pos + 8 > end:
            raise OmniBufDecodeError("omnibuf: truncated float64")
        (f64,) = _F64_UNPACK(mv, pos)
        return float(f64), pos + 8
    if kind == "string":
        s_pos = pos
        raw, next_pos = read_len_slice(mv, pos, 0, end)
        return decode_utf8_strict(raw, s_pos), next_pos
    if kind == "bytes":
        raw, next_pos = read_len_slice(mv, pos, 0, end)
        return bytes(raw), next_pos
    raise OmniBufDecodeError(f"omnibuf: unsupported proto scalar kind {kind!r}")


# ============================================================================
# Primary Codec: protobuf-py (bufbuild/protobuf-py)
# ============================================================================


@dataclass(slots=True)
class _PbpyFieldPlan:
    index: int
    field_num: int
    proto_name: str
    local_name: str
    has_presence: bool
    kind: str  # scalar kind | "enum" | "submsg" | "list_scalar" | "list_submsg" | "map"
    wire_type: int
    tag_bytes: bytes
    tag_false: bytes = b""
    tag_true: bytes = b""
    enum_cls: Any = None
    elem_kind: str = ""
    elem_wt: int = 0
    key_kind: str = ""
    key_wt: int = 0
    val_kind: str = ""
    val_wt: int = 0
    sub_plan: _PbpyMsgPlan | None = None
    sub_cls: type[Any] | None = None


class _PbpyMsgPlan:
    __slots__ = ("desc", "msg_cls", "fields", "by_num", "_schema_meta", "_field0_wire")

    def __init__(self, desc: pbpy.DescMessage) -> None:
        self.desc = desc
        self.msg_cls: type[Any] = desc.type
        self.fields: list[_PbpyFieldPlan] = []
        self.by_num: dict[int, _PbpyFieldPlan] = {}
        self._schema_meta: SchemaMeta | None = None
        self._field0_wire: bytes | None = None

    def get_schema_meta(self, visiting: frozenset[str] = frozenset()) -> SchemaMeta:
        if self._schema_meta is not None and not visiting:
            return self._schema_meta
        meta = SchemaMeta(type_name=self.desc.name)
        next_visiting = visiting | {self.desc.type_name}
        for fp in self.fields:
            meta.fields[fp.field_num] = fp.proto_name
            if fp.sub_plan is not None and fp.sub_plan.desc.type_name not in next_visiting:
                meta.children[fp.field_num] = fp.sub_plan.get_schema_meta(next_visiting)
        if not visiting:
            self._schema_meta = meta
        return meta

    def get_field0_wire(self) -> bytes:
        if self._field0_wire is None:
            self._field0_wire = encode_field0_schema_meta(self.get_schema_meta())
        return self._field0_wire


_PBPY_PLAN_CACHE: dict[str, _PbpyMsgPlan] = {}
_PBPY_BUILDING: dict[str, _PbpyMsgPlan] = {}


def _get_pbpy_plan(desc: pbpy.DescMessage) -> _PbpyMsgPlan:
    key = desc.type_name
    cached = _PBPY_PLAN_CACHE.get(key)
    if cached is not None:
        return cached
    in_prog = _PBPY_BUILDING.get(key)
    if in_prog is not None:
        return in_prog

    plan = _PbpyMsgPlan(desc)
    _PBPY_BUILDING[key] = plan
    try:
        compiled: list[_PbpyFieldPlan] = []
        for fd in desc.fields:
            fnum = fd.number
            has_pres = int(fd.presence) == 1  # SupportedFieldPresence.EXPLICIT == 1
            fval = fd.value

            if isinstance(fval, pbpy.DescFieldValueScalar):
                s_kind, s_wt = _PBPY_SCALAR_SPEC[fval.scalar]
                if s_kind == "bool":
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=has_pres,
                        kind="bool",
                        wire_type=WIRE_BOOL_FALSE,
                        tag_bytes=b"",
                        tag_false=encode_tag(fnum, WIRE_BOOL_FALSE),
                        tag_true=encode_tag(fnum, WIRE_BOOL_TRUE),
                    )
                else:
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=has_pres,
                        kind=s_kind,
                        wire_type=s_wt,
                        tag_bytes=encode_tag(fnum, s_wt),
                    )
            elif isinstance(fval, pbpy.DescFieldValueEnum):
                fp = _PbpyFieldPlan(
                    index=len(compiled),
                    field_num=fnum,
                    proto_name=fd.name,
                    local_name=fd.local_name,
                    has_presence=has_pres,
                    kind="enum",
                    wire_type=WIRE_SINT,
                    tag_bytes=encode_tag(fnum, WIRE_SINT),
                    enum_cls=fval.enum.type,
                )
            elif isinstance(fval, pbpy.DescFieldValueMessage):
                sub_p = _get_pbpy_plan(fval.message)
                fp = _PbpyFieldPlan(
                    index=len(compiled),
                    field_num=fnum,
                    proto_name=fd.name,
                    local_name=fd.local_name,
                    has_presence=True,
                    kind="submsg",
                    wire_type=WIRE_SUB_MSG,
                    tag_bytes=encode_tag(fnum, WIRE_SUB_MSG),
                    sub_plan=sub_p,
                    sub_cls=fval.message.type,
                )
            elif isinstance(fval, pbpy.DescFieldValueList):
                elem = fval.element
                tag_b = encode_tag(fnum, WIRE_ARRAY)
                if isinstance(elem, pbpy.DescMessage):
                    sub_p = _get_pbpy_plan(elem)
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="list_submsg",
                        wire_type=WIRE_ARRAY,
                        tag_bytes=tag_b,
                        elem_kind="submsg",
                        elem_wt=WIRE_SUB_MSG,
                        sub_plan=sub_p,
                        sub_cls=elem.type,
                    )
                elif isinstance(elem, pbpy.DescEnum):
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="list_scalar",
                        wire_type=WIRE_ARRAY,
                        tag_bytes=tag_b,
                        elem_kind="enum",
                        elem_wt=WIRE_SINT,
                        enum_cls=elem.type,
                    )
                else:
                    e_kind, e_wt = _PBPY_SCALAR_SPEC[elem]
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="list_scalar",
                        wire_type=WIRE_ARRAY,
                        tag_bytes=tag_b,
                        elem_kind=e_kind,
                        elem_wt=e_wt,
                    )
            elif isinstance(fval, pbpy.DescFieldValueMap):
                k_kind, k_wt = _PBPY_SCALAR_SPEC[fval.key]
                v_elem = fval.value
                tag_b = encode_tag(fnum, WIRE_MAP)
                if isinstance(v_elem, pbpy.DescMessage):
                    sub_p = _get_pbpy_plan(v_elem)
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="map",
                        wire_type=WIRE_MAP,
                        tag_bytes=tag_b,
                        key_kind=k_kind,
                        key_wt=k_wt,
                        val_kind="submsg",
                        val_wt=WIRE_SUB_MSG,
                        sub_plan=sub_p,
                        sub_cls=v_elem.type,
                    )
                elif isinstance(v_elem, pbpy.DescEnum):
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="map",
                        wire_type=WIRE_MAP,
                        tag_bytes=tag_b,
                        key_kind=k_kind,
                        key_wt=k_wt,
                        val_kind="enum",
                        val_wt=WIRE_SINT,
                        enum_cls=v_elem.type,
                    )
                else:
                    v_kind, v_wt = _PBPY_SCALAR_SPEC[v_elem]
                    fp = _PbpyFieldPlan(
                        index=len(compiled),
                        field_num=fnum,
                        proto_name=fd.name,
                        local_name=fd.local_name,
                        has_presence=False,
                        kind="map",
                        wire_type=WIRE_MAP,
                        tag_bytes=tag_b,
                        key_kind=k_kind,
                        key_wt=k_wt,
                        val_kind=v_kind,
                        val_wt=v_wt,
                    )
            else:
                raise OmniBufEncodeError(f"omnibuf: unsupported protobuf-py field {fd.name}")
            compiled.append(fp)

        compiled.sort(key=lambda item: item.field_num)
        for idx, fp in enumerate(compiled):
            fp.index = idx
            plan.by_num[fp.field_num] = fp
        plan.fields = compiled
        _PBPY_PLAN_CACHE[key] = plan
    finally:
        _PBPY_BUILDING.pop(key, None)
    return plan


def _encode_pbpy_msg(
    dst: bytearray,
    plan: _PbpyMsgPlan,
    msg: pbpy.Message[Any],
    deterministic: bool,
) -> None:
    for fp in plan.fields:
        if fp.has_presence and not msg.has_field(fp.local_name):
            continue
        val = getattr(msg, fp.local_name)
        kind = fp.kind
        if kind == "bool":
            dst.extend(fp.tag_true if val else fp.tag_false)
            continue

        dst.extend(fp.tag_bytes)
        if kind == "submsg":
            assert fp.sub_plan is not None
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            if val is not None:
                _encode_pbpy_msg(dst, fp.sub_plan, val, deterministic)
            backpatch_container_len(dst, len_pos)
        elif kind == "list_scalar":
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(fp.elem_wt)
            append_varint(dst, len(val))
            e_kind = fp.elem_kind
            for item in val:
                _write_proto_scalar(dst, e_kind, item, fp.proto_name)
            backpatch_container_len(dst, len_pos)
        elif kind == "list_submsg":
            assert fp.sub_plan is not None
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(WIRE_SUB_MSG)
            append_varint(dst, len(val))
            sub_p = fp.sub_plan
            for item in val:
                elem_pos = len(dst)
                dst.extend(b"\x00\x00")
                _encode_pbpy_msg(dst, sub_p, item, deterministic)
                backpatch_container_len(dst, elem_pos)
            backpatch_container_len(dst, len_pos)
        elif kind == "map":
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(fp.key_wt)
            dst.append(fp.val_wt)
            append_varint(dst, len(val))
            keys = sorted(val.keys()) if deterministic and len(val) > 1 else val.keys()
            k_kind = fp.key_kind
            v_kind = fp.val_kind
            map_sub_p = fp.sub_plan
            for k in keys:
                v = val[k]
                _write_proto_scalar(dst, k_kind, k, fp.proto_name)
                if v_kind == "submsg":
                    assert map_sub_p is not None
                    v_pos = len(dst)
                    dst.extend(b"\x00\x00")
                    _encode_pbpy_msg(dst, map_sub_p, v, deterministic)
                    backpatch_container_len(dst, v_pos)
                else:
                    _write_proto_scalar(dst, v_kind, v, fp.proto_name)
            backpatch_container_len(dst, len_pos)
        else:
            _write_proto_scalar(dst, kind, val, fp.proto_name)


def _decode_pbpy_msg(
    data: memoryview,
    plan: _PbpyMsgPlan,
    dst: pbpy.Message[Any],
    depth: int,
    merge: bool,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    if not merge:
        for field_to_clear in plan.fields:
            dst.clear_field(field_to_clear.local_name)

    n = len(data)
    pos = 0
    seen_mask = 0
    by_num = plan.by_num

    while pos < n:
        b0 = data[pos]
        if b0 & 1:
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
            pos += 1
        elif b0 & 2:
            if pos + 2 > n:
                raise OmniBufDecodeError(f"omnibuf: truncated tag at byte {pos}")
            u16 = (b0 | (data[pos + 1] << 8)) >> 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
            pos += 2
        else:
            tag, tn = decode_varint(data, pos, n)
            if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {pos}")
            fnum = tag >> 4
            wt = tag & 0x0F
            pos += tn

        if fnum == 0:
            pos = validate_field0_at(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        fp = by_num.get(fnum)
        if fp is None:
            pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        is_bool = fp.kind == "bool"
        if (is_bool and wt not in (WIRE_BOOL_FALSE, WIRE_BOOL_TRUE)) or (
            not is_bool and fp.wire_type != wt
        ):
            pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        bit = 1 << fp.index
        already_seen = ((seen_mask & bit) != 0) or merge
        seen_mask |= bit

        kind = fp.kind
        if is_bool:
            setattr(dst, fp.local_name, wt == WIRE_BOOL_TRUE)
        elif kind == "submsg":
            assert fp.sub_plan is not None and fp.sub_cls is not None
            sub_mv, pos = read_len_slice(data, pos, 0, n)
            cur_sub = getattr(dst, fp.local_name)
            if cur_sub is None:
                cur_sub = fp.sub_cls()
                setattr(dst, fp.local_name, cur_sub)
            _decode_pbpy_msg(sub_mv, fp.sub_plan, cur_sub, depth + 1, already_seen)
        elif kind == "list_scalar":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: array nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            arr_mv, pos = read_len_slice(data, pos, 2, n)
            elem_wt, count, p, ok = parse_array_header(arr_mv)
            if not ok or elem_wt != fp.elem_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid array header on field {fp.proto_name}")
            target_list = getattr(dst, fp.local_name)
            if not already_seen and len(target_list) > 0:
                target_list.clear()
            arr_end = len(arr_mv)
            e_kind = fp.elem_kind
            e_enum = fp.enum_cls
            for _ in range(count):
                item, p = _read_proto_scalar(arr_mv, p, arr_end, e_kind, e_enum)
                target_list.append(item)
            if p != arr_end:
                raise OmniBufDecodeError(f"omnibuf: trailing array bytes on field {fp.proto_name}")
        elif kind == "list_submsg":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: array nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            assert fp.sub_plan is not None and fp.sub_cls is not None
            arr_mv, pos = read_len_slice(data, pos, 2, n)
            elem_wt, count, p, ok = parse_array_header(arr_mv)
            if not ok or elem_wt != WIRE_SUB_MSG:
                raise OmniBufDecodeError(
                    f"omnibuf: invalid submsg array header on field {fp.proto_name}"
                )
            target_list = getattr(dst, fp.local_name)
            if not already_seen and len(target_list) > 0:
                target_list.clear()
            arr_end = len(arr_mv)
            sub_p = fp.sub_plan
            sub_cls = fp.sub_cls
            for _ in range(count):
                elem_mv, p = read_len_slice(arr_mv, p, 0, arr_end)
                elem_msg = sub_cls()
                _decode_pbpy_msg(elem_mv, sub_p, elem_msg, depth + 2, False)
                target_list.append(elem_msg)
            if p != arr_end:
                raise OmniBufDecodeError(
                    f"omnibuf: trailing submsg array bytes on field {fp.proto_name}"
                )
        elif kind == "map":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: map nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            map_mv, pos = read_len_slice(data, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(map_mv)
            if not ok or key_wt != fp.key_wt or val_wt != fp.val_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid map header on field {fp.proto_name}")
            target_map = getattr(dst, fp.local_name)
            if not already_seen and len(target_map) > 0:
                target_map.clear()
            map_end = len(map_mv)
            k_kind = fp.key_kind
            v_kind = fp.val_kind
            dec_map_p = fp.sub_plan
            dec_map_cls = fp.sub_cls
            v_enum = fp.enum_cls
            for _ in range(count):
                k_val, p = _read_proto_scalar(map_mv, p, map_end, k_kind)
                if v_kind == "submsg":
                    assert dec_map_p is not None and dec_map_cls is not None
                    v_mv, p = read_len_slice(map_mv, p, 0, map_end)
                    v_msg = dec_map_cls()
                    _decode_pbpy_msg(v_mv, dec_map_p, v_msg, depth + 2, False)
                    target_map[k_val] = v_msg
                else:
                    v_val, p = _read_proto_scalar(map_mv, p, map_end, v_kind, v_enum)
                    target_map[k_val] = v_val
            if p != map_end:
                raise OmniBufDecodeError(f"omnibuf: trailing map bytes on field {fp.proto_name}")
        else:
            val, pos = _read_proto_scalar(data, pos, n, kind, fp.enum_cls)
            setattr(dst, fp.local_name, val)


# ============================================================================
# Secondary Compatibility Codec: google.protobuf (_pb2.py)
# ============================================================================


def _is_gpb_repeated(fd: Any) -> bool:
    return bool(getattr(fd, "is_repeated", False))


def _is_gpb_map_field(fd: Any) -> bool:
    return bool(
        _is_gpb_repeated(fd)
        and fd.type == GpbFieldDescriptor.TYPE_MESSAGE
        and fd.message_type is not None
        and fd.message_type.has_options
        and fd.message_type.GetOptions().map_entry
    )


def _build_gpb_schema_meta(
    desc: Any,
    visiting: frozenset[str] = frozenset(),
) -> SchemaMeta:
    meta = SchemaMeta(type_name=str(desc.name))
    next_visiting = visiting | {str(desc.full_name)}
    for fd in desc.fields:
        fnum = int(fd.number)
        meta.fields[fnum] = str(fd.name)
        if _is_gpb_map_field(fd):
            assert fd.message_type is not None
            val_fd = fd.message_type.fields_by_name["value"]
            if (
                val_fd.type == GpbFieldDescriptor.TYPE_MESSAGE
                and val_fd.message_type is not None
                and val_fd.message_type.full_name not in next_visiting
            ):
                meta.children[fnum] = _build_gpb_schema_meta(val_fd.message_type, next_visiting)
        elif (
            fd.type == GpbFieldDescriptor.TYPE_MESSAGE
            and fd.message_type is not None
            and fd.message_type.full_name not in next_visiting
        ):
            meta.children[fnum] = _build_gpb_schema_meta(fd.message_type, next_visiting)
    return meta


def _encode_gpb_msg(dst: bytearray, msg: GpbMessage, deterministic: bool) -> None:
    desc: Any = msg.DESCRIPTOR
    sorted_fields: list[Any] = sorted(desc.fields, key=lambda f: f.number)
    for fd in sorted_fields:
        fnum = fd.number
        if fd.has_presence and not msg.HasField(fd.name):
            continue
        val = getattr(msg, fd.name)

        if _is_gpb_map_field(fd):
            assert fd.message_type is not None
            k_fd = fd.message_type.fields_by_name["key"]
            v_fd = fd.message_type.fields_by_name["value"]
            k_kind, k_wt = _GPB_SCALAR_SPEC[k_fd.type]
            is_v_msg = v_fd.type == GpbFieldDescriptor.TYPE_MESSAGE
            v_kind, v_wt = ("submsg", WIRE_SUB_MSG) if is_v_msg else _GPB_SCALAR_SPEC[v_fd.type]
            dst.extend(encode_tag(fnum, WIRE_MAP))
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(k_wt)
            dst.append(v_wt)
            append_varint(dst, len(val))
            keys = sorted(val.keys()) if deterministic and len(val) > 1 else val.keys()
            for k in keys:
                _write_proto_scalar(dst, k_kind, k, fd.name)
                if is_v_msg:
                    v_pos = len(dst)
                    dst.extend(b"\x00\x00")
                    _encode_gpb_msg(dst, val[k], deterministic)
                    backpatch_container_len(dst, v_pos)
                else:
                    _write_proto_scalar(dst, v_kind, val[k], fd.name)
            backpatch_container_len(dst, len_pos)
        elif _is_gpb_repeated(fd):
            is_msg = fd.type == GpbFieldDescriptor.TYPE_MESSAGE
            e_kind, e_wt = ("submsg", WIRE_SUB_MSG) if is_msg else _GPB_SCALAR_SPEC[fd.type]
            dst.extend(encode_tag(fnum, WIRE_ARRAY))
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(e_wt)
            append_varint(dst, len(val))
            for item in val:
                if is_msg:
                    e_pos = len(dst)
                    dst.extend(b"\x00\x00")
                    _encode_gpb_msg(dst, item, deterministic)
                    backpatch_container_len(dst, e_pos)
                else:
                    _write_proto_scalar(dst, e_kind, item, fd.name)
            backpatch_container_len(dst, len_pos)
        elif fd.type == GpbFieldDescriptor.TYPE_MESSAGE:
            dst.extend(encode_tag(fnum, WIRE_SUB_MSG))
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            _encode_gpb_msg(dst, val, deterministic)
            backpatch_container_len(dst, len_pos)
        elif fd.type == GpbFieldDescriptor.TYPE_BOOL:
            dst.extend(encode_tag(fnum, WIRE_BOOL_TRUE if val else WIRE_BOOL_FALSE))
        else:
            s_kind, s_wt = _GPB_SCALAR_SPEC[fd.type]
            dst.extend(encode_tag(fnum, s_wt))
            _write_proto_scalar(dst, s_kind, val, fd.name)


def _decode_gpb_msg(data: memoryview, dst: GpbMessage, depth: int, merge: bool) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    if not merge:
        dst.Clear()

    desc = dst.DESCRIPTOR
    by_num = desc.fields_by_number
    n = len(data)
    pos = 0
    seen: set[int] = set()

    while pos < n:
        tag, tn = decode_varint(data, pos, n)
        if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
            raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {pos}")
        pos += tn
        fnum = tag >> 4
        wt = tag & 0x0F

        if fnum == 0:
            pos = validate_field0_at(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        fd = by_num.get(fnum)
        if fd is None:
            pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        already_seen = (fnum in seen) or merge
        seen.add(fnum)

        if _is_gpb_map_field(fd):
            if wt != WIRE_MAP:
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: map nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            assert fd.message_type is not None
            k_fd = fd.message_type.fields_by_name["key"]
            v_fd = fd.message_type.fields_by_name["value"]
            k_kind, exp_k_wt = _GPB_SCALAR_SPEC[k_fd.type]
            is_v_msg = v_fd.type == GpbFieldDescriptor.TYPE_MESSAGE
            v_kind, exp_v_wt = ("submsg", WIRE_SUB_MSG) if is_v_msg else _GPB_SCALAR_SPEC[v_fd.type]

            map_mv, pos = read_len_slice(data, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(map_mv)
            if not ok or key_wt != exp_k_wt or val_wt != exp_v_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid map header on field {fd.name}")
            mp = getattr(dst, fd.name)
            if not already_seen and len(mp) > 0:
                mp.clear()
            map_end = len(map_mv)
            for _ in range(count):
                k_val, p = _read_proto_scalar(map_mv, p, map_end, k_kind)
                if is_v_msg:
                    v_mv, p = read_len_slice(map_mv, p, 0, map_end)
                    sub_entry = mp[k_val]
                    _decode_gpb_msg(v_mv, sub_entry, depth + 2, False)
                else:
                    v_val, p = _read_proto_scalar(map_mv, p, map_end, v_kind)
                    mp[k_val] = v_val
            if p != map_end:
                raise OmniBufDecodeError(f"omnibuf: trailing map bytes on field {fd.name}")
        elif _is_gpb_repeated(fd):
            if wt != WIRE_ARRAY:
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: array nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            is_msg = fd.type == GpbFieldDescriptor.TYPE_MESSAGE
            e_kind, exp_e_wt = ("submsg", WIRE_SUB_MSG) if is_msg else _GPB_SCALAR_SPEC[fd.type]
            arr_mv, pos = read_len_slice(data, pos, 2, n)
            elem_wt, count, p, ok = parse_array_header(arr_mv)
            if not ok or elem_wt != exp_e_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid array header on field {fd.name}")
            rep = getattr(dst, fd.name)
            if not already_seen and len(rep) > 0:
                del rep[:]
            arr_end = len(arr_mv)
            for _ in range(count):
                if is_msg:
                    e_mv, p = read_len_slice(arr_mv, p, 0, arr_end)
                    elem_msg = rep.add()
                    _decode_gpb_msg(e_mv, elem_msg, depth + 2, False)
                else:
                    item, p = _read_proto_scalar(arr_mv, p, arr_end, e_kind)
                    rep.append(item)
            if p != arr_end:
                raise OmniBufDecodeError(f"omnibuf: trailing array bytes on field {fd.name}")
        elif fd.type == GpbFieldDescriptor.TYPE_MESSAGE:
            if wt != WIRE_SUB_MSG:
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            sub_mv, pos = read_len_slice(data, pos, 0, n)
            sub_msg = getattr(dst, fd.name)
            sub_msg.SetInParent()
            _decode_gpb_msg(sub_mv, sub_msg, depth + 1, already_seen)
        elif fd.type == GpbFieldDescriptor.TYPE_BOOL:
            if wt not in (WIRE_BOOL_FALSE, WIRE_BOOL_TRUE):
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            setattr(dst, fd.name, wt == WIRE_BOOL_TRUE)
        else:
            s_kind, exp_wt = _GPB_SCALAR_SPEC[fd.type]
            if wt != exp_wt:
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            val, pos = _read_proto_scalar(data, pos, n, s_kind)
            setattr(dst, fd.name, val)


# ============================================================================
# Public API (marshal_proto / unmarshal_proto)
# ============================================================================


def is_proto_message_or_type(obj: Any) -> bool:
    """Returns True if obj is a protobuf-py or google.protobuf Message, class, or DescMessage."""
    if isinstance(obj, (pbpy.Message, pbpy.DescMessage, GpbMessage)):
        return True
    return isinstance(obj, type) and issubclass(obj, (pbpy.Message, GpbMessage))


def marshal_proto(
    msg: pbpy.Message[Any] | GpbMessage,
    *,
    deterministic: bool = False,
    self_describing: bool = False,
) -> bytes:
    """Serializes a protobuf-py Message (primary) or google.protobuf Message into OmniBuf wire bytes."""
    out = bytearray()
    if isinstance(msg, pbpy.Message):
        plan = _get_pbpy_plan(msg.desc())
        if self_describing:
            out.extend(plan.get_field0_wire())
        _encode_pbpy_msg(out, plan, msg, deterministic)
        return bytes(out)
    if isinstance(msg, GpbMessage):
        if self_describing:
            meta = _build_gpb_schema_meta(msg.DESCRIPTOR)
            out.extend(encode_field0_schema_meta(meta))
        _encode_gpb_msg(out, msg, deterministic)
        return bytes(out)
    raise OmniBufEncodeError(
        f"omnibuf: marshal_proto expected protobuf.Message or google.protobuf.Message, got {type(msg)!r}"
    )


@overload
def unmarshal_proto[M: pbpy.Message[Any]](packet: Buffer, target: type[M]) -> M: ...


@overload
def unmarshal_proto[M: pbpy.Message[Any]](packet: Buffer, target: M) -> M: ...


@overload
def unmarshal_proto(packet: Buffer, target: pbpy.DescMessage) -> pbpy.Message[Any]: ...


@overload
def unmarshal_proto[G: GpbMessage](packet: Buffer, target: type[G]) -> G: ...


@overload
def unmarshal_proto[G: GpbMessage](packet: Buffer, target: G) -> G: ...


def unmarshal_proto(packet: Buffer, target: Any) -> Any:
    """Decodes OmniBuf wire bytes into a protobuf-py Message/DescMessage or google.protobuf Message."""
    mv = memoryview(packet)
    if isinstance(target, pbpy.DescMessage):
        plan = _get_pbpy_plan(target)
        inst = plan.msg_cls()
        _decode_pbpy_msg(mv, plan, inst, 0, False)
        return inst
    if isinstance(target, type) and issubclass(target, pbpy.Message):
        plan = _get_pbpy_plan(target.desc())
        inst = target()
        _decode_pbpy_msg(mv, plan, inst, 0, False)
        return inst
    if isinstance(target, pbpy.Message):
        plan = _get_pbpy_plan(target.desc())
        _decode_pbpy_msg(mv, plan, target, 0, False)
        return target
    if isinstance(target, type) and issubclass(target, GpbMessage):
        g_inst = target()
        _decode_gpb_msg(mv, g_inst, 0, False)
        return g_inst
    if isinstance(target, GpbMessage):
        _decode_gpb_msg(mv, target, 0, False)
        return target
    raise OmniBufDecodeError(
        f"omnibuf: unmarshal_proto expected protobuf.Message or google.protobuf.Message, got {target!r}"
    )


__all__ = [
    "is_proto_message_or_type",
    "marshal_proto",
    "unmarshal_proto",
]
