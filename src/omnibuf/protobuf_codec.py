"""OmniBuf codec for protobuf-py (primary) and google.protobuf (compatibility) messages (Tier 2)."""

from __future__ import annotations

import struct
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, overload

import protobuf as pbpy

if TYPE_CHECKING:
    from google.protobuf.message import Message as GpbMessage

from ._omnibuf_ext import CompiledCodec
from .field0 import SchemaMeta, encode_field0_schema_meta, merge_schema_meta
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

# Standard google.protobuf FieldDescriptor.TYPE_* numeric constants (avoids eager import)
_GPB_TYPE_DOUBLE = 1
_GPB_TYPE_FLOAT = 2
_GPB_TYPE_INT64 = 3
_GPB_TYPE_UINT64 = 4
_GPB_TYPE_INT32 = 5
_GPB_TYPE_FIXED64 = 6
_GPB_TYPE_FIXED32 = 7
_GPB_TYPE_BOOL = 8
_GPB_TYPE_STRING = 9
_GPB_TYPE_GROUP = 10
_GPB_TYPE_MESSAGE = 11
_GPB_TYPE_BYTES = 12
_GPB_TYPE_UINT32 = 13
_GPB_TYPE_ENUM = 14
_GPB_TYPE_SFIXED32 = 15
_GPB_TYPE_SFIXED64 = 16
_GPB_TYPE_SINT32 = 17
_GPB_TYPE_SINT64 = 18

_GPB_STATE: tuple[type[Any] | None] | None = None


def _get_gpb_message_cls() -> type[Any] | None:
    """Lazily imports google.protobuf.message.Message only when needed."""
    global _GPB_STATE
    if _GPB_STATE is None:
        try:
            from google.protobuf.message import Message as _MsgCls
        except ImportError:
            _GPB_STATE = (None,)
        else:
            _GPB_STATE = (_MsgCls,)
    return _GPB_STATE[0]


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
    _GPB_TYPE_DOUBLE: ("float64", WIRE_FLOAT64),
    _GPB_TYPE_FLOAT: ("float32", WIRE_FLOAT32),
    _GPB_TYPE_INT64: ("sint64", WIRE_SINT),
    _GPB_TYPE_UINT64: ("uint64", WIRE_UINT),
    _GPB_TYPE_INT32: ("sint32", WIRE_SINT),
    _GPB_TYPE_FIXED64: ("fixed64", WIRE_FIXED64),
    _GPB_TYPE_FIXED32: ("fixed32", WIRE_FIXED32),
    _GPB_TYPE_BOOL: ("bool", WIRE_BOOL_FALSE),
    _GPB_TYPE_STRING: ("string", WIRE_STRING),
    _GPB_TYPE_BYTES: ("bytes", WIRE_BYTES),
    _GPB_TYPE_UINT32: ("uint32", WIRE_UINT),
    _GPB_TYPE_ENUM: ("enum", WIRE_SINT),
    _GPB_TYPE_SFIXED32: ("sfixed32", WIRE_SFIXED32),
    _GPB_TYPE_SFIXED64: ("sfixed64", WIRE_SFIXED64),
    _GPB_TYPE_SINT32: ("sint32", WIRE_SINT),
    _GPB_TYPE_SINT64: ("sint64", WIRE_SINT),
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
        if enum_cls is None:
            return ev, pos + w
        try:
            return enum_cls(ev), pos + w
        except ValueError as exc:
            raise OmniBufDecodeError(f"omnibuf: invalid enum value {ev}: {exc}") from exc
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
    __slots__ = (
        "desc",
        "msg_cls",
        "fields",
        "by_num",
        "_schema_meta",
        "_field0_wire",
        "rust_codec",
    )

    def __init__(self, desc: pbpy.DescMessage) -> None:
        self.desc = desc
        self.msg_cls: type[Any] = desc.type
        self.fields: list[_PbpyFieldPlan] = []
        self.by_num: dict[int, _PbpyFieldPlan] = {}
        self._schema_meta: SchemaMeta | None = None
        self._field0_wire: bytes | None = None
        self.rust_codec: CompiledCodec[Any] = CompiledCodec(
            desc.type,
            desc.name,
            fast_alloc=False,
            pbpy_mode=True,
        )

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

    def finalize_rust_codec(self) -> None:
        specs: list[dict[str, Any]] = []
        for fp in self.fields:
            spec: dict[str, Any] = {
                "number": fp.field_num,
                "attr": fp.local_name,
                "wire_name": fp.proto_name,
                "kind": fp.kind,
                "wire_type": fp.wire_type,
                "pbpy_presence": fp.has_presence,
                "skip_if_none": fp.kind == "submsg",
                "default_mode": "pbpy",
            }
            if fp.enum_cls is not None:
                spec["enum_cls"] = fp.enum_cls
            if fp.kind == "submsg":
                assert fp.sub_plan is not None
                spec["sub_codec"] = fp.sub_plan.rust_codec
            elif fp.kind == "list_scalar":
                spec["elem_kind"] = fp.elem_kind
                spec["elem_wt"] = fp.elem_wt
            elif fp.kind == "list_submsg":
                assert fp.sub_plan is not None
                spec["sub_codec"] = fp.sub_plan.rust_codec
            elif fp.kind == "map":
                spec["key_kind"] = fp.key_kind
                spec["key_wt"] = fp.key_wt
                spec["val_kind"] = fp.val_kind
                spec["val_wt"] = fp.val_wt
                if fp.val_kind == "submsg":
                    assert fp.sub_plan is not None
                    spec["sub_codec"] = fp.sub_plan.rust_codec
            specs.append(spec)
        self.rust_codec.set_fields(specs, self.get_field0_wire())


_PBPY_LOCK = threading.RLock()
_PBPY_PLAN_CACHE: dict[str, _PbpyMsgPlan] = {}
_PBPY_RUST_BY_CLS: dict[type[Any], CompiledCodec[Any]] = {}
_PBPY_BUILDING: dict[str, _PbpyMsgPlan] = {}
_PBPY_PENDING_FINALIZE: list[_PbpyMsgPlan] = []


def _get_pbpy_plan(desc: pbpy.DescMessage) -> _PbpyMsgPlan:
    key = desc.type_name
    cached = _PBPY_PLAN_CACHE.get(key)
    if cached is not None:
        return cached
    with _PBPY_LOCK:
        cached = _PBPY_PLAN_CACHE.get(key)
        if cached is not None:
            return cached
        in_prog = _PBPY_BUILDING.get(key)
        if in_prog is not None:
            return in_prog

        if getattr(desc, "extensions", None):
            raise OmniBufEncodeError(
                f"omnibuf: protobuf extensions are not supported on {desc.type_name}"
            )

        is_root = not _PBPY_BUILDING
        plan = _PbpyMsgPlan(desc)
        _PBPY_BUILDING[key] = plan
        try:
            compiled: list[_PbpyFieldPlan] = []
            for fd in desc.fields:
                fnum = fd.number
                has_pres = int(fd.presence) == 1  # SupportedFieldPresence.EXPLICIT == 1
                fval = fd.value
                encoding_val = getattr(fd, "encoding", None)
                if encoding_val is not None and str(encoding_val).endswith("DELIMITED"):
                    raise OmniBufEncodeError(
                        f"omnibuf: Proto2 group / delimited encoding is not supported on {desc.type_name}.{fd.name}"
                    )

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
            _PBPY_PENDING_FINALIZE.append(plan)
            if is_root:
                pending = list(_PBPY_PENDING_FINALIZE)
                _PBPY_PENDING_FINALIZE.clear()
                for p_plan in pending:
                    p_plan.finalize_rust_codec()
                for p_plan in pending:
                    _PBPY_PLAN_CACHE[p_plan.desc.type_name] = p_plan
                    _PBPY_RUST_BY_CLS[p_plan.msg_cls] = p_plan.rust_codec
        except Exception:
            if is_root:
                _PBPY_PENDING_FINALIZE.clear()
            raise
        finally:
            _PBPY_BUILDING.pop(key, None)
        return plan


# ============================================================================
# Secondary Compatibility Codec: google.protobuf (_pb2.py)
# ============================================================================


def _is_gpb_repeated(fd: Any) -> bool:
    return bool(getattr(fd, "is_repeated", False))


def _is_gpb_map_field(fd: Any) -> bool:
    return bool(
        _is_gpb_repeated(fd)
        and fd.type == _GPB_TYPE_MESSAGE
        and fd.message_type is not None
        and fd.message_type.has_options
        and fd.message_type.GetOptions().map_entry
    )


def _check_gpb_descriptor_supported(desc: Any, *, for_encode: bool) -> None:
    err_cls = OmniBufEncodeError if for_encode else OmniBufDecodeError
    if getattr(desc, "extension_ranges", None) or getattr(desc, "extensions", None):
        raise err_cls(f"omnibuf: Proto2 extensions are not supported on {desc.full_name}")
    for fd in desc.fields:
        if fd.type == _GPB_TYPE_GROUP:
            raise err_cls(
                f"omnibuf: Proto2 group field {desc.full_name}.{fd.name} is not supported"
            )


def _build_gpb_schema_meta(
    desc: Any,
    msg: Any = None,
    schema_depth: int = 1,
    visiting: frozenset[str] = frozenset(),
) -> SchemaMeta:
    meta = SchemaMeta(type_name=str(desc.name))
    if schema_depth + 1 > MAX_NESTING_DEPTH:
        return meta
    next_visiting = visiting | {str(desc.full_name)}
    for fd in desc.fields:
        fnum = int(fd.number)
        meta.fields[fnum] = str(fd.name)
        if schema_depth + 3 > MAX_NESTING_DEPTH:
            continue
        if _is_gpb_map_field(fd):
            assert fd.message_type is not None
            val_fd = fd.message_type.fields_by_name["value"]
            if val_fd.type == _GPB_TYPE_MESSAGE and val_fd.message_type is not None:
                if msg is not None:
                    mp = getattr(msg, fd.name)
                    merged: SchemaMeta | None = None
                    for v in mp.values():
                        c_meta = _build_gpb_schema_meta(
                            val_fd.message_type, v, schema_depth + 2, frozenset()
                        )
                        merged = merge_schema_meta(merged, c_meta)
                    if merged is not None:
                        meta.children[fnum] = merged
                    elif val_fd.message_type.full_name not in next_visiting:
                        meta.children[fnum] = _build_gpb_schema_meta(
                            val_fd.message_type, None, schema_depth + 2, next_visiting
                        )
                elif val_fd.message_type.full_name not in next_visiting:
                    meta.children[fnum] = _build_gpb_schema_meta(
                        val_fd.message_type, None, schema_depth + 2, next_visiting
                    )
        elif fd.type == _GPB_TYPE_MESSAGE and fd.message_type is not None:
            if _is_gpb_repeated(fd):
                if msg is not None:
                    seq = getattr(msg, fd.name)
                    merged_rep: SchemaMeta | None = None
                    for item in seq:
                        c_meta = _build_gpb_schema_meta(
                            fd.message_type, item, schema_depth + 2, frozenset()
                        )
                        merged_rep = merge_schema_meta(merged_rep, c_meta)
                    if merged_rep is not None:
                        meta.children[fnum] = merged_rep
                    elif fd.message_type.full_name not in next_visiting:
                        meta.children[fnum] = _build_gpb_schema_meta(
                            fd.message_type, None, schema_depth + 2, next_visiting
                        )
                elif fd.message_type.full_name not in next_visiting:
                    meta.children[fnum] = _build_gpb_schema_meta(
                        fd.message_type, None, schema_depth + 2, next_visiting
                    )
            else:
                if msg is not None and msg.HasField(fd.name):
                    meta.children[fnum] = _build_gpb_schema_meta(
                        fd.message_type,
                        getattr(msg, fd.name),
                        schema_depth + 2,
                        frozenset(),
                    )
                elif fd.message_type.full_name not in next_visiting:
                    meta.children[fnum] = _build_gpb_schema_meta(
                        fd.message_type, None, schema_depth + 2, next_visiting
                    )
    return meta


def _encode_gpb_msg(dst: bytearray, msg: Any, deterministic: bool) -> None:
    desc: Any = msg.DESCRIPTOR
    _check_gpb_descriptor_supported(desc, for_encode=True)
    for list_fd, _ in msg.ListFields():
        if getattr(list_fd, "is_extension", False):
            raise OmniBufEncodeError(
                f"omnibuf: Proto2 extension field {list_fd.full_name} is not supported"
            )
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
            if v_fd.type == _GPB_TYPE_GROUP:
                raise OmniBufEncodeError(
                    f"omnibuf: Proto2 group field on {desc.full_name}.{fd.name} is not supported"
                )
            k_kind, k_wt = _GPB_SCALAR_SPEC[k_fd.type]
            is_v_msg = v_fd.type == _GPB_TYPE_MESSAGE
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
            is_msg = fd.type == _GPB_TYPE_MESSAGE
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
        elif fd.type == _GPB_TYPE_MESSAGE:
            dst.extend(encode_tag(fnum, WIRE_SUB_MSG))
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            _encode_gpb_msg(dst, val, deterministic)
            backpatch_container_len(dst, len_pos)
        elif fd.type == _GPB_TYPE_BOOL:
            dst.extend(encode_tag(fnum, WIRE_BOOL_TRUE if val else WIRE_BOOL_FALSE))
        else:
            s_kind, s_wt = _GPB_SCALAR_SPEC[fd.type]
            dst.extend(encode_tag(fnum, s_wt))
            _write_proto_scalar(dst, s_kind, val, fd.name)


def _decode_gpb_msg(data: memoryview, dst: Any, depth: int, merge: bool) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    desc = dst.DESCRIPTOR
    _check_gpb_descriptor_supported(desc, for_encode=False)
    if not merge:
        dst.Clear()

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
            is_v_msg = v_fd.type == _GPB_TYPE_MESSAGE
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
            is_msg = fd.type == _GPB_TYPE_MESSAGE
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
        elif fd.type == _GPB_TYPE_MESSAGE:
            if wt != WIRE_SUB_MSG:
                pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
                continue
            sub_mv, pos = read_len_slice(data, pos, 0, n)
            sub_msg = getattr(dst, fd.name)
            sub_msg.SetInParent()
            _decode_gpb_msg(sub_mv, sub_msg, depth + 1, already_seen)
        elif fd.type == _GPB_TYPE_BOOL:
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
    if isinstance(obj, (pbpy.Message, pbpy.DescMessage)):
        return True
    if isinstance(obj, type) and issubclass(obj, pbpy.Message):
        return True
    # Avoid importing google.protobuf for standard dataclasses / user classes without DESCRIPTOR
    if not hasattr(obj, "DESCRIPTOR"):
        return False
    gpb_cls = _get_gpb_message_cls()
    if gpb_cls is None:
        return False
    if isinstance(obj, gpb_cls):
        return True
    return isinstance(obj, type) and issubclass(obj, gpb_cls)


def marshal_proto(
    msg: pbpy.Message[Any] | GpbMessage,
    *,
    deterministic: bool = False,
    self_describing: bool = False,
) -> bytes:
    """Serializes a protobuf-py Message (primary) or google.protobuf Message into OmniBuf wire bytes."""
    rc = _PBPY_RUST_BY_CLS.get(type(msg))
    if rc is not None:
        return rc.marshal(msg, deterministic=deterministic, self_describing=self_describing)
    if isinstance(msg, pbpy.Message):
        plan = _get_pbpy_plan(msg.desc())
        return plan.rust_codec.marshal(
            msg,
            deterministic=deterministic,
            self_describing=self_describing,
        )
    gpb_cls = _get_gpb_message_cls()
    if gpb_cls is not None and isinstance(msg, gpb_cls):
        out = bytearray()
        if self_describing:
            meta = _build_gpb_schema_meta(msg.DESCRIPTOR, msg)
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
    if isinstance(target, type):
        rc = _PBPY_RUST_BY_CLS.get(target)
        if rc is not None:
            return rc.unmarshal(packet)
        if issubclass(target, pbpy.Message):
            plan = _get_pbpy_plan(target.desc())
            return plan.rust_codec.unmarshal(packet)
        gpb_cls = _get_gpb_message_cls()
        if gpb_cls is not None and issubclass(target, gpb_cls):
            g_inst = target()
            mv = memoryview(bytes(packet)) if not isinstance(packet, bytes) else memoryview(packet)
            _decode_gpb_msg(mv, g_inst, 0, False)
            return g_inst
    else:
        rc = _PBPY_RUST_BY_CLS.get(type(target))
        if rc is not None:
            return rc.unmarshal(packet, target)
        if isinstance(target, pbpy.DescMessage):
            plan = _get_pbpy_plan(target)
            return plan.rust_codec.unmarshal(packet)
        if isinstance(target, pbpy.Message):
            plan = _get_pbpy_plan(target.desc())
            return plan.rust_codec.unmarshal(packet, target)
        gpb_cls = _get_gpb_message_cls()
        if gpb_cls is not None and isinstance(target, gpb_cls):
            mv = memoryview(bytes(packet)) if not isinstance(packet, bytes) else memoryview(packet)
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
