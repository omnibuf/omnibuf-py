"""Idiomatic @omnibuf_message dataclass codec (Tier 3: Annotated Structs)."""

from __future__ import annotations

import dataclasses
import struct
import sys
import types
import typing
from collections.abc import Callable
from dataclasses import MISSING, Field, dataclass
from typing import Annotated, Any, Literal, Union, dataclass_transform, overload

from .encoder import Encoder
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

type WireName = Literal[
    "uint",
    "uint32",
    "uint64",
    "sint",
    "sint32",
    "sint64",
    "bool",
    "fixed32",
    "sfixed32",
    "fixed64",
    "sfixed64",
    "float32",
    "float64",
    "string",
    "bytes",
    "submsg",
    "array",
    "map",
]


@dataclass(slots=True, frozen=True)
class _WireHint:
    wire: WireName


# Annotated scalar type aliases for ergonomic dataclass declarations
Uint32 = Annotated[int, _WireHint("uint32")]
Uint64 = Annotated[int, _WireHint("uint64")]
Sint32 = Annotated[int, _WireHint("sint32")]
Sint64 = Annotated[int, _WireHint("sint64")]
Fixed32 = Annotated[int, _WireHint("fixed32")]
Sfixed32 = Annotated[int, _WireHint("sfixed32")]
Fixed64 = Annotated[int, _WireHint("fixed64")]
Sfixed64 = Annotated[int, _WireHint("sfixed64")]
Float32 = Annotated[float, _WireHint("float32")]
Float64 = Annotated[float, _WireHint("float64")]

_META_KEY = "omnibuf"


@dataclass(slots=True, frozen=True)
class FieldInfo:
    """Per-field metadata stored inside dataclasses.Field.metadata['omnibuf']."""

    field_num: int
    name: str | None = None
    wire: WireName | None = None
    elem_wire: WireName | None = None
    key_wire: WireName | None = None
    val_wire: WireName | None = None
    omitempty: bool = False


@overload
def omnibuf_field[T](
    field_num: int,
    *,
    default: T,
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> T: ...


@overload
def omnibuf_field[T](
    field_num: int,
    *,
    default_factory: Callable[[], T],
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> T: ...


@overload
def omnibuf_field(
    field_num: int,
    *,
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> Any: ...


def omnibuf_field(
    field_num: int,
    *,
    default: Any = MISSING,
    default_factory: Any = MISSING,
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> Any:
    """Declares an OmniBuf field number and optional wire overrides on a dataclass field."""
    if field_num <= 0 or field_num > MAX_FIELD_NUMBER:
        raise ValueError(f"omnibuf: invalid field number {field_num}")
    info = FieldInfo(
        field_num=field_num,
        name=name,
        wire=wire,
        elem_wire=elem_wire,
        key_wire=key_wire,
        val_wire=val_wire,
        omitempty=omitempty,
    )
    meta = {_META_KEY: info}
    if default is not MISSING and default_factory is not MISSING:
        raise ValueError("omnibuf: cannot specify both default and default_factory")
    if default_factory is not MISSING:
        return dataclasses.field(default_factory=default_factory, metadata=meta)
    if default is not MISSING:
        return dataclasses.field(default=default, metadata=meta)
    return dataclasses.field(metadata=meta)


_REGISTERED_TYPES: dict[str, type[Any]] = {}
_CODEC_CACHE: dict[type[Any], _StructCodec] = {}
_BUILDING_CODECS: dict[type[Any], _StructCodec] = {}

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


def _apply_default_if_missing(cls: type[Any]) -> None:
    """Allows @omnibuf_message classes to omit boilerplate default=0 / default_factory=list."""
    annotations = getattr(cls, "__annotations__", None)
    if not annotations:
        return
    for attr_name in annotations:
        if attr_name not in cls.__dict__:
            continue
        val = cls.__dict__[attr_name]
        if isinstance(val, Field) and val.default is MISSING and val.default_factory is MISSING:
            # Inspect raw string/type hint to choose sensible default when omitted
            raw_ann = annotations[attr_name]
            ann_str = raw_ann if isinstance(raw_ann, str) else repr(raw_ann)
            meta = dict(val.metadata)
            if "None" in ann_str:
                setattr(cls, attr_name, dataclasses.field(default=None, metadata=meta))
            elif ann_str.startswith(("list[", "typing.List[", "List[")):
                setattr(cls, attr_name, dataclasses.field(default_factory=list, metadata=meta))
            elif ann_str.startswith(("dict[", "typing.Dict[", "Dict[")):
                setattr(cls, attr_name, dataclasses.field(default_factory=dict, metadata=meta))
            elif raw_ann is bool or ann_str == "bool":
                setattr(cls, attr_name, dataclasses.field(default=False, metadata=meta))
            elif raw_ann is str or ann_str == "str":
                setattr(cls, attr_name, dataclasses.field(default="", metadata=meta))
            elif raw_ann in (bytes, bytearray) or ann_str in ("bytes", "bytearray"):
                setattr(cls, attr_name, dataclasses.field(default=b"", metadata=meta))
            elif raw_ann is float or ann_str in ("float", "Float32", "Float64"):
                setattr(cls, attr_name, dataclasses.field(default=0.0, metadata=meta))
            elif raw_ann is int or ann_str in (
                "int",
                "Uint32",
                "Uint64",
                "Sint32",
                "Sint64",
                "Fixed32",
                "Sfixed32",
                "Fixed64",
                "Sfixed64",
            ):
                setattr(cls, attr_name, dataclasses.field(default=0, metadata=meta))


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message[T](cls: type[T], /) -> type[T]: ...


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message[T](
    type_name: str,
    /,
    *,
    slots: bool = True,
) -> Callable[[type[T]], type[T]]: ...


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message[T](
    *,
    type_name: str | None = None,
    slots: bool = True,
) -> Callable[[type[T]], type[T]]: ...


def omnibuf_message(
    cls_or_name: type[Any] | str | None = None,
    /,
    *,
    type_name: str | None = None,
    slots: bool = True,
) -> Any:
    """Marks a dataclass as an OmniBuf message (automatically applying @dataclass if needed)."""
    resolved_name = cls_or_name if isinstance(cls_or_name, str) else type_name

    def wrap(target: type[Any]) -> type[Any]:
        if not dataclasses.is_dataclass(target):
            _apply_default_if_missing(target)
            target = dataclass(slots=slots)(target)
        setattr(target, "__omnibuf_type_name__", resolved_name or target.__name__)  # noqa: B010
        _REGISTERED_TYPES[target.__name__] = target
        return target

    if isinstance(cls_or_name, type):
        return wrap(cls_or_name)
    return wrap


def _unwrap_annotated(tp: Any) -> tuple[Any, WireName | None]:
    origin = typing.get_origin(tp)
    if origin is Annotated:
        args = typing.get_args(tp)
        base = args[0]
        hint_wire: WireName | None = None
        for extra in args[1:]:
            if isinstance(extra, _WireHint):
                hint_wire = extra.wire
        inner_base, inner_wire = _unwrap_annotated(base)
        return inner_base, hint_wire or inner_wire
    return tp, None


def _unwrap_optional(tp: Any) -> tuple[Any, bool]:
    origin = typing.get_origin(tp)
    if origin is Annotated:
        args = typing.get_args(tp)
        inner_non_opt, is_opt = _unwrap_optional(args[0])
        if is_opt:
            return Annotated[(inner_non_opt, *args[1:])], True
        return tp, False
    if origin in (Union, types.UnionType):
        args = typing.get_args(tp)
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1 and len(non_none) < len(args):
            return non_none[0], True
    return tp, False


def _scalar_spec(py_type: Any, wire_opt: WireName | None) -> tuple[str, int]:
    """Maps (Python scalar type, optional wire override) to (scalar_kind, wire_type)."""
    base, ann_wire = _unwrap_annotated(py_type)
    eff = wire_opt or ann_wire

    if base is bool:
        if eff not in (None, "bool"):
            raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for bool")
        return "bool", WIRE_BOOL_FALSE

    if base is str:
        if eff in (None, "string"):
            return "string", WIRE_STRING
        if eff == "bytes":
            return "str_as_bytes", WIRE_BYTES
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for str")

    if base in (bytes, bytearray):
        if eff in (None, "bytes"):
            return "bytes", WIRE_BYTES
        if eff == "string":
            return "bytes_as_str", WIRE_STRING
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for bytes")

    if base is float:
        if eff == "float32":
            return "float32", WIRE_FLOAT32
        if eff in (None, "float64"):
            return "float64", WIRE_FLOAT64
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for float")

    if base is int:
        if eff == "uint32":
            return "uint32", WIRE_UINT
        if eff in ("uint", "uint64"):
            return "uint64", WIRE_UINT
        if eff == "sint32":
            return "sint32", WIRE_SINT
        if eff in (None, "sint", "sint64"):
            return "sint64", WIRE_SINT
        if eff == "fixed32":
            return "fixed32", WIRE_FIXED32
        if eff == "sfixed32":
            return "sfixed32", WIRE_SFIXED32
        if eff == "fixed64":
            return "fixed64", WIRE_FIXED64
        if eff == "sfixed64":
            return "sfixed64", WIRE_SFIXED64
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for int")

    raise OmniBufEncodeError(f"omnibuf: unsupported scalar type {py_type!r}")


@dataclass(slots=True)
class _FieldCodec:
    index: int
    attr: str
    field_num: int
    wire_name: str
    kind: str  # scalar kind or "submsg" | "array_scalar" | "array_submsg" | "map"
    wire_type: int
    tag_bytes: bytes
    tag_false: bytes  # for bool
    tag_true: bytes  # for bool
    optional: bool
    omitempty: bool
    elem_kind: str = ""
    elem_wt: int = 0
    elem_optional: bool = False
    key_kind: str = ""
    key_wt: int = 0
    val_kind: str = ""
    val_wt: int = 0
    val_optional: bool = False
    sub_type: type[Any] | None = None
    sub_codec: _StructCodec | None = None
    default_val: Any = None
    default_factory: Callable[[], Any] | None = None

    def make_default(self) -> Any:
        if self.optional:
            return None
        if self.default_factory is not None:
            return self.default_factory()
        if self.kind == "submsg" and self.sub_type is not None:
            return self.sub_type()
        if self.kind in ("array_scalar", "array_submsg"):
            return []
        if self.kind == "map":
            return {}
        return self.default_val


class _StructCodec:
    __slots__ = (
        "cls",
        "type_name",
        "fields",
        "by_num",
        "_schema_meta",
        "_field0_wire",
        "fast_encode_fn",
    )

    def __init__(self, cls: type[Any], type_name: str) -> None:
        self.cls = cls
        self.type_name = type_name
        self.fields: list[_FieldCodec] = []
        self.by_num: dict[int, _FieldCodec] = {}
        self._schema_meta: SchemaMeta | None = None
        self._field0_wire: bytes | None = None
        self.fast_encode_fn: Callable[[bytearray, Any, bool], None] | None = None

    def get_schema_meta(self, visiting: frozenset[type[Any]] = frozenset()) -> SchemaMeta:
        if self._schema_meta is not None and not visiting:
            return self._schema_meta
        meta = SchemaMeta(type_name=self.type_name)
        next_visiting = visiting | {self.cls}
        for fc in self.fields:
            meta.fields[fc.field_num] = fc.wire_name
            if fc.sub_codec is not None and fc.sub_codec.cls not in next_visiting:
                meta.children[fc.field_num] = fc.sub_codec.get_schema_meta(next_visiting)
        if not visiting:
            self._schema_meta = meta
        return meta

    def get_field0_wire(self) -> bytes:
        if self._field0_wire is None:
            self._field0_wire = encode_field0_schema_meta(self.get_schema_meta())
        return self._field0_wire


def _resolve_type_hints(cls: type[Any]) -> dict[str, Any]:
    mod = sys.modules.get(cls.__module__)
    globalns: dict[str, Any] = dict(vars(mod)) if mod is not None else {}
    localns: dict[str, Any] = dict(_REGISTERED_TYPES)
    localns[cls.__name__] = cls
    return typing.get_type_hints(cls, globalns=globalns, localns=localns, include_extras=True)


def _get_struct_codec(cls: type[Any]) -> _StructCodec:
    cached = _CODEC_CACHE.get(cls)
    if cached is not None:
        return cached
    in_progress = _BUILDING_CODECS.get(cls)
    if in_progress is not None:
        return in_progress
    if not dataclasses.is_dataclass(cls):
        raise OmniBufEncodeError(f"omnibuf: {cls!r} is not an @omnibuf_message / @dataclass")

    type_name = getattr(cls, "__omnibuf_type_name__", cls.__name__)
    sc = _StructCodec(cls, str(type_name))
    _BUILDING_CODECS[cls] = sc
    try:
        hints = _resolve_type_hints(cls)
        dc_fields = dataclasses.fields(cls)
        compiled: list[_FieldCodec] = []
        seen_nums: set[int] = set()

        for dc_f in dc_fields:
            info = dc_f.metadata.get(_META_KEY)
            if not isinstance(info, FieldInfo):
                continue
            fnum = info.field_num
            if fnum in seen_nums:
                raise OmniBufEncodeError(
                    f"omnibuf: duplicate field number {fnum} on {cls.__name__}"
                )
            seen_nums.add(fnum)

            wire_name = info.name or dc_f.name
            raw_tp = hints.get(dc_f.name, dc_f.type)
            unwrapped_opt, is_opt = _unwrap_optional(raw_tp)
            base_tp, ann_wire = _unwrap_annotated(unwrapped_opt)
            origin = typing.get_origin(base_tp)

            def_val = None if dc_f.default is MISSING else dc_f.default
            def_fac = None if dc_f.default_factory is MISSING else dc_f.default_factory

            if origin is list:
                args = typing.get_args(base_tp)
                if len(args) != 1:
                    raise OmniBufEncodeError(
                        f"omnibuf: list field {dc_f.name} requires element type"
                    )
                elem_raw = args[0]
                elem_no_opt, elem_is_opt = _unwrap_optional(elem_raw)
                elem_base, elem_ann_wire = _unwrap_annotated(elem_no_opt)
                tag_b = encode_tag(fnum, WIRE_ARRAY)
                if isinstance(elem_base, type) and dataclasses.is_dataclass(elem_base):
                    sub_sc = _get_struct_codec(elem_base)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="array_submsg",
                        wire_type=WIRE_ARRAY,
                        tag_bytes=tag_b,
                        tag_false=b"",
                        tag_true=b"",
                        optional=is_opt,
                        omitempty=info.omitempty,
                        elem_kind="submsg",
                        elem_wt=WIRE_SUB_MSG,
                        elem_optional=elem_is_opt,
                        sub_type=elem_base,
                        sub_codec=sub_sc,
                        default_val=def_val,
                        default_factory=def_fac,
                    )
                else:
                    eff_elem_wire = (
                        info.elem_wire
                        or (info.wire if info.wire not in (None, "array") else None)
                        or elem_ann_wire
                    )
                    e_kind, e_wt = _scalar_spec(elem_base, eff_elem_wire)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="array_scalar",
                        wire_type=WIRE_ARRAY,
                        tag_bytes=tag_b,
                        tag_false=b"",
                        tag_true=b"",
                        optional=is_opt,
                        omitempty=info.omitempty,
                        elem_kind=e_kind,
                        elem_wt=e_wt,
                        default_val=def_val,
                        default_factory=def_fac,
                    )
            elif origin is dict:
                args = typing.get_args(base_tp)
                if len(args) != 2:
                    raise OmniBufEncodeError(
                        f"omnibuf: dict field {dc_f.name} requires [K, V] types"
                    )
                k_raw, v_raw = args
                k_base, k_ann = _unwrap_annotated(k_raw)
                k_kind, k_wt = _scalar_spec(k_base, info.key_wire or k_ann)
                if k_wt not in (
                    WIRE_UINT,
                    WIRE_SINT,
                    WIRE_BOOL_FALSE,
                    WIRE_FIXED32,
                    WIRE_FIXED64,
                    WIRE_SFIXED32,
                    WIRE_SFIXED64,
                    WIRE_STRING,
                ):
                    raise OmniBufEncodeError(
                        f"omnibuf: invalid map key wire type {k_wt} on {dc_f.name}"
                    )
                v_no_opt, v_is_opt = _unwrap_optional(v_raw)
                v_base, v_ann = _unwrap_annotated(v_no_opt)
                tag_b = encode_tag(fnum, WIRE_MAP)
                if isinstance(v_base, type) and dataclasses.is_dataclass(v_base):
                    sub_sc = _get_struct_codec(v_base)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="map",
                        wire_type=WIRE_MAP,
                        tag_bytes=tag_b,
                        tag_false=b"",
                        tag_true=b"",
                        optional=is_opt,
                        omitempty=info.omitempty,
                        key_kind=k_kind,
                        key_wt=k_wt,
                        val_kind="submsg",
                        val_wt=WIRE_SUB_MSG,
                        val_optional=v_is_opt,
                        sub_type=v_base,
                        sub_codec=sub_sc,
                        default_val=def_val,
                        default_factory=def_fac,
                    )
                else:
                    eff_val_wire = (
                        info.val_wire
                        or (info.wire if info.wire not in (None, "map") else None)
                        or v_ann
                    )
                    v_kind, v_wt = _scalar_spec(v_base, eff_val_wire)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="map",
                        wire_type=WIRE_MAP,
                        tag_bytes=tag_b,
                        tag_false=b"",
                        tag_true=b"",
                        optional=is_opt,
                        omitempty=info.omitempty,
                        key_kind=k_kind,
                        key_wt=k_wt,
                        val_kind=v_kind,
                        val_wt=v_wt,
                        default_val=def_val,
                        default_factory=def_fac,
                    )
            elif isinstance(base_tp, type) and dataclasses.is_dataclass(base_tp):
                sub_sc = _get_struct_codec(base_tp)
                tag_b = encode_tag(fnum, WIRE_SUB_MSG)
                fc = _FieldCodec(
                    index=len(compiled),
                    attr=dc_f.name,
                    field_num=fnum,
                    wire_name=wire_name,
                    kind="submsg",
                    wire_type=WIRE_SUB_MSG,
                    tag_bytes=tag_b,
                    tag_false=b"",
                    tag_true=b"",
                    optional=is_opt,
                    omitempty=info.omitempty,
                    sub_type=base_tp,
                    sub_codec=sub_sc,
                    default_val=def_val,
                    default_factory=def_fac,
                )
            else:
                s_kind, s_wt = _scalar_spec(base_tp, info.wire or ann_wire)
                if s_kind == "bool":
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="bool",
                        wire_type=WIRE_BOOL_FALSE,
                        tag_bytes=b"",
                        tag_false=encode_tag(fnum, WIRE_BOOL_FALSE),
                        tag_true=encode_tag(fnum, WIRE_BOOL_TRUE),
                        optional=is_opt,
                        omitempty=info.omitempty,
                        default_val=False if def_val is None else def_val,
                        default_factory=def_fac,
                    )
                else:
                    default_scalar: Any = def_val
                    if default_scalar is None:
                        if s_kind in ("string", "str_as_bytes"):
                            default_scalar = ""
                        elif s_kind in ("bytes", "bytes_as_str"):
                            default_scalar = b""
                        elif s_kind in ("float32", "float64"):
                            default_scalar = 0.0
                        else:
                            default_scalar = 0
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind=s_kind,
                        wire_type=s_wt,
                        tag_bytes=encode_tag(fnum, s_wt),
                        tag_false=b"",
                        tag_true=b"",
                        optional=is_opt,
                        omitempty=info.omitempty,
                        default_val=default_scalar,
                        default_factory=def_fac,
                    )
            compiled.append(fc)

        compiled.sort(key=lambda item: item.field_num)
        for idx, fc in enumerate(compiled):
            fc.index = idx
            sc.by_num[fc.field_num] = fc
        sc.fields = compiled
        _CODEC_CACHE[cls] = sc
    finally:
        _BUILDING_CODECS.pop(cls, None)
    return sc


def _is_value_empty(fc: _FieldCodec, val: Any) -> bool:
    if val is None:
        return True
    if fc.kind == "bool":
        return not bool(val)
    if fc.kind in (
        "uint32",
        "uint64",
        "sint32",
        "sint64",
        "fixed32",
        "sfixed32",
        "fixed64",
        "sfixed64",
    ):
        return bool(val == 0)
    if fc.kind in ("float32", "float64"):
        return bool(val == 0.0)
    if fc.kind in (
        "string",
        "str_as_bytes",
        "bytes",
        "bytes_as_str",
        "array_scalar",
        "array_submsg",
        "map",
    ):
        return len(val) == 0
    if fc.kind == "submsg" and fc.sub_codec is not None:
        return all(
            _is_value_empty(sub_fc, getattr(val, sub_fc.attr)) for sub_fc in fc.sub_codec.fields
        )
    return False


def _write_scalar_payload(dst: bytearray, kind: str, val: Any, field_name: str) -> None:
    if kind == "bool":
        dst.append(1 if val else 0)
    elif kind == "uint32":
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} uint32 {val} out of range")
        append_varint(dst, val)
    elif kind == "uint64":
        if val < 0 or val > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} uint64 {val} out of range")
        append_varint(dst, val)
    elif kind == "sint32":
        append_varint(dst, encode_zigzag32(val))
    elif kind == "sint64":
        append_varint(dst, encode_zigzag(val))
    elif kind == "fixed32":
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} fixed32 {val} out of range")
        dst.extend(_U32_PACK(val))
    elif kind == "sfixed32":
        if val < INT32_MIN or val > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} sfixed32 {val} out of range")
        dst.extend(_I32_PACK(val))
    elif kind == "fixed64":
        if val < 0 or val > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} fixed64 {val} out of range")
        dst.extend(_U64_PACK(val))
    elif kind == "sfixed64":
        if val < INT64_MIN or val > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} sfixed64 {val} out of range")
        dst.extend(_I64_PACK(val))
    elif kind == "float32":
        try:
            dst.extend(_F32_PACK(val))
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: field {field_name} float32 overflow") from exc
    elif kind == "float64":
        dst.extend(_F64_PACK(val))
    elif kind == "string" or kind == "str_as_bytes":
        raw = encode_utf8_strict(val, field_name)
        append_varint(dst, len(raw))
        dst.extend(raw)
    elif kind == "bytes":
        append_varint(dst, len(val))
        dst.extend(val)
    elif kind == "bytes_as_str":
        decode_utf8_strict(val, 0)
        append_varint(dst, len(val))
        dst.extend(val)
    else:
        raise OmniBufEncodeError(f"omnibuf: unknown scalar kind {kind!r}")


def _encode_struct_into(
    dst: bytearray,
    sc: _StructCodec,
    obj: Any,
    deterministic: bool,
) -> None:
    for fc in sc.fields:
        val = getattr(obj, fc.attr)
        if val is None:
            if fc.optional:
                continue
            val = fc.make_default()
        if fc.omitempty and _is_value_empty(fc, val):
            continue

        kind = fc.kind
        if kind == "bool":
            dst.extend(fc.tag_true if val else fc.tag_false)
            continue

        dst.extend(fc.tag_bytes)
        if kind in (
            "uint32",
            "uint64",
            "sint32",
            "sint64",
            "fixed32",
            "sfixed32",
            "fixed64",
            "sfixed64",
            "float32",
            "float64",
            "string",
            "str_as_bytes",
            "bytes",
            "bytes_as_str",
        ):
            _write_scalar_payload(dst, kind, val, fc.wire_name)
        elif kind == "submsg":
            assert fc.sub_codec is not None
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            _encode_struct_into(dst, fc.sub_codec, val, deterministic)
            backpatch_container_len(dst, len_pos)
        elif kind == "array_scalar":
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(fc.elem_wt)
            append_varint(dst, len(val))
            e_kind = fc.elem_kind
            for item in val:
                _write_scalar_payload(dst, e_kind, item, fc.wire_name)
            backpatch_container_len(dst, len_pos)
        elif kind == "array_submsg":
            assert fc.sub_codec is not None
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(WIRE_SUB_MSG)
            append_varint(dst, len(val))
            sub_sc = fc.sub_codec
            for item in val:
                elem_len_pos = len(dst)
                dst.extend(b"\x00\x00")
                if item is not None:
                    _encode_struct_into(dst, sub_sc, item, deterministic)
                backpatch_container_len(dst, elem_len_pos)
            backpatch_container_len(dst, len_pos)
        elif kind == "map":
            len_pos = len(dst)
            dst.extend(b"\x00\x00")
            dst.append(fc.key_wt)
            dst.append(fc.val_wt)
            append_varint(dst, len(val))
            keys = sorted(val.keys()) if deterministic and len(val) > 1 else val.keys()
            k_kind = fc.key_kind
            v_kind = fc.val_kind
            map_sub_sc = fc.sub_codec
            for k in keys:
                v = val[k]
                _write_scalar_payload(dst, k_kind, k, fc.wire_name)
                if v_kind == "submsg":
                    assert map_sub_sc is not None
                    v_len_pos = len(dst)
                    dst.extend(b"\x00\x00")
                    if v is not None:
                        _encode_struct_into(dst, map_sub_sc, v, deterministic)
                    backpatch_container_len(dst, v_len_pos)
                else:
                    _write_scalar_payload(dst, v_kind, v, fc.wire_name)
            backpatch_container_len(dst, len_pos)


def _read_scalar_payload(
    mv: memoryview,
    pos: int,
    end: int,
    kind: str,
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
    if kind == "str_as_bytes":
        s_pos = pos
        raw, next_pos = read_len_slice(mv, pos, 0, end)
        return decode_utf8_strict(raw, s_pos), next_pos
    if kind == "bytes":
        raw, next_pos = read_len_slice(mv, pos, 0, end)
        return bytes(raw), next_pos
    if kind == "bytes_as_str":
        s_pos = pos
        raw, next_pos = read_len_slice(mv, pos, 0, end)
        decode_utf8_strict(raw, s_pos)
        return bytes(raw), next_pos
    raise OmniBufDecodeError(f"omnibuf: unsupported scalar kind {kind!r}")


def _decode_struct_into(
    data: memoryview,
    sc: _StructCodec,
    dst: Any,
    depth: int,
    merge: bool,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds {MAX_NESTING_DEPTH}")
    n = len(data)
    pos = 0
    seen_mask = 0
    by_num = sc.by_num

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

        fc = by_num.get(fnum)
        if fc is None:
            pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        is_bool = fc.kind == "bool"
        if (is_bool and wt not in (WIRE_BOOL_FALSE, WIRE_BOOL_TRUE)) or (
            not is_bool and fc.wire_type != wt
        ):
            pos = validate_value(data, pos, wt, depth, MAX_NESTING_DEPTH, n)
            continue

        bit = 1 << fc.index
        already_seen = ((seen_mask & bit) != 0) or merge
        seen_mask |= bit

        kind = fc.kind
        if is_bool:
            setattr(dst, fc.attr, wt == WIRE_BOOL_TRUE)
        elif kind in (
            "uint32",
            "uint64",
            "sint32",
            "sint64",
            "fixed32",
            "sfixed32",
            "fixed64",
            "sfixed64",
            "float32",
            "float64",
            "string",
            "str_as_bytes",
            "bytes",
            "bytes_as_str",
        ):
            val, pos = _read_scalar_payload(data, pos, n, kind)
            setattr(dst, fc.attr, val)
        elif kind == "submsg":
            assert fc.sub_codec is not None and fc.sub_type is not None
            sub_mv, pos = read_len_slice(data, pos, 0, n)
            cur_sub = getattr(dst, fc.attr, None)
            if cur_sub is None:
                cur_sub = fc.sub_type()
                setattr(dst, fc.attr, cur_sub)
            _decode_struct_into(sub_mv, fc.sub_codec, cur_sub, depth + 1, already_seen)
        elif kind == "array_scalar":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: array nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            arr_mv, pos = read_len_slice(data, pos, 2, n)
            elem_wt, count, p, ok = parse_array_header(arr_mv)
            if not ok or elem_wt != fc.elem_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid array header on field {fc.wire_name}")
            cur_list = getattr(dst, fc.attr, None)
            if not isinstance(cur_list, list):
                cur_list = []
                setattr(dst, fc.attr, cur_list)
            elif not already_seen:
                cur_list.clear()
            arr_end = len(arr_mv)
            e_kind = fc.elem_kind
            for _ in range(count):
                item, p = _read_scalar_payload(arr_mv, p, arr_end, e_kind)
                cur_list.append(item)
            if p != arr_end:
                raise OmniBufDecodeError(f"omnibuf: trailing array bytes on field {fc.wire_name}")
        elif kind == "array_submsg":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: array nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            assert fc.sub_codec is not None and fc.sub_type is not None
            arr_mv, pos = read_len_slice(data, pos, 2, n)
            elem_wt, count, p, ok = parse_array_header(arr_mv)
            if not ok or elem_wt != WIRE_SUB_MSG:
                raise OmniBufDecodeError(
                    f"omnibuf: invalid submsg array header on field {fc.wire_name}"
                )
            cur_list = getattr(dst, fc.attr, None)
            if not isinstance(cur_list, list):
                cur_list = []
                setattr(dst, fc.attr, cur_list)
            elif not already_seen:
                cur_list.clear()
            arr_end = len(arr_mv)
            sub_sc = fc.sub_codec
            sub_tp = fc.sub_type
            for _ in range(count):
                elem_mv, p = read_len_slice(arr_mv, p, 0, arr_end)
                elem_obj = sub_tp()
                _decode_struct_into(elem_mv, sub_sc, elem_obj, depth + 2, False)
                cur_list.append(elem_obj)
            if p != arr_end:
                raise OmniBufDecodeError(
                    f"omnibuf: trailing submsg array bytes on field {fc.wire_name}"
                )
        elif kind == "map":
            if depth + 1 > MAX_NESTING_DEPTH:
                raise OmniBufDecodeError(
                    f"omnibuf: map nesting depth {depth + 1} exceeds {MAX_NESTING_DEPTH}"
                )
            map_mv, pos = read_len_slice(data, pos, 3, n)
            key_wt, val_wt, count, p, ok = parse_map_header(map_mv)
            if not ok or key_wt != fc.key_wt or val_wt != fc.val_wt:
                raise OmniBufDecodeError(f"omnibuf: invalid map header on field {fc.wire_name}")
            cur_map = getattr(dst, fc.attr, None)
            if not isinstance(cur_map, dict):
                cur_map = {}
                setattr(dst, fc.attr, cur_map)
            elif not already_seen:
                cur_map.clear()
            map_end = len(map_mv)
            k_kind = fc.key_kind
            v_kind = fc.val_kind
            dec_map_sc = fc.sub_codec
            dec_map_tp = fc.sub_type
            for _ in range(count):
                k_val, p = _read_scalar_payload(map_mv, p, map_end, k_kind)
                if v_kind == "submsg":
                    assert dec_map_sc is not None and dec_map_tp is not None
                    v_mv, p = read_len_slice(map_mv, p, 0, map_end)
                    v_obj = dec_map_tp()
                    _decode_struct_into(v_mv, dec_map_sc, v_obj, depth + 2, False)
                    cur_map[k_val] = v_obj
                else:
                    v_val, p = _read_scalar_payload(map_mv, p, map_end, v_kind)
                    cur_map[k_val] = v_val
            if p != map_end:
                raise OmniBufDecodeError(f"omnibuf: trailing map bytes on field {fc.wire_name}")

    if not merge:
        for fc in sc.fields:
            if (seen_mask & (1 << fc.index)) == 0:
                setattr(dst, fc.attr, fc.make_default())


def marshal(
    msg: Any,
    *,
    deterministic: bool = False,
    self_describing: bool = False,
) -> bytes:
    """Serializes an @omnibuf_message dataclass instance into OmniBuf wire bytes."""
    sc = _get_struct_codec(type(msg))
    out = bytearray()
    if self_describing:
        out.extend(sc.get_field0_wire())
    _encode_struct_into(out, sc, msg, deterministic)
    return bytes(out)


@overload
def unmarshal[T](packet: Buffer, target: type[T]) -> T: ...


@overload
def unmarshal[T](packet: Buffer, target: T) -> T: ...


def unmarshal(packet: Buffer, target: Any) -> Any:
    """Decodes OmniBuf wire bytes into an @omnibuf_message class or existing instance."""
    if isinstance(target, type):
        sc = _get_struct_codec(target)
        inst = target()
    else:
        sc = _get_struct_codec(type(target))
        inst = target
    _decode_struct_into(memoryview(packet), sc, inst, 0, False)
    return inst


def schema_meta_for(target: Any) -> SchemaMeta:
    """Returns a copy of the Field #0 SchemaMeta for an @omnibuf_message class or instance."""
    cls = target if isinstance(target, type) else type(target)
    return _get_struct_codec(cls).get_schema_meta().copy()


# Convenience Encoder helper compatibility
Encoder.marshal_dataclass = staticmethod(marshal)  # type: ignore[attr-defined]

__all__ = [
    "FieldInfo",
    "Fixed32",
    "Fixed64",
    "Float32",
    "Float64",
    "Sfixed32",
    "Sfixed64",
    "Sint32",
    "Sint64",
    "Uint32",
    "Uint64",
    "WireName",
    "marshal",
    "omnibuf_field",
    "omnibuf_message",
    "schema_meta_for",
    "unmarshal",
]
