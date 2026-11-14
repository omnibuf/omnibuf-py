"""Idiomatic @omnibuf_message dataclass codec (Tier 3: Annotated Structs)."""

from __future__ import annotations

import dataclasses
import sys
import types
import typing
from collections.abc import Callable
from dataclasses import MISSING, Field, dataclass
from typing import Annotated, Any, Literal, Union, dataclass_transform, overload

from ._omnibuf_ext import CompiledCodec
from .encoder import Encoder
from .field0 import SchemaMeta, encode_field0_schema_meta
from .wire import (
    MAX_FIELD_NUMBER,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
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
    OmniBufEncodeError,
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
_RUST_CODEC_CACHE: dict[type[Any], CompiledCodec[Any]] = {}
_BUILDING_CODECS: dict[type[Any], _StructCodec] = {}
_PENDING_FINALIZE: list[_StructCodec] = []


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
    kind: str
    wire_type: int
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


class _StructCodec:
    __slots__ = (
        "cls",
        "type_name",
        "fields",
        "_schema_meta",
        "_field0_wire",
        "rust_codec",
    )

    def __init__(self, cls: type[Any], type_name: str, *, fast_alloc: bool) -> None:
        self.cls = cls
        self.type_name = type_name
        self.fields: list[_FieldCodec] = []
        self._schema_meta: SchemaMeta | None = None
        self._field0_wire: bytes | None = None
        self.rust_codec: CompiledCodec[Any] = CompiledCodec(
            cls,
            type_name,
            fast_alloc=fast_alloc,
        )

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

    def finalize_rust_codec(self) -> None:
        specs: list[dict[str, Any]] = []
        for fc in self.fields:
            spec: dict[str, Any] = {
                "number": fc.field_num,
                "attr": fc.attr,
                "wire_name": fc.wire_name,
                "kind": fc.kind,
                "wire_type": fc.wire_type,
                "skip_if_none": fc.optional,
                "omitempty": fc.omitempty,
            }
            if fc.kind == "submsg":
                assert fc.sub_codec is not None
                spec["sub_codec"] = fc.sub_codec.rust_codec
            elif fc.kind == "array_scalar":
                spec["elem_kind"] = fc.elem_kind
                spec["elem_wt"] = fc.elem_wt
            elif fc.kind == "array_submsg":
                assert fc.sub_codec is not None
                spec["sub_codec"] = fc.sub_codec.rust_codec
            elif fc.kind == "map":
                spec["key_kind"] = fc.key_kind
                spec["key_wt"] = fc.key_wt
                spec["val_kind"] = fc.val_kind
                spec["val_wt"] = fc.val_wt
                if fc.val_kind == "submsg":
                    assert fc.sub_codec is not None
                    spec["sub_codec"] = fc.sub_codec.rust_codec

            if fc.optional:
                spec["default_mode"] = "const"
                spec["default_val"] = None
            elif fc.default_factory is not None:
                if fc.default_factory is list:
                    spec["default_mode"] = "list"
                elif fc.default_factory is dict:
                    spec["default_mode"] = "dict"
                else:
                    spec["default_mode"] = "factory"
                    spec["default_val"] = fc.default_factory
            elif fc.kind == "submsg":
                assert fc.sub_codec is not None
                spec["default_mode"] = "submsg"
                spec["sub_codec"] = fc.sub_codec.rust_codec
            elif fc.kind in ("array_scalar", "array_submsg"):
                spec["default_mode"] = "list"
            elif fc.kind == "map":
                spec["default_mode"] = "dict"
            else:
                spec["default_mode"] = "const"
                spec["default_val"] = fc.default_val

            specs.append(spec)

        self.rust_codec.set_fields(specs, self.get_field0_wire())


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

    dc_fields = dataclasses.fields(cls)
    all_annotated = all(isinstance(f.metadata.get(_META_KEY), FieldInfo) for f in dc_fields)
    slots_val = getattr(cls, "__slots__", ())
    has_dict_slot = "__dict__" in (slots_val if isinstance(slots_val, tuple) else (slots_val,))
    req_fast = (
        "__slots__" in cls.__dict__
        and not has_dict_slot
        and not hasattr(cls, "__post_init__")
        and cls.__bases__ == (object,)
        and all_annotated
    )

    type_name = getattr(cls, "__omnibuf_type_name__", cls.__name__)
    is_root = not _BUILDING_CODECS
    sc = _StructCodec(cls, str(type_name), fast_alloc=req_fast)
    _BUILDING_CODECS[cls] = sc
    try:
        hints = _resolve_type_hints(cls)
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
                if isinstance(elem_base, type) and dataclasses.is_dataclass(elem_base):
                    sub_sc = _get_struct_codec(elem_base)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="array_submsg",
                        wire_type=WIRE_ARRAY,
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
                if isinstance(v_base, type) and dataclasses.is_dataclass(v_base):
                    sub_sc = _get_struct_codec(v_base)
                    fc = _FieldCodec(
                        index=len(compiled),
                        attr=dc_f.name,
                        field_num=fnum,
                        wire_name=wire_name,
                        kind="map",
                        wire_type=WIRE_MAP,
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
                fc = _FieldCodec(
                    index=len(compiled),
                    attr=dc_f.name,
                    field_num=fnum,
                    wire_name=wire_name,
                    kind="submsg",
                    wire_type=WIRE_SUB_MSG,
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
                        optional=is_opt,
                        omitempty=info.omitempty,
                        default_val=default_scalar,
                        default_factory=def_fac,
                    )
            compiled.append(fc)

        compiled.sort(key=lambda item: item.field_num)
        for idx, fc in enumerate(compiled):
            fc.index = idx
        sc.fields = compiled
        _PENDING_FINALIZE.append(sc)

        if is_root:
            pending = list(_PENDING_FINALIZE)
            _PENDING_FINALIZE.clear()
            for p_sc in pending:
                p_sc.finalize_rust_codec()
                _CODEC_CACHE[p_sc.cls] = p_sc
                _RUST_CODEC_CACHE[p_sc.cls] = p_sc.rust_codec
    except Exception:
        if is_root:
            _PENDING_FINALIZE.clear()
        raise
    finally:
        _BUILDING_CODECS.pop(cls, None)
    return sc


def marshal(
    msg: Any,
    *,
    deterministic: bool = False,
    self_describing: bool = False,
) -> bytes:
    """Serializes an @omnibuf_message dataclass instance into OmniBuf wire bytes."""
    rc = _RUST_CODEC_CACHE.get(type(msg))
    if rc is None:
        rc = _get_struct_codec(type(msg)).rust_codec
    return rc.marshal(msg, deterministic=deterministic, self_describing=self_describing)


@overload
def unmarshal[T](packet: Buffer, target: type[T]) -> T: ...


@overload
def unmarshal[T](packet: Buffer, target: T) -> T: ...


def unmarshal(packet: Buffer, target: Any) -> Any:
    """Decodes OmniBuf wire bytes into an @omnibuf_message class or existing instance."""
    if isinstance(target, type):
        rc = _RUST_CODEC_CACHE.get(target)
        if rc is None:
            rc = _get_struct_codec(target).rust_codec
        return rc.unmarshal(packet)
    rc = _RUST_CODEC_CACHE.get(type(target))
    if rc is None:
        rc = _get_struct_codec(type(target)).rust_codec
    return rc.unmarshal(packet, target)


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
