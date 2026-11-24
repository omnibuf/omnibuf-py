"""Idiomatic @omnibuf_message dataclass codec (Tier 3: Annotated Structs)."""

from __future__ import annotations

import ast
import dataclasses
import enum
import sys
import threading
import types
import typing
from collections.abc import Callable
from dataclasses import MISSING, Field, dataclass
from typing import Annotated, Any, Literal, TypeAlias, TypeVar, Union, dataclass_transform, overload

from ._omnibuf_ext import (
    CompiledCodec,
    marshal_dataclass_py,
    register_dataclass_codec_py,
    set_dataclass_resolver_py,
    unmarshal_dataclass_py,
)
from .encoder import Encoder
from .field0 import SchemaMeta, encode_field0_schema_meta
from .wire import (
    MAX_FIELD_NUMBER,
    MAX_NESTING_DEPTH,
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
    OmniBufEncodeError,
)

WireName: TypeAlias = Literal[
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

_T = TypeVar("_T")


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
_INT_ALIAS_NAMES = frozenset(
    {
        "int",
        "Uint32",
        "Uint64",
        "Sint32",
        "Sint64",
        "Fixed32",
        "Sfixed32",
        "Fixed64",
        "Sfixed64",
    }
)
_FLOAT_ALIAS_NAMES = frozenset({"float", "Float32", "Float64"})


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
def omnibuf_field(
    field_num: int,
    *,
    default: _T,
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> _T: ...


@overload
def omnibuf_field(
    field_num: int,
    *,
    default_factory: Callable[[], _T],
    name: str | None = None,
    wire: WireName | None = None,
    elem_wire: WireName | None = None,
    key_wire: WireName | None = None,
    val_wire: WireName | None = None,
    omitempty: bool = False,
) -> _T: ...


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
    if isinstance(field_num, bool) or field_num <= 0 or field_num > MAX_FIELD_NUMBER:
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


_CODEC_LOCK = threading.RLock()
_REGISTERED_TYPES: dict[str, type[Any]] = {}
_CODEC_CACHE: dict[type[Any], _StructCodec] = {}
_RUST_CODEC_CACHE: dict[type[Any], CompiledCodec[Any]] = {}
_BUILDING_CODECS: dict[type[Any], _StructCodec] = {}
_PENDING_FINALIZE: list[_StructCodec] = []


def _is_int_enum_type(tp: Any) -> typing.TypeGuard[type[enum.Enum]]:
    if not (isinstance(tp, type) and issubclass(tp, enum.Enum)):
        return False
    if issubclass(tp, int) and not issubclass(tp, bool):
        return True
    members = list(tp)
    if not members:
        return False
    return all(isinstance(m.value, int) and not isinstance(m.value, bool) for m in members)


def _default_for_enum(enum_cls: type[enum.Enum]) -> Any:
    vmap = getattr(enum_cls, "_value2member_map_", {})
    if 0 in vmap:
        return vmap[0]
    members = list(enum_cls)
    return members[0] if members else 0


def _ast_terminal_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _ast_is_none(node: ast.expr) -> bool:
    return (isinstance(node, ast.Constant) and node.value is None) or (
        isinstance(node, ast.Name) and node.id == "None"
    )


def _ast_flatten_bitor(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _ast_flatten_bitor(node.left) + _ast_flatten_bitor(node.right)
    return [node]


def _infer_ast_default(
    node: ast.expr,
    mod_ns: dict[str, Any],
) -> tuple[bool, Any, Callable[[], Any] | None]:
    if _ast_is_none(node):
        return True, None, None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        parts = _ast_flatten_bitor(node)
        if any(_ast_is_none(p) for p in parts):
            return True, None, None
        return False, MISSING, None
    if isinstance(node, ast.Subscript):
        head = _ast_terminal_name(node.value)
        if head == "Optional":
            return True, None, None
        if head == "Union":
            elts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            if any(_ast_is_none(e) for e in elts):
                return True, None, None
            return False, MISSING, None
        if head in ("list", "List"):
            return True, MISSING, list
        if head in ("dict", "Dict"):
            return True, MISSING, dict
        if head == "Annotated":
            first = node.slice.elts[0] if isinstance(node.slice, ast.Tuple) else node.slice
            return _infer_ast_default(first, mod_ns)
        return False, MISSING, None

    ident = _ast_terminal_name(node)
    if ident is None:
        return False, MISSING, None
    if ident == "bool":
        return True, False, None
    if ident == "str":
        return True, "", None
    if ident in ("bytes", "bytearray"):
        return True, b"", None
    if ident in _FLOAT_ALIAS_NAMES:
        return True, 0.0, None
    if ident in _INT_ALIAS_NAMES:
        return True, 0, None
    resolved = mod_ns.get(ident)
    if _is_int_enum_type(resolved):
        return True, _default_for_enum(resolved), None
    return False, MISSING, None


def _infer_runtime_default(raw_ann: Any) -> tuple[bool, Any, Callable[[], Any] | None]:
    unwrapped, is_opt = _unwrap_optional(raw_ann)
    if is_opt or unwrapped is type(None):
        return True, None, None
    base, _ = _unwrap_annotated(unwrapped)
    origin = typing.get_origin(base)
    if origin is list or base is list:
        return True, MISSING, list
    if origin is dict or base is dict:
        return True, MISSING, dict
    if base is bool:
        return True, False, None
    if base is str:
        return True, "", None
    if base in (bytes, bytearray):
        return True, b"", None
    if base is float:
        return True, 0.0, None
    if base is int and not isinstance(base, bool):
        return True, 0, None
    if _is_int_enum_type(base):
        return True, _default_for_enum(base), None
    return False, MISSING, None


def _apply_default_if_missing(
    cls: type[Any],
    extra_ns: dict[str, Any] | None = None,
) -> None:
    """Allows @omnibuf_message classes to omit boilerplate default=0 / default_factory=list."""
    annotations = getattr(cls, "__annotations__", None)
    if not annotations:
        return
    mod = sys.modules.get(cls.__module__)
    mod_ns: dict[str, Any] = dict(vars(mod)) if mod is not None else {}
    if extra_ns:
        mod_ns.update(extra_ns)

    for attr_name, raw_ann in annotations.items():
        if attr_name not in cls.__dict__:
            continue
        val = cls.__dict__[attr_name]
        if not (
            isinstance(val, Field) and val.default is MISSING and val.default_factory is MISSING
        ):
            continue

        matched = False
        def_val: Any = MISSING
        def_fac: Callable[[], Any] | None = None
        if isinstance(raw_ann, str):
            try:
                parsed = ast.parse(raw_ann, mode="eval").body
            except SyntaxError:
                parsed = None
            if parsed is not None:
                matched, def_val, def_fac = _infer_ast_default(parsed, mod_ns)
        else:
            matched, def_val, def_fac = _infer_runtime_default(raw_ann)

        if matched:
            meta = dict(val.metadata)
            if def_fac is not None:
                setattr(cls, attr_name, dataclasses.field(default_factory=def_fac, metadata=meta))
            else:
                setattr(cls, attr_name, dataclasses.field(default=def_val, metadata=meta))


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message(cls: type[_T], /) -> type[_T]: ...


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message(
    type_name: str,
    /,
    *,
    slots: bool = True,
) -> Callable[[type[_T]], type[_T]]: ...


@overload
@dataclass_transform(field_specifiers=(omnibuf_field, dataclasses.field))
def omnibuf_message(
    *,
    type_name: str | None = None,
    slots: bool = True,
) -> Callable[[type[_T]], type[_T]]: ...


def omnibuf_message(
    cls_or_name: type[Any] | str | None = None,
    /,
    *,
    type_name: str | None = None,
    slots: bool = True,
) -> Any:
    """Marks a dataclass as an OmniBuf message (automatically applying @dataclass if needed)."""
    resolved_name = cls_or_name if isinstance(cls_or_name, str) else type_name
    caller_locals: dict[str, Any] | None = None
    try:
        frame = sys._getframe(1)
        if frame.f_locals is not frame.f_globals:
            caller_locals = dict(frame.f_locals)
    except ValueError:
        caller_locals = None

    def wrap(target: type[Any]) -> type[Any]:
        local_snap = caller_locals
        if local_snap is None:
            try:
                w_frame = sys._getframe(1)
                if w_frame.f_locals is not w_frame.f_globals:
                    local_snap = dict(w_frame.f_locals)
            except ValueError:
                local_snap = None
        if not dataclasses.is_dataclass(target):
            _apply_default_if_missing(target, local_snap)
            target = dataclass(slots=slots)(target)
        for dc_f in dataclasses.fields(target):
            if not isinstance(dc_f.metadata.get(_META_KEY), FieldInfo):
                raise OmniBufEncodeError(
                    f"omnibuf: field {target.__name__}.{dc_f.name} is missing omnibuf_field(...)"
                )
        if local_snap is not None:
            setattr(target, "__omnibuf_localns__", local_snap)  # noqa: B010
        setattr(target, "__omnibuf_type_name__", resolved_name or target.__name__)  # noqa: B010
        with _CODEC_LOCK:
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


def _scalar_spec_ext(
    py_type: Any,
    wire_opt: WireName | None,
) -> tuple[str, int, type[Any] | None]:
    """Maps (Python scalar/enum type, optional wire override) to (scalar_kind, wire_type, enum_cls)."""
    base, ann_wire = _unwrap_annotated(py_type)
    eff = wire_opt or ann_wire

    if base is bool:
        if eff not in (None, "bool"):
            raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for bool")
        return "bool", WIRE_BOOL_FALSE, None

    if base is str:
        if eff in (None, "string"):
            return "string", WIRE_STRING, None
        if eff == "bytes":
            return "str_as_bytes", WIRE_BYTES, None
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for str")

    if base in (bytes, bytearray):
        if eff in (None, "bytes"):
            return "bytes", WIRE_BYTES, None
        if eff == "string":
            return "bytes_as_str", WIRE_STRING, None
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for bytes")

    if base is float:
        if eff == "float32":
            return "float32", WIRE_FLOAT32, None
        if eff in (None, "float64"):
            return "float64", WIRE_FLOAT64, None
        raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for float")

    if isinstance(base, type) and issubclass(base, enum.Enum):
        if not _is_int_enum_type(base):
            raise OmniBufEncodeError(f"omnibuf: enum {base!r} must have integer member values")
        if eff not in (None, "sint", "sint32"):
            raise OmniBufEncodeError(f"omnibuf: invalid wire override {eff!r} for enum {base!r}")
        return "enum", WIRE_SINT, base

    if base is int:
        if eff == "uint32":
            return "uint32", WIRE_UINT, None
        if eff in ("uint", "uint64"):
            return "uint64", WIRE_UINT, None
        if eff == "sint32":
            return "sint32", WIRE_SINT, None
        if eff in (None, "sint", "sint64"):
            return "sint64", WIRE_SINT, None
        if eff == "fixed32":
            return "fixed32", WIRE_FIXED32, None
        if eff == "sfixed32":
            return "sfixed32", WIRE_SFIXED32, None
        if eff == "fixed64":
            return "fixed64", WIRE_FIXED64, None
        if eff == "sfixed64":
            return "sfixed64", WIRE_SFIXED64, None
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
    enum_cls: type[Any] | None = None
    elem_kind: str = ""
    elem_wt: int = 0
    key_kind: str = ""
    key_wt: int = 0
    val_kind: str = ""
    val_wt: int = 0
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

    def get_schema_meta(
        self,
        visiting: frozenset[type[Any]] = frozenset(),
        schema_depth: int = 1,
    ) -> SchemaMeta:
        if self._schema_meta is not None and not visiting and schema_depth == 1:
            return self._schema_meta
        meta = SchemaMeta(type_name=self.type_name)
        if schema_depth + 1 > MAX_NESTING_DEPTH:
            return meta
        next_visiting = visiting | {self.cls}
        for fc in self.fields:
            meta.fields[fc.field_num] = fc.wire_name
            if (
                schema_depth + 3 <= MAX_NESTING_DEPTH
                and fc.sub_codec is not None
                and fc.sub_codec.cls not in next_visiting
            ):
                meta.children[fc.field_num] = fc.sub_codec.get_schema_meta(
                    next_visiting, schema_depth + 2
                )
        if not visiting and schema_depth == 1:
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
            if fc.enum_cls is not None:
                spec["enum_cls"] = fc.enum_cls
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
    globalns: dict[str, Any] = dict(_REGISTERED_TYPES)
    if mod is not None:
        globalns.update(vars(mod))
    localns: dict[str, Any] = {}
    saved_locals = getattr(cls, "__omnibuf_localns__", None)
    if isinstance(saved_locals, dict):
        localns.update(saved_locals)
    localns[cls.__name__] = cls
    return typing.get_type_hints(cls, globalns=globalns, localns=localns, include_extras=True)


def _get_struct_codec(cls: type[Any]) -> _StructCodec:
    cached = _CODEC_CACHE.get(cls)
    if cached is not None:
        return cached
    with _CODEC_LOCK:
        cached = _CODEC_CACHE.get(cls)
        if cached is not None:
            return cached
        in_progress = _BUILDING_CODECS.get(cls)
        if in_progress is not None:
            return in_progress
        if not dataclasses.is_dataclass(cls):
            raise OmniBufEncodeError(f"omnibuf: {cls!r} is not an @omnibuf_message / @dataclass")

        dc_fields = dataclasses.fields(cls)
        for dc_f in dc_fields:
            if not isinstance(dc_f.metadata.get(_META_KEY), FieldInfo):
                raise OmniBufEncodeError(
                    f"omnibuf: field {cls.__name__}.{dc_f.name} is missing omnibuf_field(...)"
                )
        req_fast = not hasattr(cls, "__post_init__") and cls.__bases__ == (object,)

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
                    if elem_is_opt or elem_no_opt is type(None):
                        raise OmniBufEncodeError(
                            f"omnibuf: Optional list elements are not supported on {cls.__name__}.{dc_f.name}"
                        )
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
                        e_kind, e_wt, e_enum = _scalar_spec_ext(elem_base, eff_elem_wire)
                        fc = _FieldCodec(
                            index=len(compiled),
                            attr=dc_f.name,
                            field_num=fnum,
                            wire_name=wire_name,
                            kind="array_scalar",
                            wire_type=WIRE_ARRAY,
                            optional=is_opt,
                            omitempty=info.omitempty,
                            enum_cls=e_enum,
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
                    k_no_opt, k_is_opt = _unwrap_optional(k_raw)
                    if k_is_opt or k_no_opt is type(None):
                        raise OmniBufEncodeError(
                            f"omnibuf: Optional map keys are not supported on {cls.__name__}.{dc_f.name}"
                        )
                    k_base, k_ann = _unwrap_annotated(k_no_opt)
                    if isinstance(k_base, type) and issubclass(k_base, enum.Enum):
                        raise OmniBufEncodeError(
                            f"omnibuf: enum map keys are not supported on {cls.__name__}.{dc_f.name}"
                        )
                    k_kind, k_wt, _ = _scalar_spec_ext(k_base, info.key_wire or k_ann)
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
                    if v_is_opt or v_no_opt is type(None):
                        raise OmniBufEncodeError(
                            f"omnibuf: Optional map values are not supported on {cls.__name__}.{dc_f.name}"
                        )
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
                        v_kind, v_wt, v_enum = _scalar_spec_ext(v_base, eff_val_wire)
                        fc = _FieldCodec(
                            index=len(compiled),
                            attr=dc_f.name,
                            field_num=fnum,
                            wire_name=wire_name,
                            kind="map",
                            wire_type=WIRE_MAP,
                            optional=is_opt,
                            omitempty=info.omitempty,
                            enum_cls=v_enum,
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
                    s_kind, s_wt, s_enum = _scalar_spec_ext(base_tp, info.wire or ann_wire)
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
                            elif s_kind == "enum" and s_enum is not None:
                                default_scalar = _default_for_enum(s_enum)
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
                            enum_cls=s_enum,
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
                for p_sc in pending:
                    _CODEC_CACHE[p_sc.cls] = p_sc
                    _RUST_CODEC_CACHE[p_sc.cls] = p_sc.rust_codec
                    register_dataclass_codec_py(p_sc.cls, p_sc.rust_codec)
        except Exception:
            if is_root:
                _PENDING_FINALIZE.clear()
            raise
        finally:
            _BUILDING_CODECS.pop(cls, None)
        return sc


def _resolve_rust_codec_for_type(cls: type[Any]) -> CompiledCodec[Any]:
    rc = _RUST_CODEC_CACHE.get(cls)
    if rc is not None:
        return rc
    return _get_struct_codec(cls).rust_codec


set_dataclass_resolver_py(_resolve_rust_codec_for_type)

marshal = marshal_dataclass_py
unmarshal = unmarshal_dataclass_py


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
