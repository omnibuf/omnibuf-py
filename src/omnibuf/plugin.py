"""protoc-gen-omnibuf-py code generator plugin (Tier 1: Rust-Backed Codec + Opaque Views)."""

from __future__ import annotations

import keyword
import re
import sys
from dataclasses import dataclass, field
from typing import Any

try:
    from google.protobuf.compiler import plugin_pb2
    from google.protobuf.descriptor_pb2 import (
        DescriptorProto,
        EnumDescriptorProto,
        FieldDescriptorProto,
        FileDescriptorProto,
    )
except ImportError as exc:
    raise ImportError("protoc-gen-omnibuf-py requires protobuf; install omnibuf[protobuf]") from exc

from .field0 import SchemaMeta, encode_field0_schema_meta
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
)


def _to_snake_case(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


_RESERVED_MSG_ATTRS: frozenset[str] = frozenset(
    {
        "None",
        "True",
        "False",
        "self",
        "cls",
        "marshal_omnibuf",
        "unmarshal_omnibuf",
        "__omnibuf_codec__",
    }
)


def _safe_ident(name: str) -> str:
    if keyword.iskeyword(name) or name in {"None", "True", "False", "self", "cls"}:
        return f"{name}_"
    return name


def _sanitize_module_ident(part: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", part)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    if keyword.iskeyword(cleaned):
        cleaned = f"{cleaned}_"
    return cleaned


def _unique_field_attr(raw_name: str, used: set[str], field_num: int) -> str:
    cand = _safe_ident(raw_name)
    if cand in _RESERVED_MSG_ATTRS:
        cand = f"{cand}_"
    if cand in used:
        base = cand
        cand = f"{base}_{field_num}"
        while cand in used:
            cand = f"{cand}_"
    used.add(cand)
    return cand


_PROTO_SCALAR_INFO: dict[int, tuple[str, int, str, str]] = {
    # proto_type: (scalar_kind, wire_type, py_type, default_expr)
    FieldDescriptorProto.TYPE_DOUBLE: ("float64", WIRE_FLOAT64, "float", "0.0"),
    FieldDescriptorProto.TYPE_FLOAT: ("float32", WIRE_FLOAT32, "float", "0.0"),
    FieldDescriptorProto.TYPE_INT64: ("sint64", WIRE_SINT, "int", "0"),
    FieldDescriptorProto.TYPE_UINT64: ("uint64", WIRE_UINT, "int", "0"),
    FieldDescriptorProto.TYPE_INT32: ("sint32", WIRE_SINT, "int", "0"),
    FieldDescriptorProto.TYPE_FIXED64: ("fixed64", WIRE_FIXED64, "int", "0"),
    FieldDescriptorProto.TYPE_FIXED32: ("fixed32", WIRE_FIXED32, "int", "0"),
    FieldDescriptorProto.TYPE_BOOL: ("bool", WIRE_BOOL_FALSE, "bool", "False"),
    FieldDescriptorProto.TYPE_STRING: ("string", WIRE_STRING, "str", '""'),
    FieldDescriptorProto.TYPE_BYTES: ("bytes", WIRE_BYTES, "bytes", 'b""'),
    FieldDescriptorProto.TYPE_UINT32: ("uint32", WIRE_UINT, "int", "0"),
    FieldDescriptorProto.TYPE_ENUM: ("sint32", WIRE_SINT, "int", "0"),
    FieldDescriptorProto.TYPE_SFIXED32: ("sfixed32", WIRE_SFIXED32, "int", "0"),
    FieldDescriptorProto.TYPE_SFIXED64: ("sfixed64", WIRE_SFIXED64, "int", "0"),
    FieldDescriptorProto.TYPE_SINT32: ("sint32", WIRE_SINT, "int", "0"),
    FieldDescriptorProto.TYPE_SINT64: ("sint64", WIRE_SINT, "int", "0"),
}

_SCALAR_KIND_CODE: dict[str, int] = {
    "bool": 0,
    "uint32": 1,
    "uint64": 2,
    "sint32": 3,
    "sint64": 4,
    "enum": 5,
    "fixed32": 6,
    "sfixed32": 7,
    "fixed64": 8,
    "sfixed64": 9,
    "float32": 10,
    "float64": 11,
    "string": 12,
    "str_as_bytes": 13,
    "bytes": 14,
    "bytes_as_str": 15,
}


def _field_wire_mask(rf: _ResolvedField) -> int:
    if rf.is_map:
        return 1 << WIRE_MAP
    if rf.repeated:
        return 1 << WIRE_ARRAY
    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        return 1 << WIRE_SUB_MSG
    if rf.proto_type == FieldDescriptorProto.TYPE_BOOL:
        return (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE)
    _, wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
    return 1 << wt


@dataclass(slots=True)
class _MapEntrySpec:
    full_name: str
    key_type: int
    val_type: int
    val_type_name: str


@dataclass(slots=True)
class _OneofGroup:
    proto_name: str
    safe_name: str
    members: list[_ResolvedField] = field(default_factory=list)


@dataclass(slots=True)
class _MsgSpec:
    full_name: str
    short_name: str
    py_name: str
    file_name: str
    desc: DescriptorProto
    fields: list[_ResolvedField] = field(default_factory=list)
    oneofs: list[_OneofGroup] = field(default_factory=list)


@dataclass(slots=True)
class _EnumSpec:
    full_name: str
    py_name: str
    file_name: str
    desc: EnumDescriptorProto


@dataclass(slots=True)
class _ResolvedField:
    number: int
    proto_name: str
    attr_name: str
    proto_type: int
    repeated: bool
    is_map: bool
    explicit_presence: bool
    real_oneof: str | None = None
    oneof_siblings: list[_ResolvedField] = field(default_factory=list)
    map_key_type: int = 0
    map_val_type: int = 0
    sub_msg_full: str = ""
    sub_msg_py: str = ""


class _Registry:
    def __init__(self, files: list[FileDescriptorProto]) -> None:
        self.messages: dict[str, _MsgSpec] = {}
        self.map_entries: dict[str, _MapEntrySpec] = {}
        self.enums: dict[str, _EnumSpec] = {}
        self.file_messages: dict[str, list[_MsgSpec]] = {}
        self.file_enums: dict[str, list[_EnumSpec]] = {}

        for fdp in files:
            pkg = fdp.package
            prefix = f".{pkg}" if pkg else ""
            f_msgs: list[_MsgSpec] = []
            f_enums: list[_EnumSpec] = []
            for edp in fdp.enum_type:
                e_spec = _EnumSpec(
                    full_name=f"{prefix}.{edp.name}",
                    py_name=edp.name,
                    file_name=fdp.name,
                    desc=edp,
                )
                self.enums[e_spec.full_name] = e_spec
                f_enums.append(e_spec)
            for mdp in fdp.message_type:
                self._collect_msg(fdp.name, prefix, "", mdp, f_msgs, f_enums)
            self.file_messages[fdp.name] = f_msgs
            self.file_enums[fdp.name] = f_enums

    def _collect_msg(
        self,
        file_name: str,
        proto_prefix: str,
        py_prefix: str,
        mdp: DescriptorProto,
        out_msgs: list[_MsgSpec],
        out_enums: list[_EnumSpec],
    ) -> None:
        full_name = f"{proto_prefix}.{mdp.name}"
        if mdp.options.map_entry:
            k_fd = next(f for f in mdp.field if f.number == 1)
            v_fd = next(f for f in mdp.field if f.number == 2)
            self.map_entries[full_name] = _MapEntrySpec(
                full_name=full_name,
                key_type=k_fd.type,
                val_type=v_fd.type,
                val_type_name=v_fd.type_name,
            )
            return

        py_name = f"{py_prefix}{mdp.name}"
        spec = _MsgSpec(
            full_name=full_name,
            short_name=mdp.name,
            py_name=py_name,
            file_name=file_name,
            desc=mdp,
        )
        self.messages[full_name] = spec
        out_msgs.append(spec)

        for edp in mdp.nested_type:
            self._collect_msg(file_name, full_name, f"{py_name}_", edp, out_msgs, out_enums)
        for enum_dp in mdp.enum_type:
            e_spec = _EnumSpec(
                full_name=f"{full_name}.{enum_dp.name}",
                py_name=f"{py_name}_{enum_dp.name}",
                file_name=file_name,
                desc=enum_dp,
            )
            self.enums[e_spec.full_name] = e_spec
            out_enums.append(e_spec)


def _module_import_for_proto(
    current_proto: str,
    target_proto: str,
    suffix: str,
) -> tuple[str, str]:
    cur_parts = [
        _sanitize_module_ident(p) for p in re.sub(r"\.proto$", "", current_proto).split("/")[:-1]
    ]
    tgt_clean = re.sub(r"\.proto$", "", target_proto).split("/")
    stem = _sanitize_module_ident(f"{tgt_clean[-1]}{suffix}")
    tgt_parts = [_sanitize_module_ident(p) for p in tgt_clean[:-1]]
    if not cur_parts:
        return (f".{'.'.join(tgt_parts)}" if tgt_parts else "."), stem
    common = 0
    while (
        common < len(cur_parts)
        and common < len(tgt_parts)
        and cur_parts[common] == tgt_parts[common]
    ):
        common += 1
    up = len(cur_parts) - common
    dots = "." * (up + 1)
    down = ".".join(tgt_parts[common:])
    return f"{dots}{down}", stem


def _build_schema_meta(
    msg_spec: _MsgSpec,
    reg: _Registry,
    visiting: frozenset[str] = frozenset(),
    schema_depth: int = 1,
) -> SchemaMeta:
    meta = SchemaMeta(type_name=msg_spec.short_name)
    if schema_depth + 1 > MAX_NESTING_DEPTH:
        return meta
    next_visiting = visiting | {msg_spec.full_name}
    for rf in msg_spec.fields:
        meta.fields[rf.number] = rf.proto_name
        if (
            schema_depth + 3 <= MAX_NESTING_DEPTH
            and rf.sub_msg_full
            and rf.sub_msg_full not in next_visiting
        ):
            child_spec = reg.messages.get(rf.sub_msg_full)
            if child_spec is not None:
                meta.children[rf.number] = _build_schema_meta(
                    child_spec, reg, next_visiting, schema_depth + 2
                )
    return meta


def _emit_field_spec_expr(rf: _ResolvedField, ref_codec_fn: Any) -> str:
    sib_nums = [s.number for s in rf.oneof_siblings]
    sib_suffix = f', "oneof_siblings": {sib_nums!r}' if sib_nums else ""

    if rf.is_map:
        k_kind, k_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
        if rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE:
            sub_c = ref_codec_fn(rf.sub_msg_full)
            return (
                f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
                f'"wire_name": {rf.proto_name!r}, "kind": "map", "wire_type": {WIRE_MAP}, '
                f'"key_kind": {k_kind!r}, "key_wt": {k_wt}, '
                f'"val_kind": "submsg", "val_wt": {WIRE_SUB_MSG}, '
                f'"sub_codec": {sub_c}, "default_mode": "dict"}}'
            )
        v_kind, v_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
        return (
            f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
            f'"wire_name": {rf.proto_name!r}, "kind": "map", "wire_type": {WIRE_MAP}, '
            f'"key_kind": {k_kind!r}, "key_wt": {k_wt}, '
            f'"val_kind": {v_kind!r}, "val_wt": {v_wt}, "default_mode": "dict"}}'
        )

    if rf.repeated:
        if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
            sub_c = ref_codec_fn(rf.sub_msg_full)
            return (
                f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
                f'"wire_name": {rf.proto_name!r}, "kind": "array_submsg", '
                f'"wire_type": {WIRE_ARRAY}, "sub_codec": {sub_c}, "default_mode": "list"}}'
            )
        e_kind, e_wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
        return (
            f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
            f'"wire_name": {rf.proto_name!r}, "kind": "array_scalar", '
            f'"wire_type": {WIRE_ARRAY}, "elem_kind": {e_kind!r}, "elem_wt": {e_wt}, '
            f'"default_mode": "list"}}'
        )

    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        sub_c = ref_codec_fn(rf.sub_msg_full)
        return (
            f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
            f'"wire_name": {rf.proto_name!r}, "kind": "submsg", '
            f'"wire_type": {WIRE_SUB_MSG}, "skip_if_none": True, "sub_codec": {sub_c}, '
            f'"default_mode": "const", "default_val": None{sib_suffix}}}'
        )

    s_kind, s_wt, _, s_def = _PROTO_SCALAR_INFO[rf.proto_type]
    def_expr = "None" if rf.explicit_presence else s_def
    return (
        f'{{"number": {rf.number}, "attr": {rf.attr_name!r}, '
        f'"wire_name": {rf.proto_name!r}, "kind": {s_kind!r}, "wire_type": {s_wt}, '
        f'"skip_if_none": {rf.explicit_presence!r}, '
        f'"default_mode": "const", "default_val": {def_expr}{sib_suffix}}}'
    )


def _sibling_specs_expr(rf: _ResolvedField) -> str:
    if not rf.oneof_siblings:
        return ""
    pairs = ", ".join(f"({s.number}, {_field_wire_mask(s)})" for s in rf.oneof_siblings)
    return f"({pairs},)"


def _sibling_nums_expr(rf: _ResolvedField) -> str:
    nums = ", ".join(str(s.number) for s in rf.oneof_siblings)
    return f"({nums},)"


def _emit_opaque_methods(
    rf: _ResolvedField,
    ref_codec_fn: Any,
    ref_opaque_cls: Any,
) -> list[str]:
    lines: list[str] = []
    attr = rf.attr_name
    num = rf.number
    sib_specs = _sibling_specs_expr(rf)

    if rf.is_map:
        k_kind, k_wt, k_py, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
        k_code = _SCALAR_KIND_CODE[k_kind]
        if rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE:
            v_py = rf.sub_msg_py
            sub_c = ref_codec_fn(rf.sub_msg_full)
            ret_tp = f"dict[{k_py}, {v_py}]"
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        return self._get_map({num}, {k_wt}, {k_code}, {WIRE_SUB_MSG}, 0, {sub_c})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._set_dirty({num}, val)",
                    "",
                ]
            )
        else:
            v_kind, v_wt, v_py, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
            v_code = _SCALAR_KIND_CODE[v_kind]
            ret_tp = f"dict[{k_py}, {v_py}]"
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        return self._get_map({num}, {k_wt}, {k_code}, {v_wt}, {v_code})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._set_dirty({num}, val)",
                    "",
                ]
            )
        return lines

    if rf.repeated:
        if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
            ret_tp = f"list[{rf.sub_msg_py}]"
            sub_c = ref_codec_fn(rf.sub_msg_full)
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        return self._get_submsg_array({num}, {sub_c})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._set_dirty({num}, val)",
                    "",
                ]
            )
        else:
            e_kind, e_wt, e_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
            e_code = _SCALAR_KIND_CODE[e_kind]
            ret_tp = f"list[{e_py}]"
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        return self._get_scalar_array({num}, {e_wt}, {e_code})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._set_dirty({num}, val)",
                    "",
                ]
            )
        return lines

    mask = _field_wire_mask(rf)
    has_arg = f"{num}, {mask}, {sib_specs}" if sib_specs else f"{num}, {mask}"

    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        ret_tp = f"{rf.sub_msg_py} | None"
        sub_c = ref_codec_fn(rf.sub_msg_full)
        op_cls = ref_opaque_cls(rf.sub_msg_full)
        sub_args = f"{num}, {sub_c}, {sib_specs}" if sib_specs else f"{num}, {sub_c}"
        op_args = (
            f"{num}, {op_cls}, {sub_c}, {sib_specs}" if sib_specs else f"{num}, {op_cls}, {sub_c}"
        )
        set_call = (
            f"self._set_oneof_dirty({num}, val, {_sibling_nums_expr(rf)})"
            if rf.oneof_siblings
            else f"self._set_dirty({num}, val)"
        )
        lines.extend(
            [
                f"    def has_{attr}(self) -> bool:",
                f"        return self._has_field({has_arg})",
                "",
                f"    def get_{attr}(self) -> {ret_tp}:",
                f"        return self._get_submsg({sub_args})",
                "",
                f"    def opaque_{attr}(self) -> {op_cls} | None:",
                f"        return self._opaque_sub({op_args})",
                "",
                f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                f"        {set_call}",
                "",
            ]
        )
        return lines

    s_kind, _, s_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
    if rf.explicit_presence:
        opt_tp = f"{s_py} | None"
        opt_args = f"{num}, {sib_specs}" if sib_specs else f"{num}"
        set_call = (
            f"self._set_oneof_dirty({num}, val, {_sibling_nums_expr(rf)})"
            if rf.oneof_siblings
            else f"self._set_{s_kind}({num}, val, True)"
        )
        lines.extend(
            [
                f"    def has_{attr}(self) -> bool:",
                f"        return self._has_field({has_arg})",
                "",
                f"    def get_{attr}(self) -> {opt_tp}:",
                f"        return self._get_opt_{s_kind}({opt_args})",
                "",
            ]
        )
        if s_kind == "bytes":
            lines.extend(
                [
                    f"    def get_{attr}_view(self) -> memoryview | None:",
                    f"        return self._get_opt_bytes_view({opt_args})",
                    "",
                ]
            )
        lines.extend(
            [
                f"    def set_{attr}(self, val: {opt_tp}) -> None:",
                f"        {set_call}",
                "",
            ]
        )
        return lines

    lines.extend(
        [
            f"    def get_{attr}(self) -> {s_py}:",
            f"        return self._get_{s_kind}({num})",
            "",
        ]
    )
    if s_kind == "bytes":
        lines.extend(
            [
                f"    def get_{attr}_view(self) -> memoryview:",
                f"        return self._get_bytes_view({num})",
                "",
            ]
        )
    lines.extend(
        [
            f"    def set_{attr}(self, val: {s_py}) -> None:",
            f"        self._set_{s_kind}({num}, val)",
            "",
        ]
    )
    return lines


def _generate_file(
    fdp: FileDescriptorProto,
    reg: _Registry,
    suffix: str,
) -> tuple[str, str]:
    if fdp.extension:
        raise ValueError(f"omnibuf: Proto2 file extensions are not supported in {fdp.name}")
    is_proto2 = fdp.syntax in ("", "proto2")
    local_msgs = reg.file_messages[fdp.name]
    imported_files: dict[str, str] = {}

    def _ref_msg_symbol(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        if spec.file_name == fdp.name:
            return spec.py_name
        alias = imported_files.get(spec.file_name)
        if alias is None:
            alias = f"_imp_{len(imported_files)}"
            imported_files[spec.file_name] = alias
        return f"{alias}.{spec.py_name}"

    def _ref_codec_symbol(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        codec_name = f"_CODEC_{_to_snake_case(spec.py_name).upper()}"
        if spec.file_name == fdp.name:
            return codec_name
        alias = imported_files.setdefault(spec.file_name, f"_imp_{len(imported_files)}")
        return f"{alias}.{codec_name}"

    def _ref_opaque_cls(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        cls_name = f"Opaque{spec.py_name}"
        if spec.file_name == fdp.name:
            return cls_name
        alias = imported_files.setdefault(spec.file_name, f"_imp_{len(imported_files)}")
        return f"{alias}.{cls_name}"

    for m_spec in local_msgs:
        mdp = m_spec.desc
        if mdp.extension or mdp.extension_range:
            raise ValueError(f"omnibuf: Proto2 extensions are not supported on {m_spec.full_name}")
        resolved: list[_ResolvedField] = []
        oneof_map: dict[int, _OneofGroup] = {}
        used_attrs: set[str] = set(_RESERVED_MSG_ATTRS)
        for od in mdp.oneof_decl:
            used_attrs.add(f"which_{_safe_ident(_to_snake_case(od.name))}")

        for fd in mdp.field:
            if fd.type == FieldDescriptorProto.TYPE_GROUP:
                raise ValueError(
                    f"omnibuf: Proto2 group field {m_spec.full_name}.{fd.name} is not supported"
                )
            num = fd.number
            if num < 1 or num > MAX_FIELD_NUMBER or (19000 <= num <= 19999):
                raise ValueError(f"omnibuf: invalid field number {num} on {m_spec.full_name}")
            rep = fd.label == FieldDescriptorProto.LABEL_REPEATED
            attr = _unique_field_attr(fd.name, used_attrs, num)
            map_entry = (
                reg.map_entries.get(fd.type_name)
                if fd.type == FieldDescriptorProto.TYPE_MESSAGE
                else None
            )
            if map_entry is not None:
                if map_entry.val_type == FieldDescriptorProto.TYPE_GROUP:
                    raise ValueError(
                        f"omnibuf: Proto2 group map value on {m_spec.full_name}.{fd.name} is not supported"
                    )
                sub_full = (
                    map_entry.val_type_name
                    if map_entry.val_type == FieldDescriptorProto.TYPE_MESSAGE
                    else ""
                )
                sub_py = _ref_msg_symbol(sub_full) if sub_full else ""
                resolved.append(
                    _ResolvedField(
                        number=num,
                        proto_name=fd.name,
                        attr_name=attr,
                        proto_type=fd.type,
                        repeated=False,
                        is_map=True,
                        explicit_presence=False,
                        map_key_type=map_entry.key_type,
                        map_val_type=map_entry.val_type,
                        sub_msg_full=sub_full,
                        sub_msg_py=sub_py,
                    )
                )
            else:
                is_msg = fd.type == FieldDescriptorProto.TYPE_MESSAGE
                has_oneof = fd.HasField("oneof_index")
                is_real_oneof = has_oneof and not bool(fd.proto3_optional)
                oneof_proto_name: str | None = None
                if is_real_oneof:
                    oidx = fd.oneof_index
                    oneof_proto_name = mdp.oneof_decl[oidx].name
                    if oidx not in oneof_map:
                        oneof_map[oidx] = _OneofGroup(
                            proto_name=oneof_proto_name,
                            safe_name=_safe_ident(_to_snake_case(oneof_proto_name)),
                        )
                explicit = not rep and (
                    is_msg or bool(fd.proto3_optional) or has_oneof or is_proto2
                )
                sub_full = fd.type_name if is_msg else ""
                sub_py = _ref_msg_symbol(sub_full) if sub_full else ""
                rf_obj = _ResolvedField(
                    number=num,
                    proto_name=fd.name,
                    attr_name=attr,
                    proto_type=fd.type,
                    repeated=rep,
                    is_map=False,
                    explicit_presence=explicit,
                    real_oneof=oneof_proto_name,
                    sub_msg_full=sub_full,
                    sub_msg_py=sub_py,
                )
                resolved.append(rf_obj)
                if is_real_oneof:
                    oneof_map[fd.oneof_index].members.append(rf_obj)

        for grp in oneof_map.values():
            grp.members.sort(key=lambda item: item.number)
            for member in grp.members:
                member.oneof_siblings = [m for m in grp.members if m.number != member.number]

        resolved.sort(key=lambda item: item.number)
        m_spec.fields = resolved
        m_spec.oneofs = [oneof_map[idx] for idx in sorted(oneof_map)]

    lines: list[str] = [
        f"# Code generated by protoc-gen-omnibuf-py from {fdp.name}. DO NOT EDIT.",
        "# ruff: noqa",
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass as _omnibuf_dataclass, field as _omnibuf_field",
        "from typing import TYPE_CHECKING as _omnibuf_TYPE_CHECKING, ClassVar as _omnibuf_ClassVar",
        "",
        "from omnibuf._omnibuf_ext import (",
        "    CompiledCodec as _omnibuf_CompiledCodec,",
        "    OpaqueView as _omnibuf_OpaqueView,",
        ")",
        "from omnibuf.wire import Buffer as _omnibuf_Buffer",
    ]

    for imp_file, alias in imported_files.items():
        pkg_mod, mod_stem = _module_import_for_proto(fdp.name, imp_file, suffix)
        lines.append(f"from {pkg_mod} import {mod_stem} as {alias}")

    lines.append("")

    for e_spec in reg.file_enums[fdp.name]:
        lines.append(f"class {e_spec.py_name}:")
        if not e_spec.desc.value:
            lines.append("    pass")
        else:
            for ev in e_spec.desc.value:
                lines.append(f"    {_safe_ident(ev.name)} = {ev.number}")
        lines.append("")

    for m_spec in local_msgs:
        snake_msg = _to_snake_case(m_spec.py_name)
        upper_msg = snake_msg.upper()
        codec_var = f"_CODEC_{upper_msg}"
        meta = _build_schema_meta(m_spec, reg)
        field0_bytes = encode_field0_schema_meta(meta)
        lines.append(f"_FIELD0_{upper_msg}: bytes = {field0_bytes!r}")
        lines.append("")

        lines.append("@_omnibuf_dataclass(slots=True)")
        lines.append(f"class {m_spec.py_name}:")
        lines.append("    if _omnibuf_TYPE_CHECKING:")
        lines.append(
            f"        __omnibuf_codec__: _omnibuf_ClassVar[_omnibuf_CompiledCodec[{m_spec.py_name}]]"
        )
        for rf in m_spec.fields:
            if rf.is_map:
                _, _, k_py, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
                if rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE:
                    v_py = rf.sub_msg_py
                else:
                    _, _, v_py, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
                lines.append(
                    f"    {rf.attr_name}: dict[{k_py}, {v_py}] = _omnibuf_field(default_factory=dict)"
                )
            elif rf.repeated:
                if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
                    e_py = rf.sub_msg_py
                else:
                    _, _, e_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
                lines.append(
                    f"    {rf.attr_name}: list[{e_py}] = _omnibuf_field(default_factory=list)"
                )
            elif rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
                lines.append(f"    {rf.attr_name}: {rf.sub_msg_py} | None = None")
            else:
                _, _, s_py, s_def = _PROTO_SCALAR_INFO[rf.proto_type]
                if rf.explicit_presence:
                    lines.append(f"    {rf.attr_name}: {s_py} | None = None")
                else:
                    lines.append(f"    {rf.attr_name}: {s_py} = {s_def}")

        for grp in m_spec.oneofs:
            lines.append("")
            lines.append(f"    def which_{grp.safe_name}(self) -> str | None:")
            for member in grp.members:
                lines.append(f"        if self.{member.attr_name} is not None:")
                lines.append(f"            return {member.proto_name!r}")
            lines.append("        return None")

        lines.extend(
            [
                "",
                "    def marshal_omnibuf(",
                "        self,",
                "        *,",
                "        deterministic: bool = False,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                f"        return {codec_var}.marshal(self, deterministic=deterministic, self_describing=self_describing)",
                "",
                "    @classmethod",
                "    def unmarshal_omnibuf(",
                "        cls,",
                "        data: _omnibuf_Buffer,",
                f"        out: {m_spec.py_name} | None = None,",
                "        *,",
                "        max_elements: int | None = None,",
                "        zero_copy_bytes: bool = False,",
                f"    ) -> {m_spec.py_name}:",
                f"        return {codec_var}.unmarshal(data, out, max_elements=max_elements, zero_copy_bytes=zero_copy_bytes)",
                "",
                f"{codec_var}: _omnibuf_CompiledCodec[{m_spec.py_name}] = _omnibuf_CompiledCodec({m_spec.py_name}, {m_spec.short_name!r})",
                f"{m_spec.py_name}.__omnibuf_codec__ = {codec_var}",
                f"marshal_{snake_msg} = {codec_var}.marshal",
                f"unmarshal_{snake_msg} = {codec_var}.unmarshal",
                f"_decode_{snake_msg} = {codec_var}.decode_at",
                "",
                f"class Opaque{m_spec.py_name}(_omnibuf_OpaqueView):",
                "    __slots__ = ()",
                "",
            ]
        )

        for rf in m_spec.fields:
            lines.extend(_emit_opaque_methods(rf, _ref_codec_symbol, _ref_opaque_cls))

        for grp in m_spec.oneofs:
            cand_items = ", ".join(
                f"({m.number}, {_field_wire_mask(m)}, {m.proto_name!r})" for m in grp.members
            )
            lines.extend(
                [
                    f"    def which_{grp.safe_name}(self) -> str | None:",
                    f"        return self._which_oneof(({cand_items},))",
                    "",
                ]
            )

        lines.extend(
            [
                "    def marshal(",
                "        self,",
                "        *,",
                "        dst_prefix: _omnibuf_Buffer | None = None,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                f"        return self._marshal_with_codec({codec_var}, dst_prefix=dst_prefix, self_describing=self_describing)",
                "",
                "    def marshal_validated(",
                "        self,",
                "        *,",
                "        dst_prefix: _omnibuf_Buffer | None = None,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                f"        return self._marshal_with_codec({codec_var}, dst_prefix=dst_prefix, self_describing=self_describing, validate_all=True)",
                "",
                "    def try_marshal(",
                "        self,",
                "        *,",
                "        dst_prefix: _omnibuf_Buffer | None = None,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                "        return self.marshal_validated(dst_prefix=dst_prefix, self_describing=self_describing)",
                "",
            ]
        )

    for m_spec in local_msgs:
        snake_msg = _to_snake_case(m_spec.py_name)
        upper_msg = snake_msg.upper()
        codec_var = f"_CODEC_{upper_msg}"
        if not m_spec.fields:
            lines.append(f"{codec_var}.set_fields([], _FIELD0_{upper_msg})")
        else:
            lines.append(f"{codec_var}.set_fields(")
            lines.append("    [")
            for rf in m_spec.fields:
                lines.append(f"        {_emit_field_spec_expr(rf, _ref_codec_symbol)},")
            lines.append("    ],")
            lines.append(f"    _FIELD0_{upper_msg},")
            lines.append(")")
        lines.append("")

    raw_parts = re.sub(r"\.proto$", "", fdp.name).split("/")
    out_dirs = [_sanitize_module_ident(p) for p in raw_parts[:-1]]
    out_stem = _sanitize_module_ident(f"{raw_parts[-1]}{suffix}")
    out_path = "/".join([*out_dirs, f"{out_stem}.py"])
    return out_path, "\n".join(lines)


def generate_code(req: plugin_pb2.CodeGeneratorRequest) -> plugin_pb2.CodeGeneratorResponse:
    """Generates Python OmniBuf codecs and Opaque views for a CodeGeneratorRequest."""
    resp = plugin_pb2.CodeGeneratorResponse()
    resp.supported_features = plugin_pb2.CodeGeneratorResponse.FEATURE_PROTO3_OPTIONAL

    suffix = "_omnibuf_pb"
    if req.parameter:
        for param in req.parameter.split(","):
            if "=" in param:
                k, v = param.split("=", 1)
                if k.strip() == "suffix" and v.strip():
                    suffix = re.sub(r"\.py$", "", v.strip())

    try:
        all_files = list(req.proto_file)
        reg = _Registry(all_files)
        target_set = set(req.file_to_generate)
        for fdp in all_files:
            if fdp.name not in target_set:
                continue
            out_name, content = _generate_file(fdp, reg, suffix)
            f_out = resp.file.add()
            f_out.name = out_name
            f_out.content = content
    except Exception as exc:  # noqa: BLE001
        resp.error = str(exc)

    return resp


def main() -> None:
    """CLI entry point for protoc-gen-omnibuf-py reading stdin and writing stdout."""
    raw_req = sys.stdin.buffer.read()
    req = plugin_pb2.CodeGeneratorRequest()
    req.ParseFromString(raw_req)
    resp = generate_code(req)
    sys.stdout.buffer.write(resp.SerializeToString())
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
