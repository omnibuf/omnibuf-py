"""protoc-gen-omnibuf-py code generator plugin (Tier 1: Generated Codec + Opaque Views)."""

from __future__ import annotations

import keyword
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from google.protobuf.compiler import plugin_pb2
from google.protobuf.descriptor_pb2 import (
    DescriptorProto,
    EnumDescriptorProto,
    FieldDescriptorProto,
    FileDescriptorProto,
)

from .field0 import SchemaMeta, encode_field0_schema_meta
from .wire import (
    MAX_FIELD_NUMBER,
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
    encode_tag,
)


def _to_snake_case(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _safe_ident(name: str) -> str:
    if keyword.iskeyword(name) or name in {"None", "True", "False", "self", "cls"}:
        return f"{name}_"
    return name


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


@dataclass(slots=True)
class _MapEntrySpec:
    full_name: str
    key_type: int
    val_type: int
    val_type_name: str


@dataclass(slots=True)
class _MsgSpec:
    full_name: str
    short_name: str
    py_name: str
    file_name: str
    desc: DescriptorProto
    fields: list[_ResolvedField] = field(default_factory=list)


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
    cur_parts = re.sub(r"\.proto$", "", current_proto).split("/")[:-1]
    tgt_clean = re.sub(r"\.proto$", "", target_proto).split("/")
    stem = f"{tgt_clean[-1]}{suffix}"
    tgt_parts = tgt_clean[:-1]
    if not cur_parts:
        return ".".join(tgt_parts), stem
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
) -> SchemaMeta:
    meta = SchemaMeta(type_name=msg_spec.short_name)
    next_visiting = visiting | {msg_spec.full_name}
    for rf in msg_spec.fields:
        meta.fields[rf.number] = rf.proto_name
        if rf.sub_msg_full and rf.sub_msg_full not in next_visiting:
            child_spec = reg.messages.get(rf.sub_msg_full)
            if child_spec is not None:
                meta.children[rf.number] = _build_schema_meta(child_spec, reg, next_visiting)
    return meta


def _emit_tag_append(tag_b: bytes, indent: str) -> str:
    if len(tag_b) == 1:
        return f"{indent}dst.append({tag_b[0]})"
    return f"{indent}dst.extend({tag_b!r})"


def _emit_scalar_encode_lines(
    kind: str,
    val_expr: str,
    indent: str,
) -> list[str]:
    if kind == "uint32":
        return [
            f"{indent}_v = int({val_expr})",
            f"{indent}if 0 <= _v <= 127:",
            f"{indent}    dst.append((_v << 1) | 1)",
            f"{indent}elif 0 <= _v <= 0xFFFFFFFF:",
            f"{indent}    append_varint(dst, _v)",
            f"{indent}else:",
            f'{indent}    raise OmniBufEncodeError("omnibuf: uint32 out of range")',
        ]
    if kind == "uint64":
        return [
            f"{indent}_v = int({val_expr})",
            f"{indent}if 0 <= _v <= 127:",
            f"{indent}    dst.append((_v << 1) | 1)",
            f"{indent}elif 0 <= _v <= 0xFFFFFFFFFFFFFFFF:",
            f"{indent}    append_varint(dst, _v)",
            f"{indent}else:",
            f'{indent}    raise OmniBufEncodeError("omnibuf: uint64 out of range")',
        ]
    if kind == "sint32":
        return [
            f"{indent}_vi = int({val_expr})",
            f"{indent}if -64 <= _vi <= 63:",
            f"{indent}    dst.append(((((_vi << 1) ^ (_vi >> 31)) & 0xFF) << 1) | 1)",
            f"{indent}else:",
            f"{indent}    append_varint(dst, encode_zigzag32(_vi))",
        ]
    if kind == "sint64":
        return [
            f"{indent}_vi = int({val_expr})",
            f"{indent}if -64 <= _vi <= 63:",
            f"{indent}    dst.append(((((_vi << 1) ^ (_vi >> 63)) & 0xFF) << 1) | 1)",
            f"{indent}else:",
            f"{indent}    append_varint(dst, encode_zigzag(_vi))",
        ]
    if kind == "fixed32":
        return [f"{indent}dst.extend(_U32_PACK(int({val_expr})))"]
    if kind == "sfixed32":
        return [f"{indent}dst.extend(_I32_PACK(int({val_expr})))"]
    if kind == "fixed64":
        return [f"{indent}dst.extend(_U64_PACK(int({val_expr})))"]
    if kind == "sfixed64":
        return [f"{indent}dst.extend(_I64_PACK(int({val_expr})))"]
    if kind == "float32":
        return [f"{indent}dst.extend(_F32_PACK(float({val_expr})))"]
    if kind == "float64":
        return [f"{indent}dst.extend(_F64_PACK(float({val_expr})))"]
    if kind == "string":
        return [
            f"{indent}_raw = {val_expr}.encode('utf-8')",
            f"{indent}_slen = len(_raw)",
            f"{indent}if _slen <= 127:",
            f"{indent}    dst.append((_slen << 1) | 1)",
            f"{indent}else:",
            f"{indent}    append_varint(dst, _slen)",
            f"{indent}dst.extend(_raw)",
        ]
    if kind == "bytes":
        return [
            f"{indent}_b = {val_expr}",
            f"{indent}_blen = len(_b)",
            f"{indent}if _blen <= 127:",
            f"{indent}    dst.append((_blen << 1) | 1)",
            f"{indent}else:",
            f"{indent}    append_varint(dst, _blen)",
            f"{indent}dst.extend(_b)",
        ]
    if kind == "bool":
        return [f"{indent}dst.append(1 if {val_expr} else 0)"]
    return []


def _emit_scalar_decode_lines(
    kind: str,
    buf_var: str,
    pos_var: str,
    end_var: str,
    target_lhs: str,
    indent: str,
) -> list[str]:
    if kind == "uint32":
        return [
            f"{indent}if {pos_var} >= {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated uint32")',
            f"{indent}_vb = {buf_var}[{pos_var}]",
            f"{indent}if _vb & 1:",
            f"{indent}    {target_lhs} = _vb >> 1",
            f"{indent}    {pos_var} += 1",
            f"{indent}else:",
            f"{indent}    _v, _w = decode_varint({buf_var}, {pos_var}, {end_var})",
            f"{indent}    if _w == 0:",
            f'{indent}        raise OmniBufDecodeError("omnibuf: invalid uint32")',
            f"{indent}    {target_lhs} = _v & 0xFFFFFFFF",
            f"{indent}    {pos_var} += _w",
        ]
    if kind == "uint64":
        return [
            f"{indent}if {pos_var} >= {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated uint64")',
            f"{indent}_vb = {buf_var}[{pos_var}]",
            f"{indent}if _vb & 1:",
            f"{indent}    {target_lhs} = _vb >> 1",
            f"{indent}    {pos_var} += 1",
            f"{indent}else:",
            f"{indent}    _v, _w = decode_varint({buf_var}, {pos_var}, {end_var})",
            f"{indent}    if _w == 0:",
            f'{indent}        raise OmniBufDecodeError("omnibuf: invalid uint64")',
            f"{indent}    {target_lhs} = _v",
            f"{indent}    {pos_var} += _w",
        ]
    if kind == "sint32":
        return [
            f"{indent}if {pos_var} >= {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated sint32")',
            f"{indent}_vb = {buf_var}[{pos_var}]",
            f"{indent}if _vb & 1:",
            f"{indent}    _u = _vb >> 1",
            f"{indent}    {target_lhs} = (_u >> 1) ^ -(_u & 1)",
            f"{indent}    {pos_var} += 1",
            f"{indent}else:",
            f"{indent}    _v, _w = decode_varint({buf_var}, {pos_var}, {end_var})",
            f"{indent}    if _w == 0:",
            f'{indent}        raise OmniBufDecodeError("omnibuf: invalid sint32")',
            f"{indent}    {target_lhs} = decode_zigzag32(_v)",
            f"{indent}    {pos_var} += _w",
        ]
    if kind == "sint64":
        return [
            f"{indent}if {pos_var} >= {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated sint64")',
            f"{indent}_vb = {buf_var}[{pos_var}]",
            f"{indent}if _vb & 1:",
            f"{indent}    _u = _vb >> 1",
            f"{indent}    {target_lhs} = (_u >> 1) ^ -(_u & 1)",
            f"{indent}    {pos_var} += 1",
            f"{indent}else:",
            f"{indent}    _v, _w = decode_varint({buf_var}, {pos_var}, {end_var})",
            f"{indent}    if _w == 0:",
            f'{indent}        raise OmniBufDecodeError("omnibuf: invalid sint64")',
            f"{indent}    {target_lhs} = decode_zigzag(_v)",
            f"{indent}    {pos_var} += _w",
        ]
    if kind == "fixed32":
        return [
            f"{indent}if {pos_var} + 4 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated fixed32")',
            f"{indent}({target_lhs},) = _U32_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 4",
        ]
    if kind == "sfixed32":
        return [
            f"{indent}if {pos_var} + 4 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated sfixed32")',
            f"{indent}({target_lhs},) = _I32_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 4",
        ]
    if kind == "fixed64":
        return [
            f"{indent}if {pos_var} + 8 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated fixed64")',
            f"{indent}({target_lhs},) = _U64_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 8",
        ]
    if kind == "sfixed64":
        return [
            f"{indent}if {pos_var} + 8 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated sfixed64")',
            f"{indent}({target_lhs},) = _I64_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 8",
        ]
    if kind == "float32":
        return [
            f"{indent}if {pos_var} + 4 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated float32")',
            f"{indent}({target_lhs},) = _F32_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 4",
        ]
    if kind == "float64":
        return [
            f"{indent}if {pos_var} + 8 > {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated float64")',
            f"{indent}({target_lhs},) = _F64_UNPACK({buf_var}, {pos_var})",
            f"{indent}{pos_var} += 8",
        ]
    if kind == "string":
        return [
            f"{indent}if {pos_var} >= {end_var}:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: truncated string")',
            f"{indent}_sb = {buf_var}[{pos_var}]",
            f"{indent}if _sb & 1:",
            f"{indent}    _slen = _sb >> 1",
            f"{indent}    {pos_var} += 1",
            f"{indent}    if {pos_var} + _slen > {end_var}:",
            f'{indent}        raise OmniBufDecodeError("omnibuf: truncated string")',
            f"{indent}    {target_lhs} = {buf_var}[{pos_var} : {pos_var} + _slen].decode('utf-8')",
            f"{indent}    {pos_var} += _slen",
            f"{indent}else:",
            f"{indent}    _s_mv, {pos_var} = read_len_bytes({buf_var}, {pos_var}, 0, {end_var})",
            f"{indent}    {target_lhs} = _s_mv.decode('utf-8')",
        ]
    if kind == "bytes":
        return [
            f"{indent}_b_mv, {pos_var} = read_len_bytes({buf_var}, {pos_var}, 0, {end_var})",
            f"{indent}{target_lhs} = bytes(_b_mv)",
        ]
    if kind == "bool":
        return [
            f"{indent}if {pos_var} >= {end_var} or {buf_var}[{pos_var}] > 1:",
            f'{indent}    raise OmniBufDecodeError("omnibuf: invalid bool byte")',
            f"{indent}{target_lhs} = {buf_var}[{pos_var}] == 1",
            f"{indent}{pos_var} += 1",
        ]
    return []


def _generate_file(
    fdp: FileDescriptorProto,
    reg: _Registry,
    suffix: str,
) -> tuple[str, str]:
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

    def _ref_encode_fn(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        fn_name = f"_encode_{_to_snake_case(spec.py_name)}"
        if spec.file_name == fdp.name:
            return fn_name
        alias = imported_files.setdefault(spec.file_name, f"_imp_{len(imported_files)}")
        return f"{alias}.{fn_name}"

    def _ref_decode_fn(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        fn_name = f"_decode_{_to_snake_case(spec.py_name)}"
        if spec.file_name == fdp.name:
            return fn_name
        alias = imported_files.setdefault(spec.file_name, f"_imp_{len(imported_files)}")
        return f"{alias}.{fn_name}"

    def _ref_opaque_cls(full_type_name: str) -> str:
        spec = reg.messages[full_type_name]
        cls_name = f"Opaque{spec.py_name}"
        if spec.file_name == fdp.name:
            return cls_name
        alias = imported_files.setdefault(spec.file_name, f"_imp_{len(imported_files)}")
        return f"{alias}.{cls_name}"

    # Resolve fields for all messages in this file
    for m_spec in local_msgs:
        mdp = m_spec.desc
        resolved: list[_ResolvedField] = []
        for fd in mdp.field:
            num = fd.number
            if num < 1 or num > MAX_FIELD_NUMBER or (19000 <= num <= 19999):
                raise ValueError(f"omnibuf: invalid field number {num} on {m_spec.full_name}")
            rep = fd.label == FieldDescriptorProto.LABEL_REPEATED
            attr = _safe_ident(fd.name)
            map_entry = (
                reg.map_entries.get(fd.type_name)
                if fd.type == FieldDescriptorProto.TYPE_MESSAGE
                else None
            )
            if map_entry is not None:
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
                explicit = not rep and (
                    is_msg or bool(fd.proto3_optional) or has_oneof or is_proto2
                )
                sub_full = fd.type_name if is_msg else ""
                sub_py = _ref_msg_symbol(sub_full) if sub_full else ""
                resolved.append(
                    _ResolvedField(
                        number=num,
                        proto_name=fd.name,
                        attr_name=attr,
                        proto_type=fd.type,
                        repeated=rep,
                        is_map=False,
                        explicit_presence=explicit,
                        sub_msg_full=sub_full,
                        sub_msg_py=sub_py,
                    )
                )
        resolved.sort(key=lambda item: item.number)
        m_spec.fields = resolved

    lines: list[str] = [
        f"# Code generated by protoc-gen-omnibuf-py from {fdp.name}. DO NOT EDIT.",
        "# ruff: noqa",
        "",
        "from __future__ import annotations",
        "",
        "import struct",
        "from dataclasses import dataclass, field",
        "from typing import Any",
        "",
        "from omnibuf.field0 import read_field0_schema_meta",
        "from omnibuf.opaque import (",
        "    opaque_get_bool,",
        "    opaque_get_bytes,",
        "    opaque_get_fixed32,",
        "    opaque_get_fixed64,",
        "    opaque_get_float32,",
        "    opaque_get_float64,",
        "    opaque_get_map,",
        "    opaque_get_scalar_array,",
        "    opaque_get_sfixed32,",
        "    opaque_get_sfixed64,",
        "    opaque_get_sint32,",
        "    opaque_get_sint64,",
        "    opaque_get_string,",
        "    opaque_get_submsg,",
        "    opaque_get_submsg_array,",
        "    opaque_get_submsg_slice,",
        "    opaque_get_uint32,",
        "    opaque_get_uint64,",
        "    splice_dirty_fields,",
        ")",
        "from omnibuf.wire import (",
        "    MAX_FIELD_NUMBER,",
        "    MAX_NESTING_DEPTH,",
        "    WIRE_ARRAY,",
        "    WIRE_BOOL_FALSE,",
        "    WIRE_BOOL_TRUE,",
        "    WIRE_MAP,",
        "    WIRE_SUB_MSG,",
        "    Buffer,",
        "    OmniBufDecodeError,",
        "    OmniBufEncodeError,",
        "    append_varint,",
        "    backpatch_container_len,",
        "    decode_utf8_strict,",
        "    decode_varint,",
        "    decode_zigzag,",
        "    decode_zigzag32,",
        "    encode_utf8_strict,",
        "    encode_zigzag,",
        "    encode_zigzag32,",
        "    parse_array_header,",
        "    parse_map_header,",
        "    read_len_bytes,",
        "    validate_field0_at,",
        "    validate_message,",
        "    validate_value,",
        ")",
    ]

    for imp_file, alias in imported_files.items():
        pkg_mod, mod_stem = _module_import_for_proto(fdp.name, imp_file, suffix)
        if pkg_mod:
            lines.append(f"from {pkg_mod} import {mod_stem} as {alias}")
        else:
            lines.append(f"import {mod_stem} as {alias}")

    lines.extend(
        [
            "",
            "_U32_PACK = struct.Struct('<I').pack",
            "_I32_PACK = struct.Struct('<i').pack",
            "_U64_PACK = struct.Struct('<Q').pack",
            "_I64_PACK = struct.Struct('<q').pack",
            "_F32_PACK = struct.Struct('<f').pack",
            "_F64_PACK = struct.Struct('<d').pack",
            "_U32_UNPACK = struct.Struct('<I').unpack_from",
            "_I32_UNPACK = struct.Struct('<i').unpack_from",
            "_U64_UNPACK = struct.Struct('<Q').unpack_from",
            "_I64_UNPACK = struct.Struct('<q').unpack_from",
            "_F32_UNPACK = struct.Struct('<f').unpack_from",
            "_F64_UNPACK = struct.Struct('<d').unpack_from",
            "",
        ]
    )

    # Emit enums as IntEnum constants if present
    for e_spec in reg.file_enums[fdp.name]:
        lines.append(f"class {e_spec.py_name}:")
        if not e_spec.desc.value:
            lines.append("    pass")
        else:
            for ev in e_spec.desc.value:
                lines.append(f"    {_safe_ident(ev.name)} = {ev.number}")
        lines.append("")

    # Emit dataclasses, codecs, and Opaque views for each message
    for m_spec in local_msgs:
        snake_msg = _to_snake_case(m_spec.py_name)
        meta = _build_schema_meta(m_spec, reg)
        field0_bytes = encode_field0_schema_meta(meta)
        lines.append(f"_FIELD0_{snake_msg.upper()}: bytes = {field0_bytes!r}")
        lines.append("")

        # 1. Message Dataclass
        lines.append("@dataclass(slots=True)")
        lines.append(f"class {m_spec.py_name}:")
        if not m_spec.fields:
            lines.append("    pass")
        else:
            for rf in m_spec.fields:
                if rf.is_map:
                    _, _, k_py, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
                    if rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE:
                        v_py = rf.sub_msg_py
                    else:
                        _, _, v_py, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
                    lines.append(
                        f"    {rf.attr_name}: dict[{k_py}, {v_py}] = field(default_factory=dict)"
                    )
                elif rf.repeated:
                    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
                        e_py = rf.sub_msg_py
                    else:
                        _, _, e_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
                    lines.append(f"    {rf.attr_name}: list[{e_py}] = field(default_factory=list)")
                elif rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
                    lines.append(f"    {rf.attr_name}: {rf.sub_msg_py} | None = None")
                else:
                    _, _, s_py, s_def = _PROTO_SCALAR_INFO[rf.proto_type]
                    if rf.explicit_presence:
                        lines.append(f"    {rf.attr_name}: {s_py} | None = None")
                    else:
                        lines.append(f"    {rf.attr_name}: {s_py} = {s_def}")

        lines.extend(
            [
                "",
                "    def marshal_omnibuf(",
                "        self,",
                "        *,",
                "        deterministic: bool = False,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                f"        return marshal_{snake_msg}(self, deterministic=deterministic, self_describing=self_describing)",
                "",
                "    @classmethod",
                f"    def unmarshal_omnibuf(cls, data: Buffer, out: {m_spec.py_name} | None = None) -> {m_spec.py_name}:",
                f"        return unmarshal_{snake_msg}(data, out)",
                "",
            ]
        )

        # 2. Helper to encode a single field by field_num (shared by _encode and Opaque splice)
        lines.append(
            f"def _encode_{snake_msg}_field(dst: bytearray, fnum: int, val: Any, deterministic: bool) -> None:"
        )
        if not m_spec.fields:
            lines.append("    return")
        else:
            for idx, rf in enumerate(m_spec.fields):
                kw = "if" if idx == 0 else "elif"
                lines.append(f"    {kw} fnum == {rf.number}:")
                lines.extend(_emit_field_encode_block(rf, "val", _ref_encode_fn, "        "))
        lines.append("")

        # 3. Full-message _encode_<msg> and marshal_<msg>
        lines.append(
            f"def _encode_{snake_msg}(dst: bytearray, msg: Any, deterministic: bool) -> None:"
        )
        if not m_spec.fields:
            lines.append("    return")
        else:
            for rf in m_spec.fields:
                v_var = f"_v_{rf.number}"
                lines.append(f"    {v_var} = msg.{rf.attr_name}")
                if (
                    rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE
                    and not rf.repeated
                    and not rf.is_map
                ) or rf.explicit_presence:
                    lines.append(f"    if {v_var} is not None:")
                    lines.extend(_emit_field_encode_block(rf, v_var, _ref_encode_fn, "        "))
                else:
                    lines.extend(_emit_field_encode_block(rf, v_var, _ref_encode_fn, "    "))
        lines.append("")

        lines.extend(
            [
                f"def marshal_{snake_msg}(",
                "    msg: Any,",
                "    *,",
                "    deterministic: bool = False,",
                "    self_describing: bool = False,",
                ") -> bytes:",
                "    dst = bytearray()",
                "    if self_describing:",
                f"        dst.extend(_FIELD0_{snake_msg.upper()})",
                "    try:",
                f"        _encode_{snake_msg}(dst, msg, deterministic)",
                "    except UnicodeEncodeError as exc:",
                "        raise OmniBufEncodeError(str(exc)) from exc",
                "    return bytes(dst)",
                "",
            ]
        )

        # 4. Full-message _decode_<msg> and unmarshal_<msg>
        lines.extend(
            [
                f"def _decode_{snake_msg}(",
                "    data: Buffer,",
                f"    out: {m_spec.py_name} | None = None,",
                "    depth: int = 0,",
                "    merge: bool = False,",
                f") -> {m_spec.py_name}:",
                "    if depth > MAX_NESTING_DEPTH:",
                '        raise OmniBufDecodeError("omnibuf: nesting depth exceeds limit")',
                "    if out is None:",
                f"        out = {m_spec.py_name}()",
                "    elif not merge:",
            ]
        )
        if not m_spec.fields:
            lines.append("        pass")
        else:
            for rf in m_spec.fields:
                if rf.is_map or rf.repeated:
                    lines.append(f"        out.{rf.attr_name}.clear()")
                elif rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE or rf.explicit_presence:
                    lines.append(f"        out.{rf.attr_name} = None")
                else:
                    _, _, _, s_def = _PROTO_SCALAR_INFO[rf.proto_type]
                    lines.append(f"        out.{rf.attr_name} = {s_def}")

        lines.extend(
            [
                "    mv = data if isinstance(data, (bytes, bytearray)) else bytes(data)",
                "    n = len(mv)",
                "    pos = 0",
                "    seen_mask = 0",
                "    try:",
                "        while pos < n:",
                "            b0 = mv[pos]",
                "            if b0 & 1:",
                "                fnum = b0 >> 5",
                "                wt = (b0 >> 1) & 0x0F",
                "                pos += 1",
                "            elif b0 & 2:",
                "                if pos + 2 > n:",
                '                    raise OmniBufDecodeError("omnibuf: truncated tag")',
                "                u16 = (b0 | (mv[pos + 1] << 8)) >> 2",
                "                fnum = u16 >> 4",
                "                wt = u16 & 0x0F",
                "                pos += 2",
                "            else:",
                "                tag, tn = decode_varint(mv, pos, n)",
                "                if tn == 0 or (tag >> 4) > MAX_FIELD_NUMBER:",
                '                    raise OmniBufDecodeError("omnibuf: invalid tag")',
                "                fnum = tag >> 4",
                "                wt = tag & 0x0F",
                "                pos += tn",
                "            if fnum == 0:",
                "                pos = validate_field0_at(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
                "                continue",
            ]
        )

        if not m_spec.fields:
            lines.append(
                "            pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)"
            )
        else:
            for idx, rf in enumerate(m_spec.fields):
                kw = "if" if idx == 0 else "elif"
                lines.append(f"            {kw} fnum == {rf.number}:")
                lines.extend(_emit_field_decode_block(rf, idx, _ref_decode_fn, "                "))
            lines.append("            else:")
            lines.append(
                "                pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)"
            )

        lines.extend(
            [
                "    except UnicodeDecodeError as exc:",
                "        raise OmniBufDecodeError(str(exc)) from exc",
                "    return out",
                "",
                f"def unmarshal_{snake_msg}(data: Buffer, out: {m_spec.py_name} | None = None) -> {m_spec.py_name}:",
                f"    return _decode_{snake_msg}(data, out, 0, False)",
                "",
            ]
        )

        # 5. Lazy Opaque<Message> View
        slot_names = ["_raw", "_dirty_nums"] + [f"_d_{rf.attr_name}" for rf in m_spec.fields]
        slots_tuple = ", ".join(repr(s) for s in slot_names)
        lines.extend(
            [
                f"class Opaque{m_spec.py_name}:",
                f"    __slots__ = ({slots_tuple},)",
                "",
                "    def __init__(self, raw: Buffer) -> None:",
                "        self._raw: Buffer = raw",
                "        self._dirty_nums: set[int] = set()",
            ]
        )
        for rf in m_spec.fields:
            lines.append(f"        self._d_{rf.attr_name}: Any = None")
        lines.extend(
            [
                "",
                "    def raw(self) -> Buffer:",
                "        return self._raw",
                "",
            ]
        )

        for rf in m_spec.fields:
            lines.extend(_emit_opaque_methods(rf, _ref_decode_fn, _ref_opaque_cls))

        lines.extend(
            [
                "    def _encode_dirty(self, dst: bytearray, fnum: int) -> None:",
            ]
        )
        if not m_spec.fields:
            lines.append("        return")
        else:
            for idx, rf in enumerate(m_spec.fields):
                kw = "if" if idx == 0 else "elif"
                lines.append(f"        {kw} fnum == {rf.number}:")
                lines.append(f"            _v = self._d_{rf.attr_name}")
                if (
                    rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE
                    and not rf.repeated
                    and not rf.is_map
                ):
                    lines.append("            if _v is not None:")
                    lines.append(
                        f"                _encode_{snake_msg}_field(dst, {rf.number}, _v, True)"
                    )
                else:
                    lines.append(
                        f"            _encode_{snake_msg}_field(dst, {rf.number}, _v, True)"
                    )

        lines.extend(
            [
                "",
                "    def marshal(",
                "        self,",
                "        *,",
                "        dst_prefix: Buffer | None = None,",
                "        self_describing: bool = False,",
                "    ) -> bytes:",
                "        if self._dirty_nums:",
                "            try:",
                "                spliced = splice_dirty_fields(None, self._raw, self._dirty_nums, self._encode_dirty)",
                "            except UnicodeEncodeError as exc:",
                "                raise OmniBufEncodeError(str(exc)) from exc",
                "            self._raw = spliced",
                "            self._dirty_nums.clear()",
                "        else:",
                "            validate_message(self._raw)",
                "            spliced = bytes(self._raw)",
                "        prefix = bytearray(dst_prefix) if dst_prefix is not None else bytearray()",
                "        if self_describing and read_field0_schema_meta(spliced) is None:",
                f"            prefix.extend(_FIELD0_{snake_msg.upper()})",
                "        if prefix:",
                "            prefix.extend(spliced)",
                "            return bytes(prefix)",
                "        return spliced",
                "",
            ]
        )

    out_path = re.sub(r"\.proto$", f"{suffix}.py", fdp.name)
    return out_path, "\n".join(lines)


def _emit_field_encode_block(
    rf: _ResolvedField,
    val_expr: str,
    ref_encode_fn: Any,
    indent: str,
) -> list[str]:
    out: list[str] = []
    if rf.is_map:
        k_kind, k_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
        is_v_msg = rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE
        if is_v_msg:
            v_kind, v_wt = "submsg", WIRE_SUB_MSG
        else:
            v_kind, v_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
        tag_b = encode_tag(rf.number, WIRE_MAP)
        out.extend(
            [
                f"{indent}dst.extend({tag_b!r})",
                f"{indent}_lp = len(dst)",
                f"{indent}dst.extend(b'\\x00\\x00')",
                f"{indent}dst.append({k_wt})",
                f"{indent}dst.append({v_wt})",
                f"{indent}_mp = {val_expr}",
                f"{indent}append_varint(dst, len(_mp))",
                f"{indent}_keys = sorted(_mp.keys()) if deterministic and len(_mp) > 1 else _mp.keys()",
                f"{indent}for _k in _keys:",
                f"{indent}    _mv_val = _mp[_k]",
            ]
        )
        out.extend(_emit_scalar_encode_lines(k_kind, "_k", indent + "    "))
        if is_v_msg:
            enc_fn = ref_encode_fn(rf.sub_msg_full)
            out.extend(
                [
                    f"{indent}    _vp = len(dst)",
                    f"{indent}    dst.extend(b'\\x00\\x00')",
                    f"{indent}    if _mv_val is not None:",
                    f"{indent}        {enc_fn}(dst, _mv_val, deterministic)",
                    f"{indent}    backpatch_container_len(dst, _vp)",
                ]
            )
        else:
            out.extend(_emit_scalar_encode_lines(v_kind, "_mv_val", indent + "    "))
        out.append(f"{indent}backpatch_container_len(dst, _lp)")
        return out

    if rf.repeated:
        tag_b = encode_tag(rf.number, WIRE_ARRAY)
        if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
            enc_fn = ref_encode_fn(rf.sub_msg_full)
            out.extend(
                [
                    f"{indent}dst.extend({tag_b!r})",
                    f"{indent}_lp = len(dst)",
                    f"{indent}dst.extend(b'\\x00\\x00')",
                    f"{indent}dst.append({WIRE_SUB_MSG})",
                    f"{indent}_arr = {val_expr}",
                    f"{indent}append_varint(dst, len(_arr))",
                    f"{indent}for _item in _arr:",
                    f"{indent}    _ep = len(dst)",
                    f"{indent}    dst.extend(b'\\x00\\x00')",
                    f"{indent}    if _item is not None:",
                    f"{indent}        {enc_fn}(dst, _item, deterministic)",
                    f"{indent}    backpatch_container_len(dst, _ep)",
                    f"{indent}backpatch_container_len(dst, _lp)",
                ]
            )
        else:
            e_kind, e_wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
            out.extend(
                [
                    f"{indent}dst.extend({tag_b!r})",
                    f"{indent}_lp = len(dst)",
                    f"{indent}dst.extend(b'\\x00\\x00')",
                    f"{indent}dst.append({e_wt})",
                    f"{indent}_arr = {val_expr}",
                    f"{indent}append_varint(dst, len(_arr))",
                    f"{indent}for _item in _arr:",
                ]
            )
            out.extend(_emit_scalar_encode_lines(e_kind, "_item", indent + "    "))
            out.append(f"{indent}backpatch_container_len(dst, _lp)")
        return out

    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        tag_b = encode_tag(rf.number, WIRE_SUB_MSG)
        enc_fn = ref_encode_fn(rf.sub_msg_full)
        out.extend(
            [
                _emit_tag_append(tag_b, indent),
                f"{indent}_lp = len(dst)",
                f"{indent}dst.extend(b'\\x00\\x00')",
                f"{indent}{enc_fn}(dst, {val_expr}, deterministic)",
                f"{indent}backpatch_container_len(dst, _lp)",
            ]
        )
        return out

    if rf.proto_type == FieldDescriptorProto.TYPE_BOOL:
        t_false = encode_tag(rf.number, WIRE_BOOL_FALSE)
        t_true = encode_tag(rf.number, WIRE_BOOL_TRUE)
        if len(t_true) == 1 and len(t_false) == 1:
            out.append(f"{indent}dst.append({t_true[0]} if {val_expr} else {t_false[0]})")
        else:
            out.append(f"{indent}dst.extend({t_true!r} if {val_expr} else {t_false!r})")
        return out

    s_kind, s_wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
    tag_b = encode_tag(rf.number, s_wt)
    out.append(_emit_tag_append(tag_b, indent))
    out.extend(_emit_scalar_encode_lines(s_kind, val_expr, indent))
    return out


def _emit_field_decode_block(
    rf: _ResolvedField,
    field_idx: int,
    ref_decode_fn: Any,
    indent: str,
) -> list[str]:
    bit = 1 << field_idx
    out: list[str] = []

    if rf.is_map:
        k_kind, k_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
        is_v_msg = rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE
        if is_v_msg:
            v_kind, v_wt = "submsg", WIRE_SUB_MSG
        else:
            v_kind, v_wt, _, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
        out.extend(
            [
                f"{indent}if wt != WIRE_MAP:",
                f"{indent}    pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
                f"{indent}    continue",
                f"{indent}if depth + 1 > MAX_NESTING_DEPTH:",
                f'{indent}    raise OmniBufDecodeError("omnibuf: map depth exceeds limit")',
                f"{indent}_already = ((seen_mask & {bit}) != 0) or merge",
                f"{indent}seen_mask |= {bit}",
                f"{indent}_m_mv, pos = read_len_bytes(mv, pos, 3, n)",
                f"{indent}_kwt, _vwt, _cnt, _p, _ok = parse_map_header(_m_mv)",
                f"{indent}if not _ok or _kwt != {k_wt} or _vwt != {v_wt}:",
                f'{indent}    raise OmniBufDecodeError("omnibuf: invalid map header")',
                f"{indent}_mp = out.{rf.attr_name}",
                f"{indent}if not _already and _mp:",
                f"{indent}    _mp.clear()",
                f"{indent}_mend = len(_m_mv)",
                f"{indent}for _ in range(_cnt):",
            ]
        )
        out.extend(
            _emit_scalar_decode_lines(k_kind, "_m_mv", "_p", "_mend", "_mk", indent + "    ")
        )
        if is_v_msg:
            dec_fn = ref_decode_fn(rf.sub_msg_full)
            out.extend(
                [
                    f"{indent}    _vmv, _p = read_len_bytes(_m_mv, _p, 0, _mend)",
                    f"{indent}    _mp[_mk] = {dec_fn}(_vmv, None, depth + 2, False)",
                ]
            )
        else:
            out.extend(
                _emit_scalar_decode_lines(
                    v_kind, "_m_mv", "_p", "_mend", "_mp[_mk]", indent + "    "
                )
            )
        out.extend(
            [
                f"{indent}if _p != _mend:",
                f'{indent}    raise OmniBufDecodeError("omnibuf: trailing map bytes")',
            ]
        )
        return out

    if rf.repeated:
        out.extend(
            [
                f"{indent}if wt != WIRE_ARRAY:",
                f"{indent}    pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
                f"{indent}    continue",
                f"{indent}if depth + 1 > MAX_NESTING_DEPTH:",
                f'{indent}    raise OmniBufDecodeError("omnibuf: array depth exceeds limit")',
                f"{indent}_already = ((seen_mask & {bit}) != 0) or merge",
                f"{indent}seen_mask |= {bit}",
                f"{indent}_a_mv, pos = read_len_bytes(mv, pos, 2, n)",
                f"{indent}_ewt, _cnt, _p, _ok = parse_array_header(_a_mv)",
            ]
        )
        if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
            dec_fn = ref_decode_fn(rf.sub_msg_full)
            out.extend(
                [
                    f"{indent}if not _ok or _ewt != WIRE_SUB_MSG:",
                    f'{indent}    raise OmniBufDecodeError("omnibuf: invalid submsg array header")',
                    f"{indent}_lst = out.{rf.attr_name}",
                    f"{indent}if not _already and _lst:",
                    f"{indent}    _lst.clear()",
                    f"{indent}_aend = len(_a_mv)",
                    f"{indent}for _ in range(_cnt):",
                    f"{indent}    _emv, _p = read_len_bytes(_a_mv, _p, 0, _aend)",
                    f"{indent}    _lst.append({dec_fn}(_emv, None, depth + 2, False))",
                    f"{indent}if _p != _aend:",
                    f'{indent}    raise OmniBufDecodeError("omnibuf: trailing submsg array bytes")',
                ]
            )
        else:
            e_kind, e_wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
            out.extend(
                [
                    f"{indent}if not _ok or _ewt != {e_wt}:",
                    f'{indent}    raise OmniBufDecodeError("omnibuf: invalid array header")',
                    f"{indent}_lst = out.{rf.attr_name}",
                    f"{indent}if not _already and _lst:",
                    f"{indent}    _lst.clear()",
                    f"{indent}_aend = len(_a_mv)",
                    f"{indent}for _ in range(_cnt):",
                ]
            )
            out.extend(
                _emit_scalar_decode_lines(e_kind, "_a_mv", "_p", "_aend", "_item", indent + "    ")
            )
            out.extend(
                [
                    f"{indent}    _lst.append(_item)",
                    f"{indent}if _p != _aend:",
                    f'{indent}    raise OmniBufDecodeError("omnibuf: trailing array bytes")',
                ]
            )
        return out

    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        dec_fn = ref_decode_fn(rf.sub_msg_full)
        out.extend(
            [
                f"{indent}if wt != WIRE_SUB_MSG:",
                f"{indent}    pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
                f"{indent}    continue",
                f"{indent}_already = ((seen_mask & {bit}) != 0) or merge",
                f"{indent}seen_mask |= {bit}",
                f"{indent}_sub_mv, pos = read_len_bytes(mv, pos, 0, n)",
                f"{indent}out.{rf.attr_name} = {dec_fn}(_sub_mv, out.{rf.attr_name}, depth + 1, _already)",
            ]
        )
        return out

    if rf.proto_type == FieldDescriptorProto.TYPE_BOOL:
        out.extend(
            [
                f"{indent}if wt != WIRE_BOOL_FALSE and wt != WIRE_BOOL_TRUE:",
                f"{indent}    pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
                f"{indent}    continue",
                f"{indent}seen_mask |= {bit}",
                f"{indent}out.{rf.attr_name} = (wt == WIRE_BOOL_TRUE)",
            ]
        )
        return out

    s_kind, s_wt, _, _ = _PROTO_SCALAR_INFO[rf.proto_type]
    out.extend(
        [
            f"{indent}if wt != {s_wt}:",
            f"{indent}    pos = validate_value(mv, pos, wt, depth, MAX_NESTING_DEPTH, n)",
            f"{indent}    continue",
            f"{indent}seen_mask |= {bit}",
        ]
    )
    out.extend(_emit_scalar_decode_lines(s_kind, "mv", "pos", "n", f"out.{rf.attr_name}", indent))
    return out


def _emit_opaque_methods(
    rf: _ResolvedField,
    ref_decode_fn: Any,
    ref_opaque_cls: Any,
) -> list[str]:
    lines: list[str] = []
    attr = rf.attr_name
    num = rf.number

    if rf.is_map:
        k_kind, k_wt, k_py, _ = _PROTO_SCALAR_INFO[rf.map_key_type]
        if rf.map_val_type == FieldDescriptorProto.TYPE_MESSAGE:
            v_kind, v_wt, v_py = "submsg", WIRE_SUB_MSG, rf.sub_msg_py
            sub_dec = ref_decode_fn(rf.sub_msg_full)
        else:
            v_kind, v_wt, v_py, _ = _PROTO_SCALAR_INFO[rf.map_val_type]
            sub_dec = "None"
        ret_tp = f"dict[{k_py}, {v_py}]"
        lines.extend(
            [
                f"    def get_{attr}(self) -> {ret_tp}:",
                f"        if {num} in self._dirty_nums:",
                f"            return self._d_{attr}  # type: ignore[no-any-return]",
                f"        return opaque_get_map(self._raw, {num}, {k_wt}, {k_kind!r}, {v_wt}, {v_kind!r}, {sub_dec})",
                "",
                f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                f"        self._d_{attr} = val",
                f"        self._dirty_nums.add({num})",
                "",
            ]
        )
        return lines

    if rf.repeated:
        if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
            ret_tp = f"list[{rf.sub_msg_py}]"
            dec_fn = ref_decode_fn(rf.sub_msg_full)
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        if {num} in self._dirty_nums:",
                    f"            return self._d_{attr}  # type: ignore[no-any-return]",
                    f"        return opaque_get_submsg_array(self._raw, {num}, {dec_fn})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._d_{attr} = val",
                    f"        self._dirty_nums.add({num})",
                    "",
                ]
            )
        else:
            e_kind, e_wt, e_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
            ret_tp = f"list[{e_py}]"
            lines.extend(
                [
                    f"    def get_{attr}(self) -> {ret_tp}:",
                    f"        if {num} in self._dirty_nums:",
                    f"            return self._d_{attr}  # type: ignore[no-any-return]",
                    f"        return opaque_get_scalar_array(self._raw, {num}, {e_wt}, {e_kind!r})",
                    "",
                    f"    def set_{attr}(self, val: {ret_tp}) -> None:",
                    f"        self._d_{attr} = val",
                    f"        self._dirty_nums.add({num})",
                    "",
                ]
            )
        return lines

    if rf.proto_type == FieldDescriptorProto.TYPE_MESSAGE:
        ret_tp = f"{rf.sub_msg_py} | None"
        dec_fn = ref_decode_fn(rf.sub_msg_full)
        op_cls = ref_opaque_cls(rf.sub_msg_full)
        lines.extend(
            [
                f"    def get_{attr}(self) -> {ret_tp}:",
                f"        if {num} in self._dirty_nums:",
                f"            return self._d_{attr}  # type: ignore[no-any-return]",
                f"        return opaque_get_submsg(self._raw, {num}, {dec_fn})",
                "",
                f"    def opaque_{attr}(self) -> {op_cls} | None:",
                f"        if {num} in self._dirty_nums:",
                f"            _cur = self._d_{attr}",
                "            if _cur is None:",
                "                return None",
                f"            return {op_cls}(_cur.marshal_omnibuf())",
                f"        _sub = opaque_get_submsg_slice(self._raw, {num})",
                "        if _sub is None:",
                "            return None",
                f"        return {op_cls}(_sub)",
                "",
                f"    def set_{attr}(self, val: Any) -> None:",
                f"        self._d_{attr} = val",
                f"        self._dirty_nums.add({num})",
                "",
            ]
        )
        return lines

    s_kind, _, s_py, _ = _PROTO_SCALAR_INFO[rf.proto_type]
    helper = f"opaque_get_{s_kind}"
    lines.extend(
        [
            f"    def get_{attr}(self) -> {s_py}:",
            f"        if {num} in self._dirty_nums:",
            f"            return self._d_{attr}  # type: ignore[no-any-return]",
            f"        return {helper}(self._raw, {num})",
            "",
            f"    def set_{attr}(self, val: {s_py}) -> None:",
            f"        self._d_{attr} = val",
            f"        self._dirty_nums.add({num})",
            "",
        ]
    )
    return lines


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
