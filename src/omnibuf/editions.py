"""Resolve and validate Protobuf Editions 2023, 2024, and 2026 features for OmniBuf."""

from __future__ import annotations

import math
from collections.abc import Collection, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from google.protobuf.descriptor_pb2 import (
        DescriptorProto,
        EnumDescriptorProto,
        FeatureSet,
        FileDescriptorProto,
    )

EDITION_2023 = 1000
EDITION_2024 = 1001
EDITION_2026 = 1002
SUPPORTED_EDITIONS: tuple[int, ...] = (EDITION_2023, EDITION_2024, EDITION_2026)

# FieldDescriptorProto.Type numeric constants (avoids eager google.protobuf import).
_TYPE_DOUBLE = 1
_TYPE_FLOAT = 2
_TYPE_INT64 = 3
_TYPE_UINT64 = 4
_TYPE_INT32 = 5
_TYPE_FIXED64 = 6
_TYPE_FIXED32 = 7
_TYPE_BOOL = 8
_TYPE_STRING = 9
_TYPE_GROUP = 10
_TYPE_MESSAGE = 11
_TYPE_BYTES = 12
_TYPE_UINT32 = 13
_TYPE_ENUM = 14
_TYPE_SFIXED32 = 15
_TYPE_SFIXED64 = 16
_TYPE_SINT32 = 17
_TYPE_SINT64 = 18

_INT_FIELD_TYPES: frozenset[int] = frozenset(
    {
        _TYPE_INT32,
        _TYPE_INT64,
        _TYPE_UINT32,
        _TYPE_UINT64,
        _TYPE_SINT32,
        _TYPE_SINT64,
        _TYPE_FIXED32,
        _TYPE_FIXED64,
        _TYPE_SFIXED32,
        _TYPE_SFIXED64,
    }
)

_FLOAT_FIELD_TYPES: frozenset[int] = frozenset({_TYPE_FLOAT, _TYPE_DOUBLE})

DESCRIPTOR_OPTION_EXTENDEES: frozenset[str] = frozenset(
    {
        "google.protobuf.FileOptions",
        "google.protobuf.MessageOptions",
        "google.protobuf.FieldOptions",
        "google.protobuf.OneofOptions",
        "google.protobuf.EnumOptions",
        "google.protobuf.EnumValueOptions",
        "google.protobuf.ExtensionRangeOptions",
        "google.protobuf.ServiceOptions",
        "google.protobuf.MethodOptions",
    }
)


def is_descriptor_options_extendee(extendee: str) -> bool:
    """Return True if extendee names a google.protobuf.*Options descriptor message."""
    return extendee.lstrip(".") in DESCRIPTOR_OPTION_EXTENDEES


def is_zero_typed_default(val: Any) -> bool:
    """Return True if a typed runtime default value is the canonical zero value."""
    if isinstance(val, bool):
        return val is False
    if isinstance(val, int):
        return val == 0
    if isinstance(val, float):
        return val == 0.0 and not (math.copysign(1.0, val) < 0.0)
    if isinstance(val, str):
        return val == ""
    if isinstance(val, (bytes, bytearray)):
        return len(val) == 0
    return False


def is_zero_default_str(
    field_type: int,
    raw: str,
    enum_values: dict[str, int] | None = None,
) -> bool:
    """Return True if a FileDescriptorProto default_value string represents a zero default."""
    if field_type in _INT_FIELD_TYPES:
        try:
            return int(raw, 0) == 0
        except ValueError:
            return False
    if field_type in _FLOAT_FIELD_TYPES:
        try:
            fv = float(raw)
        except ValueError:
            return False
        return fv == 0.0 and not (math.copysign(1.0, fv) < 0.0)
    if field_type == _TYPE_BOOL:
        return raw == "false"
    if field_type in (_TYPE_STRING, _TYPE_BYTES):
        return raw == ""
    if field_type == _TYPE_ENUM:
        if enum_values is not None and raw in enum_values:
            return enum_values[raw] == 0
        return raw == "0"
    return False


def _norm_type_name(name: str) -> str:
    if not name:
        return ""
    return name if name.startswith(".") else f".{name}"


def _is_editions_fdp(source: FileDescriptorProto) -> bool:
    return source.syntax == "editions" or int(source.edition) >= EDITION_2023


def _collect_enum_metadata(
    sources: Sequence[FileDescriptorProto],
) -> tuple[dict[str, bool], dict[str, dict[str, int]]]:
    """Collect open/closed status and value numbers for every enum across all files."""
    from google.protobuf.descriptor_pb2 import FeatureSet as _FeatureSet

    enum_closed: dict[str, bool] = {}
    enum_values: dict[str, dict[str, int]] = {}

    def record_enum(
        edp: EnumDescriptorProto,
        scope_prefix: str,
        *,
        is_proto2: bool,
        is_editions: bool,
        parent_features: FeatureSet | None,
    ) -> None:
        full_name = f"{scope_prefix}.{edp.name}"
        if is_proto2:
            closed = True
        elif is_editions:
            assert parent_features is not None
            ef = _FeatureSet()
            ef.CopyFrom(parent_features)
            ef.MergeFrom(edp.options.features)
            closed = ef.enum_type != _FeatureSet.OPEN
        else:
            closed = False
        enum_closed[full_name] = closed
        enum_values[full_name] = {ev.name: int(ev.number) for ev in edp.value}

    def walk_msg(
        mdp: DescriptorProto,
        scope_prefix: str,
        *,
        is_proto2: bool,
        is_editions: bool,
        parent_features: FeatureSet | None,
    ) -> None:
        msg_prefix = f"{scope_prefix}.{mdp.name}"
        cur_features: FeatureSet | None = None
        if is_editions:
            assert parent_features is not None
            cur_features = _FeatureSet()
            cur_features.CopyFrom(parent_features)
            cur_features.MergeFrom(mdp.options.features)
        for edp in mdp.enum_type:
            record_enum(
                edp,
                msg_prefix,
                is_proto2=is_proto2,
                is_editions=is_editions,
                parent_features=cur_features,
            )
        for nested in mdp.nested_type:
            walk_msg(
                nested,
                msg_prefix,
                is_proto2=is_proto2,
                is_editions=is_editions,
                parent_features=cur_features,
            )

    for src in sources:
        pkg = src.package
        prefix = f".{pkg}" if pkg else ""
        is_ed = _is_editions_fdp(src)
        is_p2 = (not is_ed) and src.syntax in ("", "proto2")
        base_features: FeatureSet | None = None
        if is_ed:
            base_features = _FeatureSet(
                field_presence=_FeatureSet.EXPLICIT,
                enum_type=_FeatureSet.OPEN,
                repeated_field_encoding=_FeatureSet.PACKED,
                utf8_validation=_FeatureSet.VERIFY,
                message_encoding=_FeatureSet.LENGTH_PREFIXED,
                json_format=_FeatureSet.ALLOW,
            )
            base_features.MergeFrom(src.options.features)
        for edp in src.enum_type:
            record_enum(
                edp,
                prefix,
                is_proto2=is_p2,
                is_editions=is_ed,
                parent_features=base_features,
            )
        for mdp in src.message_type:
            walk_msg(
                mdp,
                prefix,
                is_proto2=is_p2,
                is_editions=is_ed,
                parent_features=base_features,
            )

    return enum_closed, enum_values


def _resolve_single_edition_file(
    source: FileDescriptorProto,
    enum_closed: dict[str, bool],
    enum_values: dict[str, dict[str, int]],
    *,
    strict: bool,
) -> FileDescriptorProto:
    from google.protobuf.descriptor_pb2 import (
        FeatureSet as _FeatureSet,
    )
    from google.protobuf.descriptor_pb2 import (
        FieldDescriptorProto as _FieldDescriptorProto,
    )
    from google.protobuf.descriptor_pb2 import (
        FileDescriptorProto as _FileDescriptorProto,
    )

    if not _is_editions_fdp(source):
        return source
    if int(source.edition) not in SUPPORTED_EDITIONS:
        raise ValueError(f"omnibuf: unsupported protobuf edition {source.edition} ({source.name})")

    file = _FileDescriptorProto()
    file.CopyFrom(source)
    base = _FeatureSet(
        field_presence=_FeatureSet.EXPLICIT,
        enum_type=_FeatureSet.OPEN,
        repeated_field_encoding=_FeatureSet.PACKED,
        utf8_validation=_FeatureSet.VERIFY,
        message_encoding=_FeatureSet.LENGTH_PREFIXED,
        json_format=_FeatureSet.ALLOW,
    )
    base.MergeFrom(file.options.features)

    if strict:
        for ext in file.extension:
            if not is_descriptor_options_extendee(ext.extendee):
                raise ValueError(
                    f"omnibuf: editions file extensions are not supported in {file.name} ({ext.name})"
                )

    def check_enums(enums: Sequence[EnumDescriptorProto], parent: FeatureSet) -> None:
        if not strict:
            return
        for enum in enums:
            features = _FeatureSet()
            features.CopyFrom(parent)
            features.MergeFrom(enum.options.features)
            if features.enum_type != _FeatureSet.OPEN:
                raise ValueError(f"omnibuf: editions CLOSED enums are not supported ({enum.name})")

    def visit(
        msg: DescriptorProto,
        parent: FeatureSet,
        scope_prefix: str,
        map_field_features: FeatureSet | None = None,
    ) -> None:
        features = _FeatureSet()
        features.CopyFrom(parent)
        if map_field_features is not None:
            features.MergeFrom(map_field_features)
        features.MergeFrom(msg.options.features)
        msg_full = f"{scope_prefix}.{msg.name}"

        if strict:
            if msg.extension_range:
                raise ValueError(f"omnibuf: editions extensions are not supported on {msg.name}")
            for ext in msg.extension:
                if not is_descriptor_options_extendee(ext.extendee):
                    raise ValueError(
                        f"omnibuf: editions extensions are not supported on {msg.name} ({ext.name})"
                    )

        check_enums(msg.enum_type, features)

        nested_map_entries: set[str] = {
            f"{msg_full}.{nested.name}" for nested in msg.nested_type if nested.options.map_entry
        }
        map_entry_overrides: dict[str, FeatureSet] = {}

        for field in msg.field:
            resolved = _FeatureSet()
            resolved.CopyFrom(features)
            if field.HasField("oneof_index"):
                resolved.MergeFrom(msg.oneof_decl[field.oneof_index].options.features)
            resolved.MergeFrom(field.options.features)

            if strict:
                if (
                    field.label == _FieldDescriptorProto.LABEL_REQUIRED
                    or resolved.field_presence not in (_FeatureSet.EXPLICIT, _FeatureSet.IMPLICIT)
                ):
                    raise ValueError(
                        f"omnibuf: editions LEGACY_REQUIRED is not supported ({msg.name}.{field.name})"
                    )
                if (
                    field.type == _FieldDescriptorProto.TYPE_STRING
                    and resolved.utf8_validation != _FeatureSet.VERIFY
                ):
                    raise ValueError(
                        f"omnibuf: editions UTF-8 NONE is not supported ({msg.name}.{field.name})"
                    )
                if field.type == _FieldDescriptorProto.TYPE_ENUM:
                    norm_enum = _norm_type_name(field.type_name)
                    if enum_closed.get(norm_enum, False):
                        raise ValueError(
                            f"omnibuf: editions CLOSED enums are not supported "
                            f"({msg.name}.{field.name} -> {field.type_name})"
                        )
                if field.HasField("default_value"):
                    ev_map = (
                        enum_values.get(_norm_type_name(field.type_name))
                        if field.type == _FieldDescriptorProto.TYPE_ENUM
                        else None
                    )
                    if not is_zero_default_str(int(field.type), field.default_value, ev_map):
                        raise ValueError(
                            f"omnibuf: editions custom non-zero default value is not supported "
                            f"({msg.name}.{field.name} = {field.default_value!r})"
                        )

            if field.type == _FieldDescriptorProto.TYPE_MESSAGE:
                norm_msg = _norm_type_name(field.type_name)
                if norm_msg in nested_map_entries:
                    map_entry_overrides[norm_msg] = field.options.features

            if field.type == _FieldDescriptorProto.TYPE_GROUP:
                field.type = _FieldDescriptorProto.TYPE_MESSAGE

            if (
                not field.HasField("oneof_index")
                and field.label != _FieldDescriptorProto.LABEL_REPEATED
                and not msg.options.map_entry
            ):
                field.proto3_optional = resolved.field_presence == _FeatureSet.EXPLICIT

        for nested in msg.nested_type:
            nested_full = f"{msg_full}.{nested.name}"
            visit(nested, features, msg_full, map_entry_overrides.get(nested_full))

    pkg = file.package
    root_prefix = f".{pkg}" if pkg else ""
    check_enums(file.enum_type, base)
    for msg in file.message_type:
        visit(msg, base, root_prefix)
    file.syntax = "proto3"
    return file


def resolve_edition_files(
    sources: Sequence[FileDescriptorProto],
    target_files: Collection[str] | None = None,
) -> list[FileDescriptorProto]:
    """Validate and resolve Editions 2023/2024/2026 descriptors with cross-file enum resolution."""
    enum_closed, enum_values = _collect_enum_metadata(sources)
    target_set = set(target_files) if target_files is not None else None
    out: list[FileDescriptorProto] = []
    for src in sources:
        strict = target_set is None or src.name in target_set
        out.append(_resolve_single_edition_file(src, enum_closed, enum_values, strict=strict))
    return out


def resolve_edition_file(source: FileDescriptorProto) -> FileDescriptorProto:
    """Return an internal codec descriptor with resolved Editions features for a single file."""
    return resolve_edition_files([source])[0]


__all__ = [
    "DESCRIPTOR_OPTION_EXTENDEES",
    "EDITION_2023",
    "EDITION_2024",
    "EDITION_2026",
    "SUPPORTED_EDITIONS",
    "is_descriptor_options_extendee",
    "is_zero_default_str",
    "is_zero_typed_default",
    "resolve_edition_file",
    "resolve_edition_files",
]
