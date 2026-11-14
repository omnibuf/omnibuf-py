"""OmniBuf: Explicit-typed, header-hop binary wire codec for Python."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, overload

import protobuf as pbpy

if TYPE_CHECKING:
    from google.protobuf.message import Message as GpbMessage

from ._omnibuf_ext import CompiledCodec, OpaqueView
from .blind import decode_blind, decode_blind_json
from .dataclass_codec import (
    FieldInfo,
    Fixed32,
    Fixed64,
    Float32,
    Float64,
    Sfixed32,
    Sfixed64,
    Sint32,
    Sint64,
    Uint32,
    Uint64,
    WireName,
    omnibuf_field,
    omnibuf_message,
    schema_meta_for,
)
from .dataclass_codec import marshal as marshal_dataclass
from .dataclass_codec import unmarshal as unmarshal_dataclass
from .decoder import Decoder
from .encoder import Encoder
from .field0 import (
    SchemaMeta,
    decode_schema_meta,
    encode_field0_schema_meta,
    merge_schema_meta,
    read_field0_schema_meta,
    write_field0_schema_meta,
)
from .opaque import (
    opaque_get_bool,
    opaque_get_bytes,
    opaque_get_fixed32,
    opaque_get_fixed64,
    opaque_get_float32,
    opaque_get_float64,
    opaque_get_map,
    opaque_get_scalar_array,
    opaque_get_sfixed32,
    opaque_get_sfixed64,
    opaque_get_sint32,
    opaque_get_sint64,
    opaque_get_string,
    opaque_get_submsg,
    opaque_get_submsg_array,
    opaque_get_submsg_slice,
    opaque_get_uint32,
    opaque_get_uint64,
    splice_dirty_fields,
)
from .protobuf_codec import is_proto_message_or_type, marshal_proto, unmarshal_proto
from .wire import (
    FIELD0_TAG,
    MAX_CONTAINER_DEPTH,
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
    OmniBufEncodeError,
    OmniBufError,
    SpliceField,
    append_tag,
    append_varint,
    decode_tag,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    encode_tag,
    encode_varint,
    encode_zigzag,
    encode_zigzag32,
    fast_skip_value,
    locate_field,
    next_container_field,
    round_float32_shortest,
    splice_fields,
    validate_message,
    varint_size,
    wire_type_name,
)

__version__ = "0.1.0"


def marshal(
    msg: Any,
    *,
    deterministic: bool = False,
    self_describing: bool = False,
) -> bytes:
    """Serializes a protobuf-py message, @omnibuf_message dataclass, or generated message."""
    gen_codec: CompiledCodec[Any] | None = getattr(type(msg), "__omnibuf_codec__", None)
    if gen_codec is not None:
        return gen_codec.marshal(
            msg,
            deterministic=deterministic,
            self_describing=self_describing,
        )
    if is_proto_message_or_type(msg):
        return marshal_proto(
            msg,
            deterministic=deterministic,
            self_describing=self_describing,
        )
    marshal_fn = getattr(msg, "marshal_omnibuf", None)
    if callable(marshal_fn):
        res: bytes = marshal_fn(
            deterministic=deterministic,
            self_describing=self_describing,
        )
        return res
    return marshal_dataclass(
        msg,
        deterministic=deterministic,
        self_describing=self_describing,
    )


@overload
def unmarshal[M: pbpy.Message[Any]](packet: Buffer, target: type[M]) -> M: ...


@overload
def unmarshal[M: pbpy.Message[Any]](packet: Buffer, target: M) -> M: ...


@overload
def unmarshal(packet: Buffer, target: pbpy.DescMessage) -> pbpy.Message[Any]: ...


@overload
def unmarshal[G: GpbMessage](packet: Buffer, target: type[G]) -> G: ...


@overload
def unmarshal[G: GpbMessage](packet: Buffer, target: G) -> G: ...


@overload
def unmarshal[T](packet: Buffer, target: type[T]) -> T: ...


@overload
def unmarshal[T](packet: Buffer, target: T) -> T: ...


def unmarshal(packet: Buffer, target: Any) -> Any:
    """Decodes OmniBuf wire bytes into a protobuf-py message, dataclass, or generated message."""
    if isinstance(target, type):
        gen_codec: CompiledCodec[Any] | None = getattr(target, "__omnibuf_codec__", None)
        if gen_codec is not None:
            return gen_codec.unmarshal(packet)
        if is_proto_message_or_type(target):
            return unmarshal_proto(packet, target)
        unmarshal_cls_fn = getattr(target, "unmarshal_omnibuf", None)
        if callable(unmarshal_cls_fn):
            return unmarshal_cls_fn(packet)
        return unmarshal_dataclass(packet, target)
    gen_inst_codec: CompiledCodec[Any] | None = getattr(type(target), "__omnibuf_codec__", None)
    if gen_inst_codec is not None:
        return gen_inst_codec.unmarshal(packet, target)
    if is_proto_message_or_type(target):
        return unmarshal_proto(packet, target)
    unmarshal_inst_fn = getattr(type(target), "unmarshal_omnibuf", None)
    if callable(unmarshal_inst_fn):
        return unmarshal_inst_fn(packet, target)
    return unmarshal_dataclass(packet, target)


__all__ = [
    "FIELD0_TAG",
    "MAX_CONTAINER_DEPTH",
    "MAX_FIELD_NUMBER",
    "MAX_NESTING_DEPTH",
    "WIRE_ARRAY",
    "WIRE_BOOL_FALSE",
    "WIRE_BOOL_TRUE",
    "WIRE_BYTES",
    "WIRE_EXTENDED",
    "WIRE_FIXED32",
    "WIRE_FIXED64",
    "WIRE_FLOAT32",
    "WIRE_FLOAT64",
    "WIRE_MAP",
    "WIRE_SFIXED32",
    "WIRE_SFIXED64",
    "WIRE_SINT",
    "WIRE_STRING",
    "WIRE_SUB_MSG",
    "WIRE_UINT",
    "Buffer",
    "CompiledCodec",
    "Decoder",
    "Encoder",
    "FieldInfo",
    "Fixed32",
    "Fixed64",
    "Float32",
    "Float64",
    "OmniBufDecodeError",
    "OmniBufEncodeError",
    "OmniBufError",
    "OpaqueView",
    "SchemaMeta",
    "Sfixed32",
    "Sfixed64",
    "Sint32",
    "Sint64",
    "SpliceField",
    "Uint32",
    "Uint64",
    "WireName",
    "__version__",
    "append_tag",
    "append_varint",
    "decode_blind",
    "decode_blind_json",
    "decode_schema_meta",
    "decode_tag",
    "decode_varint",
    "decode_zigzag",
    "decode_zigzag32",
    "encode_field0_schema_meta",
    "encode_tag",
    "encode_varint",
    "encode_zigzag",
    "encode_zigzag32",
    "fast_skip_value",
    "is_proto_message_or_type",
    "locate_field",
    "marshal",
    "marshal_dataclass",
    "marshal_proto",
    "merge_schema_meta",
    "next_container_field",
    "omnibuf_field",
    "omnibuf_message",
    "opaque_get_bool",
    "opaque_get_bytes",
    "opaque_get_fixed32",
    "opaque_get_fixed64",
    "opaque_get_float32",
    "opaque_get_float64",
    "opaque_get_map",
    "opaque_get_scalar_array",
    "opaque_get_sfixed32",
    "opaque_get_sfixed64",
    "opaque_get_sint32",
    "opaque_get_sint64",
    "opaque_get_string",
    "opaque_get_submsg",
    "opaque_get_submsg_array",
    "opaque_get_submsg_slice",
    "opaque_get_uint32",
    "opaque_get_uint64",
    "read_field0_schema_meta",
    "round_float32_shortest",
    "schema_meta_for",
    "splice_dirty_fields",
    "splice_fields",
    "unmarshal",
    "unmarshal_dataclass",
    "unmarshal_proto",
    "validate_message",
    "varint_size",
    "wire_type_name",
    "write_field0_schema_meta",
]
