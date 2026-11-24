"""Unit tests for OpaqueView accessors, standalone opaque helpers, and field splicing."""

from __future__ import annotations

from typing import Any

import pytest
from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2

import omnibuf
from omnibuf import (
    WIRE_SUB_MSG,
    WIRE_UINT,
    OmniBufDecodeError,
    OmniBufEncodeError,
    SpliceField,
    opaque_get_uint32,
    splice_fields,
)
from omnibuf import wire as omnibuf_wire
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb
from omnibuf.gen.omnibuf.conformance import conformance_omnibuf_pb
from omnibuf.opaque import splice_dirty_fields
from omnibuf.plugin import generate_code
from omnibuf.wire import MAX_FIELD_NUMBER, encode_tag, encode_varint


def test_opaque_clearing_inactive_oneof_branch_preserves_active_wire_branch() -> None:
    """Calling op.set_branch_a(None) when branch_b is active on the wire must not delete branch_b."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "oneof_bug.proto"
    fdp.package = "test.opaque"
    fdp.syntax = "proto3"

    msg = fdp.message_type.add()
    msg.name = "OneofEnvelope"
    oneof = msg.oneof_decl.add()
    oneof.name = "payload"

    fa = msg.field.add()
    fa.name = "branch_a"
    fa.number = 1
    fa.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fa.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    fa.oneof_index = 0

    fb = msg.field.add()
    fb.name = "branch_b"
    fb.number = 2
    fb.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fb.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    fb.oneof_index = 0

    req.file_to_generate.append("oneof_bug.proto")
    resp = generate_code(req)
    assert not resp.error
    ns: dict[str, Any] = {}
    exec(resp.file[0].content, ns)  # noqa: S102

    msg_cls = ns["OneofEnvelope"]
    opaque_cls = ns["OpaqueOneofEnvelope"]

    wire_bytes = omnibuf.marshal(msg_cls(branch_b="hello"))
    op = opaque_cls(wire_bytes)
    assert op.get_branch_b() == "hello"

    # Clearing the already-inactive sibling branch_a must NOT wipe active branch_b!
    op.set_branch_a(None)
    spliced = op.marshal()
    decoded = omnibuf.unmarshal(spliced, msg_cls)
    assert decoded.branch_b == "hello"


def test_standalone_opaque_getters_propagate_errors() -> None:
    """Standalone opaque_get_* helpers must raise OmniBufDecodeError on wire corruption / bad UTF-8."""
    # Legitimately absent returns default / None / empty view
    empty = b""
    assert opaque_get_uint32(empty, 1, 7) == 7
    assert omnibuf.opaque_get_string(empty, 1, "fallback") == "fallback"
    assert omnibuf.opaque_get_bytes(empty, 1, b"def") == b"def"
    assert bytes(omnibuf.opaque_get_bytes_view(empty, 1)) == b""
    assert omnibuf.opaque_get_submsg_slice(empty, 1) is None

    # Invalid Field #0 wire type (WIRE_UINT instead of WIRE_SUB_MSG)
    bad_f0 = encode_varint((0 << 4) | WIRE_UINT) + encode_varint(1)
    with pytest.raises(OmniBufDecodeError):
        opaque_get_uint32(bad_f0, 1, 7)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_string(bad_f0, 1, "fallback")
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_bytes(bad_f0, 1, b"def")
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_bytes_view(bad_f0, 1)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_submsg_slice(bad_f0, 1)

    # Truncated field payload
    truncated = encode_tag(1, WIRE_UINT) + b"\x00"  # 9-byte varint header with 0 trailing bytes
    with pytest.raises(OmniBufDecodeError):
        opaque_get_uint32(truncated, 1, 7)

    # Invalid UTF-8 in WireString field
    bad_utf8 = encode_tag(1, omnibuf_wire.WIRE_STRING) + encode_varint(2) + b"\xff\xfe"
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_string(bad_utf8, 1, "fallback")


def test_opaque_zero_dim_memoryview_safe() -> None:
    """0-D memoryview backed by bytes must not OOB-read strides in ByteSliceOwner."""
    # Single-byte packet: field #1 = true ((1 << 4) | WIRE_BOOL_TRUE = 0x13 -> varint 0x27)
    raw_bool = encode_tag(1, omnibuf_wire.WIRE_BOOL_TRUE)
    assert len(raw_bool) == 1
    mv0 = memoryview(raw_bool).cast("B", shape=())
    assert mv0.ndim == 0
    view = omnibuf.OpaqueView(mv0)
    assert view._get_bool(1) is True


def test_opaque_error_propagation_and_splice_validation() -> None:
    # Truncated submessage length on field 9 (Location)
    corrupt_pkt = encode_tag(9, WIRE_SUB_MSG) + encode_varint(50) + b"\x01\x02"
    op_bad = peer_omnibuf_pb.OpaquePeerUpdate(corrupt_pkt)
    with pytest.raises(OmniBufDecodeError):
        op_bad.validate()
    with pytest.raises(OmniBufDecodeError):
        op_bad.get_location()
    with pytest.raises(OmniBufDecodeError):
        op_bad.opaque_location()
    op_bad.set_sequence(5)
    with pytest.raises(OmniBufDecodeError):
        op_bad.marshal()

    # splice_dirty_fields validation on bool, negative bitmask, bit 0, and out-of-range
    valid_pkt = peer_omnibuf_pb.PeerUpdate(sequence=1).marshal_omnibuf()
    bad_inputs: list[Any] = [True, False, -1, -99, 1, {0}, {MAX_FIELD_NUMBER + 1}, {True}]
    for bad_dirty in bad_inputs:
        with pytest.raises(OmniBufEncodeError):
            splice_dirty_fields(None, valid_pkt, bad_dirty, lambda _b, _f: None)
    with pytest.raises(OmniBufEncodeError):
        splice_fields(b"", valid_pkt, [SpliceField(field_num=True, encoded_field=b"")])


def test_opaque_generalized_fast_scalar_setters() -> None:
    base = conformance_omnibuf_pb.TestAllTypes(f6_string="init").marshal_omnibuf()
    op = conformance_omnibuf_pb.OpaqueTestAllTypes(base)
    op.set_f1_uint32(101)
    b1 = op.marshal()
    op2 = conformance_omnibuf_pb.OpaqueTestAllTypes(b1)
    op2.set_f3_sint32(-42)
    b2 = op2.marshal()
    op3 = conformance_omnibuf_pb.OpaqueTestAllTypes(b2)
    op3.set_f4_sint64(-9_000_000_000)
    b3 = op3.marshal()
    op4 = conformance_omnibuf_pb.OpaqueTestAllTypes(b3)
    op4.set_f5_bool(True)
    b4 = op4.marshal()
    op5 = conformance_omnibuf_pb.OpaqueTestAllTypes(b4)
    op5.set_f6_string("updated-fast")
    b5 = op5.marshal()
    op6 = conformance_omnibuf_pb.OpaqueTestAllTypes(b5)
    op6.set_f13_float32(1.5)
    b6 = op6.marshal()
    op7 = conformance_omnibuf_pb.OpaqueTestAllTypes(b6)
    op7.set_f14_float64(-2.25)
    b7 = op7.marshal()
    op8 = conformance_omnibuf_pb.OpaqueTestAllTypes(b7)
    op8.set_f15_fixed32(0xDEAD_BEEF)
    b8 = op8.marshal()
    op9 = conformance_omnibuf_pb.OpaqueTestAllTypes(b8)
    op9.set_f16_fixed64(0xCAFE_BABE_1234_5678)
    final_bytes = op9.marshal()

    res = conformance_omnibuf_pb.unmarshal_test_all_types(final_bytes)
    assert res.f1_uint32 == 101
    assert res.f3_sint32 == -42
    assert res.f4_sint64 == -9_000_000_000
    assert res.f5_bool is True
    assert res.f6_string == "updated-fast"
    assert res.f13_float32 == 1.5
    assert res.f14_float64 == -2.25
    assert res.f15_fixed32 == 0xDEAD_BEEF
    assert res.f16_fixed64 == 0xCAFE_BABE_1234_5678
