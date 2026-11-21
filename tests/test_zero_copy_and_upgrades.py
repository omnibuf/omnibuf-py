"""Tests for zero-copy memoryview reads, >16 KiB backpatch heuristic, and OpaqueView upgrades."""

from __future__ import annotations

import pytest

import omnibuf
from omnibuf import (
    WIRE_STRING,
    Encoder,
    OmniBufDecodeError,
    Uint32,
    encode_tag,
    encode_varint,
    omnibuf_field,
    omnibuf_message,
    opaque_get_bytes_view,
)
from omnibuf.conformance import AnnotatedTestAllTypes
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb
from omnibuf.gen.omnibuf.conformance import conformance_omnibuf_pb


@omnibuf_message("BytesLeaf")
class _BytesLeaf:
    payload: bytes = omnibuf_field(1, default=b"")


@omnibuf_message("BytesEnvelope")
class _BytesEnvelope:
    raw: bytes = omnibuf_field(1, default=b"")
    leaf: _BytesLeaf | None = omnibuf_field(2, default=None)
    chunks: list[bytes] = omnibuf_field(3, default_factory=list)
    named: dict[str, bytes] = omnibuf_field(4, default_factory=dict)


def test_opaque_get_bytes_view_zero_copy_readonly() -> None:
    payload = b"omnibuf-zero-copy-payload-" * 8
    msg = conformance_omnibuf_pb.TestAllTypes(f1_uint32=42, f7_bytes=payload)
    wire = msg.marshal_omnibuf()

    op = conformance_omnibuf_pb.OpaqueTestAllTypes(wire)
    mv = op.get_f7_bytes_view()
    assert isinstance(mv, memoryview)
    assert mv.readonly
    assert bytes(mv) == payload
    assert op.get_f7_bytes() == payload

    # Also verify standalone helper
    mv_direct = opaque_get_bytes_view(wire, 7)
    assert isinstance(mv_direct, memoryview)
    assert mv_direct.readonly
    assert bytes(mv_direct) == payload

    # Verify memoryview input to OpaqueView stays zero-copy
    op_mv = conformance_omnibuf_pb.OpaqueTestAllTypes(memoryview(wire))
    mv2 = op_mv.get_f7_bytes_view()
    assert isinstance(mv2, memoryview)
    assert mv2.readonly
    assert bytes(mv2) == payload

    # Dirty bytes field still returns a read-only memoryview of updated bytes
    op.set_f7_bytes(b"updated-bytes")
    mv_dirty = op.get_f7_bytes_view()
    assert isinstance(mv_dirty, memoryview)
    assert mv_dirty.readonly
    assert bytes(mv_dirty) == b"updated-bytes"


def test_unmarshal_zero_copy_bytes_option() -> None:
    env = _BytesEnvelope(
        raw=b"top-level-bytes",
        leaf=_BytesLeaf(payload=b"nested-leaf-bytes"),
        chunks=[b"chunk-0", b"chunk-1"],
        named={"a": b"val-a", "b": b"val-b"},
    )
    wire = omnibuf.marshal(env, deterministic=True)

    # Default unmarshal returns bytes
    eager = omnibuf.unmarshal(wire, _BytesEnvelope)
    assert type(eager.raw) is bytes
    assert eager.raw == b"top-level-bytes"

    # zero_copy_bytes=True returns read-only memoryview slices across all nested bytes fields
    zc = omnibuf.unmarshal(wire, _BytesEnvelope, zero_copy_bytes=True)
    assert isinstance(zc.raw, memoryview)
    assert zc.raw.readonly
    assert bytes(zc.raw) == b"top-level-bytes"

    assert zc.leaf is not None
    assert isinstance(zc.leaf.payload, memoryview)
    assert zc.leaf.payload.readonly
    assert bytes(zc.leaf.payload) == b"nested-leaf-bytes"

    assert len(zc.chunks) == 2
    assert all(isinstance(c, memoryview) and c.readonly for c in zc.chunks)
    assert [bytes(c) for c in zc.chunks] == [b"chunk-0", b"chunk-1"]

    assert all(isinstance(v, memoryview) and v.readonly for v in zc.named.values())
    assert {k: bytes(v) for k, v in zc.named.items()} == {"a": b"val-a", "b": b"val-b"}

    # Generated Tier 1 codec also supports zero_copy_bytes=True
    all_wire = conformance_omnibuf_pb.TestAllTypes(f7_bytes=b"tier1-zc").marshal_omnibuf()
    all_zc = omnibuf.unmarshal(all_wire, conformance_omnibuf_pb.TestAllTypes, zero_copy_bytes=True)
    assert isinstance(all_zc.f7_bytes, memoryview)
    assert all_zc.f7_bytes.readonly
    assert bytes(all_zc.f7_bytes) == b"tier1-zc"

    # Tier 3 AnnotatedTestAllTypes also supports zero_copy_bytes=True
    ann_zc = omnibuf.unmarshal(all_wire, AnnotatedTestAllTypes, zero_copy_bytes=True)
    assert isinstance(ann_zc.f7_bytes, memoryview)
    assert bytes(ann_zc.f7_bytes) == b"tier1-zc"


def test_large_container_over_16kib_backpatch_canonical_wire() -> None:
    """Arrays and maps > 16 KiB must use canonical 4-byte Prefix-Varint length and roundtrip."""
    big_ints = list(range(20_000))
    big_map = {f"k{i:05d}": i for i in range(4_000)}
    msg = conformance_omnibuf_pb.TestAllTypes(
        f10_uint32_arr=big_ints,
        f12_map_str_uint=big_map,
    )
    wire = msg.marshal_omnibuf(deterministic=True)
    assert len(wire) > 32_768
    omnibuf.validate_message(wire)

    decoded = conformance_omnibuf_pb.TestAllTypes.unmarshal_omnibuf(wire)
    assert decoded.f10_uint32_arr == big_ints
    assert decoded.f12_map_str_uint == big_map

    # Verify bit-for-bit wire equivalence with Encoder
    enc = Encoder()
    enc.begin_array(10, omnibuf.WIRE_UINT, len(big_ints))
    for v in big_ints:
        enc.write_elem_uint(v)
    enc.end_array()
    enc_arr = enc.finish()

    @omnibuf_message("BigArrHolder")
    class BigArrHolder:
        vals: list[Uint32] = omnibuf_field(10, default_factory=list)

    dc_arr = omnibuf.marshal(BigArrHolder(vals=big_ints))
    assert dc_arr == enc_arr


def test_opaque_marshal_vs_marshal_validated_and_subview() -> None:
    """OpaqueView marshal_validated/try_marshal validates unknown WireString UTF-8."""
    peer = peer_omnibuf_pb.PeerUpdate(
        asn=64512,
        router_id="rtr-1",
        location=peer_omnibuf_pb.Location(region="eu", city="Zurich", rack=7),
        sequence=10,
    )
    valid_wire = peer.marshal_omnibuf()

    # Subview reads without copying unmodified packet bytes
    op = peer_omnibuf_pb.OpaquePeerUpdate(valid_wire)
    sub = op.opaque_location()
    assert sub is not None
    assert sub.get_city() == "Zurich"
    assert sub.get_rack() == 7

    # Append unknown field #99 with invalid UTF-8 bytes
    bad_utf8_wire = valid_wire + encode_tag(99, WIRE_STRING) + encode_varint(2) + b"\xff\xfe"
    op_bad = peer_omnibuf_pb.OpaquePeerUpdate(bad_utf8_wire)
    op_bad.set_sequence(11)

    with pytest.raises(OmniBufDecodeError):
        op_bad.marshal_validated()
    with pytest.raises(OmniBufDecodeError):
        op_bad.try_marshal()
