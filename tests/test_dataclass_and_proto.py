"""Cross-tier tests for protobuf-py, @omnibuf_message dataclasses, google.protobuf, and Opaque views."""

from __future__ import annotations

import enum
import math
import signal
import subprocess
import sys
import textwrap
import threading
import types
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from google.protobuf import descriptor_pb2

import omnibuf
from omnibuf import (
    WIRE_ARRAY,
    WIRE_SINT,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Encoder,
    Float32,
    Float64,
    OmniBufDecodeError,
    OmniBufEncodeError,
    OmniBufError,
    Sint32,
    Sint64,
    Uint32,
    Uint64,
    decode_blind,
    marshal,
    omnibuf_field,
    omnibuf_message,
    unmarshal,
    validate_message,
)
from omnibuf import wire as omnibuf_wire
from omnibuf.conformance import (
    AnnotatedLocation,
    AnnotatedPeerUpdate,
    NestedCluster,
    NestedNIC,
    NestedRack,
    NestedServer,
    TreeNode,
)
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb, peer_pb, peer_pb2
from omnibuf.gen.omnibuf.conformance import conformance_omnibuf_pb, conformance_pb, conformance_pb2
from omnibuf.wire import encode_tag, encode_varint, encode_zigzag32

_PEER_PB2: object = peer_pb2
_CONF_PB2: object = conformance_pb2


def test_protobuf_py_primary_codec_and_cross_tier_equivalence() -> None:
    pb_msg = peer_pb.PeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=["tier1", "ebgp", "eu-central", "ixp-de-cix"],
        prefixes=[167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040],
        location=peer_pb.Location(
            region="eu-central-1",
            datacenter="FRA-Equinix-FR5",
            city="Frankfurt",
            rack=42,
            latitude=50.1109,
            longitude=8.6821,
        ),
        neighbors=[
            peer_pb.Neighbor(
                peer_asn=3356,
                router="ae0.fra1.level3.net",
                latency_us=850,
                established=True,
            ),
            peer_pb.Neighbor(
                peer_asn=1299,
                router="ffm-b5-link.telia.net",
                latency_us=920,
                established=True,
            ),
            peer_pb.Neighbor(
                peer_asn=174,
                router="be2040.ccr41.fra03.atlas.cogentco.com",
                latency_us=1120,
                established=True,
            ),
            peer_pb.Neighbor(
                peer_asn=2914,
                router="ae-12.r24.frnkge08.de.bb.gin.ntt.net",
                latency_us=980,
                established=False,
            ),
        ],
        sequence=9876543210,
    )

    wire_bytes = marshal(pb_msg, deterministic=True)
    assert len(wire_bytes) == 366

    # 1. Decode via protobuf-py class and DescMessage
    dec_pb = unmarshal(wire_bytes, peer_pb.PeerUpdate)
    assert dec_pb.router_id == pb_msg.router_id
    assert dec_pb.location is not None
    assert dec_pb.location.city == "Frankfurt"
    assert len(dec_pb.neighbors) == 4
    assert dec_pb.sequence == 9876543210

    dec_by_desc = unmarshal(wire_bytes, peer_pb.PeerUpdate.desc())
    assert isinstance(dec_by_desc, peer_pb.PeerUpdate)
    assert dec_by_desc.asn == 64512

    # 2. Decode exact same bytes via @omnibuf_message dataclass
    dec_dc = unmarshal(wire_bytes, AnnotatedPeerUpdate)
    assert dec_dc.asn == 64512
    assert dec_dc.location.city == "Frankfurt"
    assert marshal(dec_dc, deterministic=True) == wire_bytes

    # 3. Decode exact same bytes via protoc-gen-omnibuf-py and OpaquePeerUpdate
    dec_gen = peer_omnibuf_pb.unmarshal_peer_update(wire_bytes)
    assert dec_gen.router_id == pb_msg.router_id
    assert dec_gen.marshal_omnibuf(deterministic=True) == wire_bytes

    op = peer_omnibuf_pb.OpaquePeerUpdate(wire_bytes)
    op_loc = op.opaque_location()
    assert op_loc is not None
    assert op_loc.get_city() == "Frankfurt"
    assert op.get_sequence() == 9876543210
    op.set_sequence(9876543211)
    mutated_bytes = op.marshal()
    assert unmarshal(mutated_bytes, peer_pb.PeerUpdate).sequence == 9876543211

    # 4. Decode exact same bytes via google.protobuf compatibility codec
    gpb_peer_cls = getattr(_PEER_PB2, "PeerUpdate")  # noqa: B009
    dec_gpb = unmarshal(wire_bytes, gpb_peer_cls)
    assert dec_gpb.router_id == pb_msg.router_id
    assert dec_gpb.location.city == "Frankfurt"
    assert marshal(dec_gpb, deterministic=True) == wire_bytes


def test_self_describing_roundtrip_across_all_tiers() -> None:
    pb_all = conformance_pb.TestAllTypes(
        f1_uint32=42,
        f3_sint32=-99,
        f5_bool=True,
        f6_string="omnibuf-py",
        f8_sub_msg=conformance_pb.AllTypesSubMsg(id=7, label="nested", flag=True, score=-1234),
        f12_map_str_uint={"alpha": 1, "beta": 2},
    )
    sd_bytes = marshal(pb_all, deterministic=True, self_describing=True)
    blind = decode_blind(sd_bytes)
    assert blind["f1_uint32"] == 42
    assert blind["f3_sint32"] == -99
    assert blind["f6_string"] == "omnibuf-py"
    assert blind["f8_sub_msg"]["label"] == "nested"
    assert blind["f12_map_str_uint"] == {"alpha": 1, "beta": 2}

    # Verify google.protobuf self_describing also decodes identically
    gpb_all_cls = getattr(_CONF_PB2, "TestAllTypes")  # noqa: B009
    gpb_all = unmarshal(sd_bytes, gpb_all_cls)
    gpb_sd = marshal(gpb_all, deterministic=True, self_describing=True)
    assert decode_blind(gpb_sd)["f8_sub_msg"]["score"] == -1234

    # Verify OpaqueTestAllTypes self_describing preservation
    op_all = conformance_omnibuf_pb.OpaqueTestAllTypes(marshal(pb_all, deterministic=True))
    op_sd = op_all.marshal(self_describing=True)
    assert decode_blind(op_sd)["f6_string"] == "omnibuf-py"


def test_recursive_treenode_and_nested_cluster_dataclasses() -> None:
    root = TreeNode(
        id=1,
        name="root",
        weight=-50,
        primary=TreeNode(id=2, name="primary-child", weight=10),
        children=[TreeNode(id=3, name="c1"), TreeNode(id=4, name="c2")],
        branches=[TreeNode(), TreeNode(id=5, name="b1")],
        labels={"depth": 2, "nodes": 5},
    )
    raw = marshal(root, deterministic=True, self_describing=True)
    decoded = unmarshal(raw, TreeNode)
    assert decoded.id == 1
    assert decoded.primary == TreeNode(id=2, name="primary-child", weight=10)
    assert decoded.children == [TreeNode(id=3, name="c1"), TreeNode(id=4, name="c2")]
    assert decoded.branches == [TreeNode(), TreeNode(id=5, name="b1")]
    assert decoded.labels == {"depth": 2, "nodes": 5}
    blind = decode_blind(raw)
    assert blind["name"] == "root"
    assert blind["primary"]["name"] == "primary-child"
    assert blind["branches"][0]["name"] == ""
    assert blind["branches"][1]["name"] == "b1"

    cluster = NestedCluster(
        cluster_name="eu-fra",
        racks=[
            NestedRack(
                rack_id=10,
                zone="az1",
                servers=[
                    NestedServer(
                        server_id=100,
                        hostname="srv01",
                        nics=[NestedNIC(if_index=1, mac="00:11:22:33:44:55", ips=[0x0A000001])],
                    )
                ],
            )
        ],
        epoch=123456789,
    )
    c_raw = marshal(cluster, deterministic=True)
    assert unmarshal(c_raw, NestedCluster) == cluster


def test_dataclass_optional_scalars_and_omitempty() -> None:
    @omnibuf_message
    class SparseConfig:
        port: Uint32 = omnibuf_field(1, default=0, omitempty=True)
        timeout_ms: Uint64 | None = omnibuf_field(2, default=None)
        offset: Sint32 = omnibuf_field(3, default=0, omitempty=True)
        delta: Sint64 = omnibuf_field(4, default=0, omitempty=True)
        ratio: Float32 = omnibuf_field(5, default=0.0, omitempty=True)
        weight: Float64 = omnibuf_field(6, default=0.0, omitempty=True)

    empty_cfg = SparseConfig()
    assert marshal(empty_cfg) == b""

    populated = SparseConfig(port=8080, timeout_ms=0, offset=-5, delta=-99, ratio=0.5, weight=1.25)
    raw = marshal(populated)
    restored = unmarshal(raw, SparseConfig)
    assert restored.port == 8080
    assert restored.timeout_ms == 0
    assert restored.offset == -5
    assert restored.delta == -99
    assert omnibuf.schema_meta_for(SparseConfig).type_name == "SparseConfig"


def test_cyclic_object_graph_raises_instead_of_sigsegv() -> None:
    """Marshaling a cyclic TreeNode graph must raise OmniBufEncodeError/RecursionError, not SIGSEGV."""
    code = textwrap.dedent(
        """
        import sys
        import omnibuf
        from omnibuf.conformance import TreeNode

        n = TreeNode(id=1, name="cycle")
        n.primary = n
        try:
            omnibuf.marshal(n)
        except (omnibuf.OmniBufError, RecursionError):
            sys.exit(0)
        sys.exit(2)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode != -signal.SIGSEGV, (
        f"Child process crashed with SIGSEGV (returncode={proc.returncode}): {proc.stderr}"
    )
    assert proc.returncode == 0, (
        f"Expected clean OmniBufError/RecursionError (exit 0), got returncode={proc.returncode}: "
        f"{proc.stderr}"
    )


def test_acyclic_depth_above_max_nesting_rejected_on_marshal() -> None:
    """Marshaling an acyclic message chain deeper than MAX_NESTING_DEPTH (32) must raise OmniBufError."""
    node = TreeNode(id=35, name="leaf")
    for depth_id in range(34, 0, -1):
        node = TreeNode(id=depth_id, name=f"d{depth_id}", primary=node)

    with pytest.raises(OmniBufError):
        marshal(node)


def test_submsg_array_unmarshal_enforces_max_elements_budget() -> None:
    """unmarshal must support and enforce a max_elements budget against 1-byte empty submsg amplification."""
    enc = Encoder()
    enc.begin_array(5, WIRE_SUB_MSG, 5_000)
    enc.write_raw(b"\x01" * 5_000)  # 5,000 empty 0-byte sub-messages in ~5 KB
    enc.end_array()
    pkt = enc.finish()

    assert len(pkt) < 5_100
    validate_message(pkt)

    with pytest.raises(OmniBufDecodeError):
        unmarshal(pkt, TreeNode, max_elements=100)


def test_non_cyclic_deep_schema_hierarchy_marshals() -> None:
    """18 distinct non-cyclic @omnibuf_message levels (< MAX_NESTING_DEPTH=32) must marshal cleanly."""
    classes: list[type[Any]] = []

    @omnibuf_message("DeepLevel18")
    class DeepLevel18:
        leaf_val: Uint32 = omnibuf_field(1, default=0)

    classes.append(DeepLevel18)
    child_cls: type[Any] = DeepLevel18

    for lvl in range(17, 0, -1):
        cls_name = f"DeepLevel{lvl}"
        raw_cls = type(
            cls_name,
            (),
            {
                "__annotations__": {"child": child_cls | None},
                "child": omnibuf_field(1, default=None),
            },
        )
        decorated: type[Any] = omnibuf_message(cls_name)(raw_cls)
        classes.append(decorated)
        child_cls = decorated

    inst: Any = DeepLevel18(leaf_val=777)
    for wrapper_cls in classes[1:]:
        inst = wrapper_cls(child=inst)

    raw = marshal(inst, self_describing=False)
    decoded = unmarshal(raw, classes[-1])
    cur = decoded
    for _ in range(17):
        assert cur.child is not None
        cur = cur.child
    assert cur.leaf_val == 777


def test_bool_rejected_for_int_fields() -> None:
    """Passing `True` to a uint32/int field or Opaque setter must raise TypeError/OmniBufEncodeError."""
    bad_dc = AnnotatedPeerUpdate(asn=True)
    with pytest.raises((TypeError, OmniBufEncodeError)):
        marshal(bad_dc)

    op = peer_omnibuf_pb.OpaquePeerUpdate(b"")
    with pytest.raises((TypeError, OmniBufEncodeError)):
        op.set_asn(True)


def test_dataclass_missing_omnibuf_field_rejected() -> None:
    """An @omnibuf_message field missing omnibuf_field(...) must raise instead of silent data loss."""
    with pytest.raises((TypeError, ValueError, OmniBufEncodeError)):

        @omnibuf_message
        class AccidentalUnnumberedField:
            id: Uint32 = omnibuf_field(1, default=0)
            forgotten_field: str = "important"

        marshal(AccidentalUnnumberedField(id=7, forgotten_field="lost"))


def test_dataclass_slots_false_submsg_without_default_unmarshals() -> None:
    """@omnibuf_message(slots=False) with a non-optional sub-message field must unmarshal cleanly."""

    @omnibuf_message(slots=False)
    class SlotsFalseEnvelope:
        loc: AnnotatedLocation = omnibuf_field(1)

    pkt = marshal(SlotsFalseEnvelope(loc=AnnotatedLocation(city="Zurich")))
    decoded = unmarshal(pkt, SlotsFalseEnvelope)
    assert decoded.loc.city == "Zurich"


class _OpenEnumStatus(enum.IntEnum):
    UNKNOWN = 0
    READY = 1


@omnibuf_message
class _OpenEnumHolder:
    status: _OpenEnumStatus = omnibuf_field(1, default=_OpenEnumStatus.UNKNOWN)


def test_dataclass_open_int_enum_unknown_wire_value() -> None:
    """Unknown wire enum integers (e.g. 99) must decode cleanly with open-enum semantics."""
    pkt = encode_tag(1, WIRE_SINT) + encode_varint(encode_zigzag32(99))
    decoded = unmarshal(pkt, _OpenEnumHolder)
    assert int(decoded.status) == 99


@omnibuf_message
class _FastSlotU32List:
    vals: list[Uint32] = omnibuf_field(1, default_factory=list)


def test_fast_slot_uint32_list_large_values() -> None:
    """Encoding list[Uint32] with values >= 2^29 (9-byte Prefix-Varints) must not overflow buffer."""
    big = [0x2000_0000, 0xFFFF_FFFF, 0x3FFF_FFFF, 0x8000_0000] * 64
    pkt = marshal(_FastSlotU32List(vals=big))
    validate_message(pkt)
    decoded = unmarshal(pkt, _FastSlotU32List)
    assert decoded.vals == big


@omnibuf_message
class _CyclicOmitEmpty:
    child: _CyclicOmitEmpty | None = omnibuf_field(1, default=None, omitempty=True)


def test_omitempty_cyclic_submsg_raises_encode_error() -> None:
    """Cyclic SubMsg with omitempty=True must raise OmniBufEncodeError instead of stack overflow."""
    node = _CyclicOmitEmpty()
    node.child = node
    with pytest.raises(OmniBufEncodeError):
        marshal(node)


@omnibuf_message
class _DepthLeafList:
    items: list[Uint32] = omnibuf_field(1, default_factory=list)


@omnibuf_message
class _DepthChain:
    nxt: _DepthChain | None = omnibuf_field(1, default=None)
    leaf: _DepthLeafList | None = omnibuf_field(2, default=None)


def test_fast_slot_none_empty_list_respects_depth_limit() -> None:
    """Fast-slot encoder must enforce MAX_NESTING_DEPTH for None default-empty list fields."""
    leaf = _DepthLeafList(items=None)  # type: ignore[arg-type]
    cur = _DepthChain(leaf=leaf)
    # leaf sits at depth = MAX_NESTING_DEPTH, so its array field is at MAX_NESTING_DEPTH + 1
    for _ in range(omnibuf_wire.MAX_NESTING_DEPTH - 1):
        cur = _DepthChain(nxt=cur)
    with pytest.raises(OmniBufEncodeError):
        marshal(cur)


class _HugeFakeSeq(Sequence[int]):
    def __len__(self) -> int:
        return 10**12

    def __getitem__(self, idx: int | slice) -> Any:
        raise ValueError("hostile sequence")


def test_hostile_sequence_huge_len_raises_without_abort() -> None:
    """Encoding a non-list sequence with huge __len__ must raise cleanly without Rust OOM abort."""
    holder = _FastSlotU32List(vals=_HugeFakeSeq())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="hostile sequence"):
        marshal(holder)


def test_gpb_mismatched_wire_type_before_repeated_clears_reused_dst() -> None:
    """Mismatched wire type on a repeated field must not mark it seen before a valid occurrence."""
    from omnibuf.protobuf_codec import unmarshal_proto

    # FileDescriptorProto has repeated string dependency = 3
    dst = descriptor_pb2.FileDescriptorProto(dependency=["stale"])
    # Wire packet: field #3 with mismatched WIRE_UINT, then field #3 with valid WIRE_ARRAY of strings
    enc = Encoder()
    enc.write_uint32(3, 999)
    enc.write_string_array(3, ["fresh"])
    pkt = enc.finish()

    unmarshal_proto(pkt, dst)
    assert list(dst.dependency) == ["fresh"]


@omnibuf_message
class _ScalarArraysMsg:
    u32s: list[Uint32] = omnibuf_field(1, default_factory=list)
    f64s: list[float] = omnibuf_field(2, default_factory=list)
    bools: list[bool] = omnibuf_field(3, default_factory=list)


@omnibuf_message
class _ArrayLeaf:
    x: Uint32 = omnibuf_field(1, default=0)


@omnibuf_message
class _SubMsgArrayHolder:
    items: list[_ArrayLeaf] = omnibuf_field(1, default_factory=list)


@omnibuf_message
class _SubMsgArrayChain:
    nxt: _SubMsgArrayChain | None = omnibuf_field(1, default=None)
    items: list[_ArrayLeaf] = omnibuf_field(2, default_factory=list)


def test_truncated_array_huge_count_fails_without_oom() -> None:
    """A 7-byte crafted array claiming count=4_194_304 with 0 element bytes must fail without OOM."""
    import tracemalloc

    huge_count = 4_194_304
    # 1-byte tag + 1-byte container len (5) + 1-byte elem_wt + 4-byte varint count = 7 bytes
    arr_body_u32 = bytes([WIRE_UINT]) + encode_varint(huge_count)
    pkt_u32 = encode_tag(1, WIRE_ARRAY) + encode_varint(len(arr_body_u32)) + arr_body_u32
    assert len(pkt_u32) == 7

    arr_body_sub = bytes([WIRE_SUB_MSG]) + encode_varint(huge_count)
    pkt_sub = encode_tag(1, WIRE_ARRAY) + encode_varint(len(arr_body_sub)) + arr_body_sub
    assert len(pkt_sub) == 7

    # Also test fixed-width element size check: count=2 for Float64 (8 bytes each) with only 8 bytes
    arr_body_f64 = bytes([omnibuf_wire.WIRE_FLOAT64]) + encode_varint(2) + (b"\x00" * 8)
    pkt_f64 = encode_tag(2, WIRE_ARRAY) + encode_varint(len(arr_body_f64)) + arr_body_f64

    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        # Fast-slot scalar array path
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_u32, _ScalarArraysMsg)
        # Slow / decode_slice_budget scalar array path (passing an instance forces decode_slice_budget)
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_u32, _ScalarArraysMsg())
        # Fixed-width min_elem_bytes check (fast + slow paths)
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_f64, _ScalarArraysMsg)
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_f64, _ScalarArraysMsg())
        # Fast-slot submsg array path
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_sub, _SubMsgArrayHolder)
        # Slow / decode_slice_budget submsg array path
        with pytest.raises(OmniBufDecodeError):
            unmarshal(pkt_sub, _SubMsgArrayHolder())

        _, peak = tracemalloc.get_traced_memory()
        # 4_194_304 pointers would be ~33.5 MB; peak must stay tiny (< 1 MB)
        assert peak < 1_000_000, f"Unexpectedly high allocation peak: {peak} bytes"
    finally:
        tracemalloc.stop()


def test_fast_submsg_array_enforces_max_depth() -> None:
    """decode_fast_array_submsg_raw must reject non-empty submsg arrays at depth+2 > MAX_NESTING_DEPTH."""
    # Innermost chain node at depth = MAX_NESTING_DEPTH - 1 (31):
    # - Its array field is at depth + 1 = 32 (allowed)
    # - A non-empty element inside that array is at depth + 2 = 33 (> 32 -> rejected)
    arr_non_empty = bytes([WIRE_SUB_MSG]) + encode_varint(1) + encode_varint(0)
    node_non_empty = encode_tag(2, WIRE_ARRAY) + encode_varint(len(arr_non_empty)) + arr_non_empty
    arr_empty = bytes([WIRE_SUB_MSG]) + encode_varint(0)
    node_empty = encode_tag(2, WIRE_ARRAY) + encode_varint(len(arr_empty)) + arr_empty

    pkt_non_empty = node_non_empty
    pkt_empty = node_empty
    for _ in range(omnibuf_wire.MAX_NESTING_DEPTH - 1):
        pkt_non_empty = (
            encode_tag(1, WIRE_SUB_MSG) + encode_varint(len(pkt_non_empty)) + pkt_non_empty
        )
        pkt_empty = encode_tag(1, WIRE_SUB_MSG) + encode_varint(len(pkt_empty)) + pkt_empty

    # Fast-slot path
    with pytest.raises(OmniBufDecodeError):
        unmarshal(pkt_non_empty, _SubMsgArrayChain)
    # Slow path
    with pytest.raises(OmniBufDecodeError):
        unmarshal(pkt_non_empty, _SubMsgArrayChain())

    # Empty submsg array at depth 31 (array depth 32, 0 elements) is valid
    decoded = unmarshal(pkt_empty, _SubMsgArrayChain)
    assert isinstance(decoded, _SubMsgArrayChain)


@omnibuf_message
class _StrMsg:
    s: str = omnibuf_field(1, default="")


def test_long_ascii_and_non_ascii_strings_roundtrip() -> None:
    """Fast-slot string decode handles >64B ASCII, >64B non-ASCII, and invalid >64B UTF-8."""
    long_ascii = "a" * 128
    long_utf8 = "日本語テスト🚀" * 16  # > 64 UTF-8 bytes
    for text in ("", "x", "hi", "é" * 10, long_ascii, long_utf8):
        raw = marshal(_StrMsg(s=text))
        got = unmarshal(raw, _StrMsg)
        assert got.s == text

    bad_long_utf8 = b"a" * 70 + b"\xff\xfe"
    bad_pkt = (
        encode_tag(1, omnibuf_wire.WIRE_STRING) + encode_varint(len(bad_long_utf8)) + bad_long_utf8
    )
    with pytest.raises(OmniBufDecodeError):
        unmarshal(bad_pkt, _StrMsg)


def test_large_bool_and_float64_arrays_roundtrip() -> None:
    """Large (>4096) bool and float64 arrays exercise CHECK_SIGNALS=true in decode_fast_array_scalar_other."""
    n = 5000
    msg = _ScalarArraysMsg(
        f64s=[float(i) * 0.5 for i in range(n)],
        bools=[(i % 2) == 0 for i in range(n)],
    )
    raw = marshal(msg)
    assert len(raw) >= 4096
    got = unmarshal(raw, _ScalarArraysMsg)
    assert got.f64s == msg.f64s
    assert got.bools == msg.bools


def test_mutable_bytearray_snapshot_during_python_reentry() -> None:
    target_buf = bytearray()

    @omnibuf_message
    class EvilChild:
        label: str = omnibuf_field(1, default="")

        def __init__(self, label: str = "") -> None:
            # Mutating the input bytearray mid-decode must not corrupt or UAF the Rust decoder
            target_buf.clear()
            target_buf.extend(b"\xff" * 64)
            self.label = label

    @omnibuf_message
    class EvilParent:
        child: EvilChild | None = omnibuf_field(1, default=None)
        tail: Uint32 = omnibuf_field(2, default=0)

    enc = Encoder()
    enc.begin_submsg(1)
    enc.write_string(1, "safe-payload")
    enc.end_submsg()
    enc.write_uint32(2, 4242)
    valid_bytes = enc.finish()

    target_buf[:] = valid_bytes
    decoded = unmarshal(target_buf, EvilParent)
    assert decoded.child is not None
    assert decoded.child.label == "safe-payload"
    assert decoded.tail == 4242

    # Also verify memoryview over bytearray works cleanly across Opaque, splice, and blind decode
    raw_peer = peer_omnibuf_pb.marshal_peer_update(
        peer_omnibuf_pb.PeerUpdate(
            asn=64512,
            router_id="rtr1",
            location=peer_omnibuf_pb.Location(city="Frankfurt"),
            sequence=10,
        )
    )
    mut_peer = bytearray(raw_peer)
    mv_peer = memoryview(mut_peer)
    op = peer_omnibuf_pb.OpaquePeerUpdate(mv_peer)
    mut_peer[0] ^= (
        0xFF  # Mutating original bytearray after OpaqueView init must not affect snapshot
    )
    loc = op.get_location()
    assert loc is not None and loc.city == "Frankfurt"
    op.set_sequence(11)
    spliced = op.marshal()
    assert peer_omnibuf_pb.unmarshal_peer_update(spliced).sequence == 11

    mut_blind = bytearray(valid_bytes)
    validate_message(memoryview(mut_blind))
    assert decode_blind(memoryview(mut_blind)) == {
        "field_1": {"field_1": "safe-payload"},
        "field_2": 4242,
    }


def test_list_and_dict_mutation_during_element_dunder_callbacks() -> None:
    @omnibuf_message
    class ContainerMsg:
        nums: list[Uint32] = omnibuf_field(1, default_factory=list)
        scores: dict[str, Uint32] = omnibuf_field(2, default_factory=dict)

    nums_list: list[Any] = []
    scores_dict: dict[str, Any] = {}

    class MutatingListInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            nums_list.clear()
            return self._val

    class MutatingDictInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            scores_dict.clear()
            return self._val

    nums_list.extend([MutatingListInt(10), MutatingListInt(20), MutatingListInt(30)])
    scores_dict["a"] = MutatingDictInt(100)
    scores_dict["b"] = MutatingDictInt(200)

    msg = ContainerMsg(nums=nums_list, scores=scores_dict)
    raw = marshal(msg, deterministic=True)
    restored = unmarshal(raw, ContainerMsg)
    assert restored.nums == [10, 20, 30]
    assert restored.scores == {"a": 100, "b": 200}


def test_submsg_list_mutation_during_property_access() -> None:
    children_list: list[Any] = []

    class MutatingSubInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            children_list.clear()
            return self._val

    @omnibuf_message
    class LeafItem:
        val: Uint32 = omnibuf_field(1, default=0)

    @omnibuf_message
    class BagMsg:
        items: list[LeafItem] = omnibuf_field(1, default_factory=list)

    children_list.extend([LeafItem(val=MutatingSubInt(77)), LeafItem(val=MutatingSubInt(88))])  # type: ignore[arg-type]
    raw = marshal(BagMsg(items=children_list))
    restored = unmarshal(raw, BagMsg)
    assert [it.val for it in restored.items] == [77, 88]


def test_multithreaded_first_use_dataclass_codec_compilation() -> None:
    @omnibuf_message
    class ConcurrentLeaf:
        x: Uint32 = omnibuf_field(1, default=0)

    @omnibuf_message
    class ConcurrentNode:
        id: Uint32 = omnibuf_field(1, default=0)
        leaf: ConcurrentLeaf = omnibuf_field(2, default_factory=ConcurrentLeaf)
        children: list[ConcurrentNode] = omnibuf_field(3, default_factory=list)

    barrier = threading.Barrier(8)

    def worker(idx: int) -> int:
        barrier.wait()
        node = ConcurrentNode(
            id=idx,
            leaf=ConcurrentLeaf(x=idx * 10),
            children=[ConcurrentNode(id=idx + 100)],
        )
        raw = marshal(node)
        out = unmarshal(raw, ConcurrentNode)
        return out.leaf.x + out.children[0].id

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(1, 9)))
    assert results == [i * 10 + (i + 100) for i in range(1, 9)]


def test_registered_types_do_not_shadow_module_local_classes() -> None:
    mod_a = types.ModuleType("_pkg_a_test")
    mod_b = types.ModuleType("_pkg_b_test")
    sys.modules["_pkg_a_test"] = mod_a
    sys.modules["_pkg_b_test"] = mod_b
    try:
        exec(
            "from omnibuf import Uint32, omnibuf_field, omnibuf_message\n"
            "@omnibuf_message\n"
            "class CollisionChild:\n"
            "    a_only: Uint32 = omnibuf_field(1, default=11)\n",
            mod_a.__dict__,
        )
        exec(
            "from __future__ import annotations\n"
            "from omnibuf import omnibuf_field, omnibuf_message\n"
            "class CollisionChild:\n"
            "    pass\n"
            "# Replace with module-local @omnibuf_message of the same name\n"
            "@omnibuf_message\n"
            "class CollisionChild:\n"  # noqa: F811
            "    b_text: str = omnibuf_field(2, default='from_b')\n"
            "@omnibuf_message\n"
            "class HolderB:\n"
            "    child: CollisionChild = omnibuf_field(1, default_factory=CollisionChild)\n",
            mod_b.__dict__,
        )
        holder_cls = mod_b.__dict__["HolderB"]
        child_b_cls = mod_b.__dict__["CollisionChild"]
        inst = holder_cls(child=child_b_cls(b_text="local-wins"))
        raw = marshal(inst)
        decoded = unmarshal(raw, holder_cls)
        assert isinstance(decoded.child, child_b_cls)
        assert decoded.child.b_text == "local-wins"
    finally:
        sys.modules.pop("_pkg_a_test", None)
        sys.modules.pop("_pkg_b_test", None)


def test_dataclass_enums_and_invalid_enum_decode_error() -> None:
    class RoleInt(enum.IntEnum):
        UNKNOWN = 0
        PRIMARY = 1
        STANDBY = -2

    class PlainStatus(enum.Enum):
        IDLE = 0
        ACTIVE = 5

    @omnibuf_message
    class NodeState:
        role: RoleInt = omnibuf_field(1, default=RoleInt.UNKNOWN)
        status: PlainStatus = omnibuf_field(2, default=PlainStatus.IDLE)
        history: list[RoleInt] = omnibuf_field(3, default_factory=list)
        by_peer: dict[str, PlainStatus] = omnibuf_field(4, default_factory=dict)

    state = NodeState(
        role=RoleInt.STANDBY,
        status=PlainStatus.ACTIVE,
        history=[RoleInt.PRIMARY, RoleInt.STANDBY],
        by_peer={"p1": PlainStatus.ACTIVE},
    )
    raw = marshal(state, deterministic=True)
    decoded = unmarshal(raw, NodeState)
    assert decoded == state
    assert isinstance(decoded.role, RoleInt)
    assert isinstance(decoded.status, PlainStatus)

    # Unknown closed enum value on wire raises OmniBufDecodeError (not bare ValueError)
    enc_bad = Encoder()
    enc_bad.write_sint32(2, 999)
    with pytest.raises(OmniBufDecodeError):
        unmarshal(enc_bad.finish(), NodeState)


def test_none_policy_class_name_and_optional_container_elements_rejected() -> None:
    class NonePolicy:
        pass

    # NonePolicy contains "None" in its name, so it must NOT receive an implicit default=None
    @omnibuf_message
    class BadMissingDefault:
        policy: NonePolicy = omnibuf_field(1)

    with pytest.raises(TypeError):
        BadMissingDefault()  # type: ignore[call-arg]

    @omnibuf_message
    class GoodOptionalPolicy:
        policy: NonePolicy | None = omnibuf_field(1)

    assert GoodOptionalPolicy().policy is None  # type: ignore[call-arg]

    @omnibuf_message
    class BadOptList:
        items: list[int | None] = omnibuf_field(1, default_factory=list)

    with pytest.raises(OmniBufEncodeError):
        marshal(BadOptList())

    @omnibuf_message
    class BadOptMapVal:
        mapping: dict[str, int | None] = omnibuf_field(1, default_factory=dict)

    with pytest.raises(OmniBufEncodeError):
        marshal(BadOptMapVal())


def test_bytes_as_str_encode_error_and_neg_zero_omitempty_and_deep_recursive_field0() -> None:
    @omnibuf_message
    class RawLabel:
        text: bytes = omnibuf_field(1, wire="string", default=b"")

    with pytest.raises(OmniBufEncodeError):
        marshal(RawLabel(text=b"\xff\xfe"))

    @omnibuf_message
    class SignedZeroMsg:
        f32: Float32 = omnibuf_field(1, default=0.0, omitempty=True)
        f64: Float64 = omnibuf_field(2, default=0.0, omitempty=True)

    # +0.0 is omitted when omitempty=True, whereas -0.0 is emitted and preserves sign bit!
    assert marshal(SignedZeroMsg(f32=0.0, f64=0.0)) == b""
    neg_raw = marshal(SignedZeroMsg(f32=-0.0, f64=-0.0))
    assert len(neg_raw) > 0
    neg_dec = unmarshal(neg_raw, SignedZeroMsg)
    assert math.copysign(1.0, neg_dec.f32) == -1.0
    assert math.copysign(1.0, neg_dec.f64) == -1.0

    # Deep recursive TreeNode self_describing=True populates SchemaMeta down active levels
    deep = TreeNode(
        id=1,
        name="L1",
        primary=TreeNode(
            id=2,
            name="L2",
            primary=TreeNode(
                id=3,
                name="L3",
                children=[TreeNode(id=4, name="L4")],
            ),
        ),
    )
    sd = marshal(deep, self_describing=True)
    blind = decode_blind(sd)
    assert blind["name"] == "L1"
    assert blind["primary"]["name"] == "L2"
    assert blind["primary"]["primary"]["name"] == "L3"
    assert blind["primary"]["primary"]["children"][0]["name"] == "L4"


def test_omnibuf_works_without_google_protobuf_installed() -> None:
    script = """
import sys
sys.modules["google.protobuf"] = None
sys.modules["google.protobuf.message"] = None
sys.modules["google.protobuf.descriptor"] = None

import omnibuf
from omnibuf import Uint32, omnibuf_field, omnibuf_message
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb, peer_pb

@omnibuf_message
class Ping:
    seq: Uint32 = omnibuf_field(1, default=0)
    msg: str = omnibuf_field(2, default="")

raw = omnibuf.marshal(Ping(seq=7, msg="ok"), self_describing=True)
assert omnibuf.unmarshal(raw, Ping) == Ping(seq=7, msg="ok")
assert omnibuf.decode_blind(raw) == {"seq": 7, "msg": "ok"}

pb = peer_pb.PeerUpdate(asn=64512, router_id="r1", sequence=99)
pb_wire = omnibuf.marshal(pb)
assert omnibuf.unmarshal(pb_wire, peer_pb.PeerUpdate).sequence == 99
assert peer_omnibuf_pb.OpaquePeerUpdate(pb_wire).get_sequence() == 99
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"


@pytest.mark.parametrize("number", [33_554_431, 33_554_432, 268_435_457, 536_870_911])
@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize(
    ("field_type", "value", "wire"),
    [
        (int, 42, None),
        (bool, True, None),
        (float, 1.5, None),
        (str, "hello", None),
        (bytes, b"hello", None),
        (int, 42, "fixed32"),
        (int, 42, "fixed64"),
        (list[int], [1, 42], None),
    ],
)
def test_large_field_tags(number: int, slots: bool, field_type: Any, value: Any, wire: Any) -> None:
    from dataclasses import make_dataclass

    cls: Any = omnibuf_message(
        make_dataclass(
            f"LargeTags{number}{slots}",
            [
                (
                    "value",
                    field_type,
                    omnibuf_field(number, default_factory=lambda: value, wire=wire),
                ),
            ],
            slots=slots,
        )
    )
    raw = marshal(cls())
    assert f"field_{number}" in decode_blind(raw)
    assert unmarshal(raw, cls).value == value


def test_foreign_slot_descriptor_rejected() -> None:
    from omnibuf import CompiledCodec

    class Other:
        __slots__ = ("value",)

    class Victim:
        __slots__ = ("actual",)

    setattr(Victim, "value", Other.__dict__["value"])  # noqa: B010
    codec = CompiledCodec(Victim, "Victim")
    with pytest.raises(OmniBufEncodeError, match="unrelated class"):
        codec.set_fields([dict(number=1, attr="value", kind="uint64", wire_type=WIRE_UINT)], b"")


def test_optional_getter_error_propagates() -> None:
    from omnibuf import CompiledCodec

    class Message:
        @property
        def values(self) -> list[int]:
            raise RuntimeError("getter failed")

        @values.setter
        def values(self, value: list[int]) -> None:
            raise AssertionError("must not replace a failed getter")

    codec = CompiledCodec(Message, "Message", fast_alloc=False)
    codec.set_fields(
        [
            dict(
                number=1,
                attr="values",
                kind="array_scalar",
                wire_type=WIRE_ARRAY,
                elem_kind="uint64",
                elem_wt=WIRE_UINT,
            )
        ],
        b"",
    )
    # Field 1: array<uint>, one element with value 42.
    with pytest.raises(RuntimeError, match="getter failed"):
        codec.decode_at(bytes([0x3B, 0x07, WIRE_UINT, 0x03, 0x55]), Message(), merge=True)


def test_extension_codec_cache_releases_evicted_classes() -> None:
    import gc
    import weakref

    from omnibuf import CompiledCodec
    from omnibuf._omnibuf_ext import register_dataclass_codec_py

    def register(index: int) -> weakref.ReferenceType[type[Any]]:
        cls = type(f"EvictedCodec{index}", (), {})
        codec: CompiledCodec[Any] = CompiledCodec(cls, cls.__name__)
        codec.set_fields([], b"")
        register_dataclass_codec_py(cls, codec)
        return weakref.ref(cls)

    first = register(0)
    for index in range(1, 130):
        register(index)
    gc.collect()
    assert first() is None
