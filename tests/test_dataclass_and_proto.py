"""Cross-tier tests for protobuf-py, @omnibuf_message dataclasses, google.protobuf, and Opaque views."""

from __future__ import annotations

from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2

import omnibuf
from omnibuf import (
    Float32,
    Float64,
    Sint32,
    Sint64,
    Uint32,
    Uint64,
    decode_blind,
    marshal,
    omnibuf_field,
    omnibuf_message,
    unmarshal,
)
from omnibuf.conformance import (
    AnnotatedPeerUpdate,
    NestedCluster,
    NestedNIC,
    NestedRack,
    NestedServer,
    TreeNode,
)
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb, peer_pb, peer_pb2
from omnibuf.gen.omnibuf.conformance import conformance_omnibuf_pb, conformance_pb, conformance_pb2
from omnibuf.plugin import generate_code

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


def test_plugin_generates_relative_cross_file_imports() -> None:
    req = plugin_pb2.CodeGeneratorRequest()
    f_common = req.proto_file.add()
    f_common.name = "acme/common/types.proto"
    f_common.package = "acme.common"
    f_common.syntax = "proto3"
    m_tag = f_common.message_type.add()
    m_tag.name = "Tag"
    fd_k = m_tag.field.add()
    fd_k.name = "key"
    fd_k.number = 1
    fd_k.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_k.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f_svc = req.proto_file.add()
    f_svc.name = "acme/service/item.proto"
    f_svc.package = "acme.service"
    f_svc.syntax = "proto3"
    f_svc.dependency.append("acme/common/types.proto")
    m_item = f_svc.message_type.add()
    m_item.name = "Item"
    fd_t = m_item.field.add()
    fd_t.name = "tag"
    fd_t.number = 1
    fd_t.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_t.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd_t.type_name = ".acme.common.Tag"

    req.file_to_generate.extend(["acme/common/types.proto", "acme/service/item.proto"])
    resp = generate_code(req)
    assert not resp.error
    by_name = {f.name: f.content for f in resp.file}
    assert (
        "from ..common import types_omnibuf_pb as _imp_0"
        in by_name["acme/service/item_omnibuf_pb.py"]
    )
