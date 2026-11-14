"""OmniBuf conformance runner adapter exercising all 4 implementation tiers."""

from __future__ import annotations

import struct
import sys
from typing import BinaryIO

from . import (
    WIRE_UINT,
    Fixed32,
    Fixed64,
    Float32,
    Float64,
    OmniBufDecodeError,
    OmniBufEncodeError,
    Sint32,
    Sint64,
    SpliceField,
    Uint32,
    Uint64,
    append_varint,
    decode_blind,
    decode_blind_json,
    marshal,
    omnibuf_field,
    omnibuf_message,
    splice_fields,
    unmarshal,
)
from .gen.omnibuf.bench import peer_omnibuf_pb, peer_pb
from .gen.omnibuf.conformance import conformance_omnibuf_pb, conformance_pb

MAX_FRAME_BYTES = 16 * 1024 * 1024
_FRAME_LEN = struct.Struct("<I")
_F32_BITS = struct.Struct("<f")
_F64_BITS = struct.Struct("<d")
_U32_BITS = struct.Struct("<I")
_U64_BITS = struct.Struct("<Q")


def _f32_bits(val: float) -> int:
    (bits,) = _U32_BITS.unpack(_F32_BITS.pack(val))
    return int(bits)


def _f64_bits(val: float) -> int:
    (bits,) = _U64_BITS.unpack(_F64_BITS.pack(val))
    return int(bits)


# ============================================================================
# Conformance Framing Messages (matching protocol.go uint32 tier & wire_format)
# ============================================================================

WIRE_FORMAT_UNSPECIFIED = 0
WIRE_FORMAT_OMNIBUF = 1
WIRE_FORMAT_JSON = 2

TIER_UNSPECIFIED = 0
TIER_PLUGIN = 1
TIER_PROTOBUF_TYPES = 2
TIER_ANNOTATED_STRUCT = 3
TIER_BLIND = 4


@omnibuf_message("ConformanceRequest")
class ConformanceFrameRequest:
    test_name: str = omnibuf_field(1, default="")
    message_type: str = omnibuf_field(2, default="")
    tier: Uint32 = omnibuf_field(3, default=0)
    requested_output_format: Uint32 = omnibuf_field(4, default=0)
    omnibuf_payload: bytes = omnibuf_field(5, default=b"")
    json_payload: str = omnibuf_field(6, default="")
    self_describing: bool = omnibuf_field(7, default=False)
    test_opaque_splice: bool = omnibuf_field(8, default=False)
    test_opaque_splice_shrink: bool = omnibuf_field(9, default=False)


@omnibuf_message("ConformanceResponse")
class ConformanceFrameResponse:
    parse_error: str = omnibuf_field(1, default="", omitempty=True)
    serialize_error: str = omnibuf_field(2, default="", omitempty=True)
    runtime_error: str = omnibuf_field(3, default="", omitempty=True)
    skipped: str = omnibuf_field(4, default="", omitempty=True)
    omnibuf_payload: bytes = omnibuf_field(5, default=b"", omitempty=True)
    json_payload: str = omnibuf_field(6, default="", omitempty=True)


# ============================================================================
# Canonical Tier 3 Annotated Struct (@omnibuf_message) Definitions
# ============================================================================


@omnibuf_message("Location")
class AnnotatedLocation:
    region: str = omnibuf_field(1, default="")
    datacenter: str = omnibuf_field(2, default="")
    city: str = omnibuf_field(3, default="")
    rack: Uint32 = omnibuf_field(4, default=0)
    latitude: Float32 = omnibuf_field(5, default=0.0)
    longitude: Float32 = omnibuf_field(6, default=0.0)


@omnibuf_message("Neighbor")
class AnnotatedNeighbor:
    peer_asn: Uint32 = omnibuf_field(1, default=0)
    router: str = omnibuf_field(2, default="")
    latency_us: Uint32 = omnibuf_field(3, default=0)
    established: bool = omnibuf_field(4, default=False)


@omnibuf_message("PeerUpdate")
class AnnotatedPeerUpdate:
    asn: Uint32 = omnibuf_field(1, default=0)
    router_id: str = omnibuf_field(2, default="")
    active: bool = omnibuf_field(3, default=False)
    uptime_sec: Uint64 = omnibuf_field(4, default=0)
    rssi_dbm: Sint32 = omnibuf_field(5, default=0)
    cpu_load: Float64 = omnibuf_field(6, default=0.0)
    tags: list[str] = omnibuf_field(7, default_factory=list)
    prefixes: list[Uint32] = omnibuf_field(8, default_factory=list)
    location: AnnotatedLocation = omnibuf_field(9, default_factory=AnnotatedLocation)
    neighbors: list[AnnotatedNeighbor] = omnibuf_field(10, default_factory=list)
    sequence: Uint64 = omnibuf_field(11, default=0)


@omnibuf_message("AllTypesSubMsg")
class AnnotatedAllTypesSubMsg:
    id: Uint32 = omnibuf_field(1, default=0)
    label: str = omnibuf_field(2, default="")
    flag: bool = omnibuf_field(3, default=False)
    score: Sint64 = omnibuf_field(4, wire="sint", default=0)


@omnibuf_message("TestAllTypes")
class AnnotatedTestAllTypes:
    f1_uint32: Uint32 = omnibuf_field(1, default=0)
    f2_uint64: Uint64 = omnibuf_field(2, default=0)
    f3_sint32: Sint32 = omnibuf_field(3, wire="sint", default=0)
    f4_sint64: Sint64 = omnibuf_field(4, wire="sint", default=0)
    f5_bool: bool = omnibuf_field(5, default=False)
    f6_string: str = omnibuf_field(6, default="")
    f7_bytes: bytes = omnibuf_field(7, default=b"")
    f8_sub_msg: AnnotatedAllTypesSubMsg | None = omnibuf_field(8, default=None)
    f9_string_arr: list[str] = omnibuf_field(9, default_factory=list)
    f10_uint32_arr: list[Uint32] = omnibuf_field(10, default_factory=list)
    f11_sub_msg_arr: list[AnnotatedAllTypesSubMsg] = omnibuf_field(11, default_factory=list)
    f12_map_str_uint: dict[str, Uint64] = omnibuf_field(12, default_factory=dict)
    f13_float32: Float32 = omnibuf_field(13, default=0.0)
    f14_float64: Float64 = omnibuf_field(14, default=0.0)
    f15_fixed32: Fixed32 = omnibuf_field(15, wire="fixed32", default=0)
    f16_fixed64: Fixed64 = omnibuf_field(16, wire="fixed64", default=0)
    f20_overflow_str: str = omnibuf_field(20, default="")


@omnibuf_message("TreeNode")
class TreeNode:
    id: Uint32 = omnibuf_field(1, default=0)
    name: str = omnibuf_field(2, default="")
    weight: Sint64 = omnibuf_field(3, wire="sint", default=0)
    primary: TreeNode | None = omnibuf_field(4, default=None)
    children: list[TreeNode] = omnibuf_field(5, default_factory=list)
    branches: list[TreeNode] = omnibuf_field(6, default_factory=list)
    labels: dict[str, Uint64] = omnibuf_field(7, default_factory=dict)


@omnibuf_message("NestedNIC")
class NestedNIC:
    if_index: Uint32 = omnibuf_field(1, default=0)
    mac: str = omnibuf_field(2, default="")
    ips: list[Uint32] = omnibuf_field(3, default_factory=list)


@omnibuf_message("NestedServer")
class NestedServer:
    server_id: Uint32 = omnibuf_field(1, default=0)
    hostname: str = omnibuf_field(2, default="")
    nics: list[NestedNIC] = omnibuf_field(3, default_factory=list)


@omnibuf_message("NestedRack")
class NestedRack:
    rack_id: Uint32 = omnibuf_field(1, default=0)
    zone: str = omnibuf_field(2, default="")
    servers: list[NestedServer] = omnibuf_field(3, default_factory=list)


@omnibuf_message("NestedCluster")
class NestedCluster:
    cluster_name: str = omnibuf_field(1, default="")
    racks: list[NestedRack] = omnibuf_field(2, default_factory=list)
    epoch: Uint64 = omnibuf_field(3, default=0)


# ============================================================================
# Tier Handlers
# ============================================================================


def _check_splice_aliased_prefix(packet: bytes) -> None:
    enc = bytearray()
    append_varint(enc, (1 << 4) | WIRE_UINT)
    append_varint(enc, 1 << 40)
    repl = [SpliceField(field_num=1, encoded_field=bytes(enc))]
    spliced = splice_fields(None, packet, repl)
    for prefix_len in (0, 3, 32):
        prefix = b"\xa5" * prefix_len
        storage = bytearray(prefix + packet)
        mv = memoryview(storage)
        want = prefix + spliced
        got = splice_fields(mv[:prefix_len], mv[prefix_len:], repl)
        if got != want:
            raise RuntimeError(
                f"opaque splice with {prefix_len}-byte aliased prefix changed prefix or output"
            )
        if bytes(storage[prefix_len:]) != packet:
            raise RuntimeError(
                f"opaque splice with {prefix_len}-byte aliased prefix modified source packet"
            )


def _handle_blind(req: ConformanceFrameRequest) -> ConformanceFrameResponse:
    resp = ConformanceFrameResponse()
    payload = req.omnibuf_payload
    if req.requested_output_format == WIRE_FORMAT_JSON:
        try:
            resp.json_payload = decode_blind_json(
                payload,
                allow_nan=False,
                fallback_on_non_finite=True,
            )
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
        return resp

    try:
        decode_blind(payload)
    except OmniBufDecodeError as exc:
        resp.parse_error = str(exc)
    return resp


def _handle_plugin_tier(
    req: ConformanceFrameRequest,
) -> ConformanceFrameResponse:
    resp = ConformanceFrameResponse()
    payload = req.omnibuf_payload

    msg_type = req.message_type
    if req.test_opaque_splice or req.test_opaque_splice_shrink:
        try:
            _check_splice_aliased_prefix(payload)
            if msg_type == "omnibuf.bench.PeerUpdate":
                probe_peer = peer_omnibuf_pb.OpaquePeerUpdate(payload)
                probe_peer.set_sequence(0)
                _ = probe_peer.marshal()
            elif msg_type == "omnibuf.conformance.TestAllTypes":
                probe_all = conformance_omnibuf_pb.OpaqueTestAllTypes(payload)
                probe_all.set_f1_uint32(0)
                _ = probe_all.marshal()
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp
        except OmniBufEncodeError as exc:
            resp.serialize_error = str(exc)
            return resp
        except Exception as exc:  # noqa: BLE001
            resp.runtime_error = str(exc)
            return resp
    if msg_type == "omnibuf.bench.PeerUpdate":
        msg = peer_omnibuf_pb.PeerUpdate(
            asn=999999,
            router_id="stale-router",
            active=True,
            tags=["stale-tag"],
            prefixes=[999],
            location=peer_omnibuf_pb.Location(region="stale", city="stale-city", rack=999),
            neighbors=[peer_omnibuf_pb.Neighbor(peer_asn=999, router="stale-neighbor")],
            sequence=999999,
        )
        try:
            peer_omnibuf_pb.unmarshal_peer_update(payload, msg)
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp

        try:
            op = peer_omnibuf_pb.OpaquePeerUpdate(payload)
            op_loc = op.opaque_location()
            op_loc_city = op_loc.get_city() if op_loc is not None else ""
            want_city = msg.location.city if msg.location is not None else ""
            if (
                op.get_asn() != msg.asn
                or op.get_router_id() != msg.router_id
                or op.get_active() != msg.active
                or op.get_uptime_sec() != msg.uptime_sec
                or op.get_rssi_dbm() != msg.rssi_dbm
                or _f64_bits(op.get_cpu_load()) != _f64_bits(msg.cpu_load)
                or len(op.get_tags()) != len(msg.tags)
                or len(op.get_prefixes()) != len(msg.prefixes)
                or op_loc_city != want_city
                or len(op.get_neighbors()) != len(msg.neighbors)
                or op.get_sequence() != msg.sequence
            ):
                resp.parse_error = "opaque PeerUpdate getter mismatch with decoded struct"
                return resp

            if req.test_opaque_splice:
                op.set_asn(1_000_000)
                op.set_router_id("edge-rtr-fra01-" * 20)
                op.set_active(not op.get_active())
                op.set_uptime_sec(0xFFFF_FFFF_FFFF_FFFF)
                op.set_rssi_dbm(-1_000_000)
                op.set_cpu_load(99.875)
                op.set_tags(["tag-grow-a", "tag-grow-b", "long-tag-" * 20])
                op.set_prefixes([100000, 200000, 300000, 400000, 500000, 600000])
                op.set_location(
                    peer_omnibuf_pb.Location(
                        region="eu-central-grown",
                        datacenter="fra-dc-" * 25,
                        city="Berlin",
                        rack=999999,
                        latitude=52.52,
                        longitude=13.405,
                    )
                )
                op.set_sequence(op.get_sequence() + 1)
                resp.omnibuf_payload = op.marshal()
                return resp

            if req.test_opaque_splice_shrink:
                op.set_asn(1)
                op.set_router_id("r")
                op.set_active(False)
                op.set_uptime_sec(5)
                op.set_rssi_dbm(-1)
                op.set_cpu_load(0.5)
                op.set_tags(["t"])
                op.set_prefixes([1])
                op.set_location(
                    peer_omnibuf_pb.Location(
                        region="r",
                        datacenter="d",
                        city="c",
                        rack=1,
                        latitude=1.0,
                        longitude=2.0,
                    )
                )
                op.set_sequence(2)
                resp.omnibuf_payload = op.marshal()
                return resp

            resp.omnibuf_payload = msg.marshal_omnibuf(
                deterministic=True,
                self_describing=req.self_describing,
            )
            return resp
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp
        except OmniBufEncodeError as exc:
            resp.serialize_error = str(exc)
            return resp

    if msg_type == "omnibuf.conformance.TestAllTypes":
        msg_all = conformance_omnibuf_pb.TestAllTypes(
            f1_uint32=999999,
            f5_bool=True,
            f6_string="stale-str",
            f7_bytes=b"\xff",
            f8_sub_msg=conformance_omnibuf_pb.AllTypesSubMsg(
                id=999,
                label="stale-sub",
                flag=True,
                score=-999,
            ),
            f9_string_arr=["stale"],
            f10_uint32_arr=[999],
            f11_sub_msg_arr=[conformance_omnibuf_pb.AllTypesSubMsg(id=999, label="stale-elem")],
            f12_map_str_uint={"stale": 999},
            f20_overflow_str="stale-overflow",
        )
        try:
            conformance_omnibuf_pb.unmarshal_test_all_types(payload, msg_all)
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp

        try:
            op_all = conformance_omnibuf_pb.OpaqueTestAllTypes(payload)
            _ = op_all.get_f12_map_str_uint()
            want_sub = msg_all.f8_sub_msg or conformance_omnibuf_pb.AllTypesSubMsg()
            got_sub = op_all.get_f8_sub_msg() or conformance_omnibuf_pb.AllTypesSubMsg()
            if (
                op_all.get_f1_uint32() != msg_all.f1_uint32
                or op_all.get_f2_uint64() != msg_all.f2_uint64
                or op_all.get_f3_sint32() != msg_all.f3_sint32
                or op_all.get_f4_sint64() != msg_all.f4_sint64
                or op_all.get_f5_bool() != msg_all.f5_bool
                or op_all.get_f6_string() != msg_all.f6_string
                or op_all.get_f7_bytes() != msg_all.f7_bytes
                or got_sub.id != want_sub.id
                or got_sub.label != want_sub.label
                or got_sub.flag != want_sub.flag
                or got_sub.score != want_sub.score
                or len(op_all.get_f9_string_arr()) != len(msg_all.f9_string_arr)
                or len(op_all.get_f10_uint32_arr()) != len(msg_all.f10_uint32_arr)
                or len(op_all.get_f11_sub_msg_arr()) != len(msg_all.f11_sub_msg_arr)
                or _f32_bits(op_all.get_f13_float32()) != _f32_bits(msg_all.f13_float32)
                or _f64_bits(op_all.get_f14_float64()) != _f64_bits(msg_all.f14_float64)
                or op_all.get_f15_fixed32() != msg_all.f15_fixed32
                or op_all.get_f16_fixed64() != msg_all.f16_fixed64
                or op_all.get_f20_overflow_str() != msg_all.f20_overflow_str
            ):
                resp.parse_error = "opaque TestAllTypes getter mismatch with decoded struct"
                return resp

            if req.test_opaque_splice:
                op_all.set_f1_uint32(1_000_000)
                op_all.set_f2_uint64(0xFFFF_FFFF_FFFF_FFFF)
                op_all.set_f3_sint32(-1_000_000)
                op_all.set_f4_sint64(-0x8000_0000_0000_0000)
                op_all.set_f5_bool(not op_all.get_f5_bool())
                op_all.set_f6_string("grown-str-" * 30)
                op_all.set_f7_bytes(b"\xab\xcd" * 130)
                op_all.set_f8_sub_msg(
                    conformance_omnibuf_pb.AllTypesSubMsg(
                        id=888888,
                        label="sub-grown-" * 20,
                        flag=True,
                        score=-999999999,
                    )
                )
                op_all.set_f9_string_arr(["arr-grow-1", "arr-grow-2", "arr-grow-3-" * 15])
                op_all.set_f10_uint32_arr([100000, 200000, 300000, 400000, 500000])
                op_all.set_f11_sub_msg_arr(
                    [
                        conformance_omnibuf_pb.AllTypesSubMsg(
                            id=100001,
                            label="elem0-" * 25,
                            flag=True,
                            score=-500000,
                        ),
                        conformance_omnibuf_pb.AllTypesSubMsg(
                            id=100002,
                            label="elem1-grown",
                            flag=False,
                            score=500000,
                        ),
                    ]
                )
                op_all.set_f12_map_str_uint(
                    {
                        "k1": 1000000,
                        "k2": 0xFFFF_FFFF_FFFF_FFFF,
                        "k3_long_key": 424242,
                    }
                )
                op_all.set_f13_float32(-1234.5)
                op_all.set_f14_float64(3.141592653589793)
                op_all.set_f15_fixed32(0xDEADBEEF)
                op_all.set_f16_fixed64(0xCAFEBABEDEADBEEF)
                op_all.set_f20_overflow_str("overflow20-" * 20)
                resp.omnibuf_payload = op_all.marshal()
                return resp

            if req.test_opaque_splice_shrink:
                op_all.set_f1_uint32(1)
                op_all.set_f2_uint64(2)
                op_all.set_f3_sint32(-1)
                op_all.set_f4_sint64(-2)
                op_all.set_f5_bool(False)
                op_all.set_f6_string("s")
                op_all.set_f7_bytes(b"\x01")
                op_all.set_f8_sub_msg(
                    conformance_omnibuf_pb.AllTypesSubMsg(id=1, label="x", flag=False, score=-1)
                )
                op_all.set_f9_string_arr(["a"])
                op_all.set_f10_uint32_arr([7])
                op_all.set_f11_sub_msg_arr(
                    [conformance_omnibuf_pb.AllTypesSubMsg(id=1, label="e", flag=True, score=1)]
                )
                op_all.set_f12_map_str_uint({"k": 1})
                op_all.set_f13_float32(0.5)
                op_all.set_f14_float64(-0.25)
                op_all.set_f15_fixed32(7)
                op_all.set_f16_fixed64(9)
                op_all.set_f20_overflow_str("z")
                resp.omnibuf_payload = op_all.marshal()
                return resp

            resp.omnibuf_payload = msg_all.marshal_omnibuf(
                deterministic=True,
                self_describing=req.self_describing,
            )
            return resp
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp
        except OmniBufEncodeError as exc:
            resp.serialize_error = str(exc)
            return resp

    resp.skipped = "plugin tier generated for PeerUpdate and TestAllTypes"
    return resp


def _handle_protobuf_types_tier(
    req: ConformanceFrameRequest,
) -> ConformanceFrameResponse:
    resp = ConformanceFrameResponse()
    payload = req.omnibuf_payload
    msg_type = req.message_type

    if msg_type == "omnibuf.bench.PeerUpdate":
        pb_peer = peer_pb.PeerUpdate(
            asn=999999,
            router_id="stale-router",
            active=True,
            tags=["stale"],
            prefixes=[999],
            location=peer_pb.Location(region="stale", city="stale-city"),
            neighbors=[peer_pb.Neighbor(peer_asn=999, router="stale")],
            sequence=999999,
        )
        try:
            unmarshal(payload, pb_peer)
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp
        try:
            resp.omnibuf_payload = marshal(
                pb_peer,
                deterministic=True,
                self_describing=req.self_describing,
            )
        except OmniBufEncodeError as exc:
            resp.serialize_error = str(exc)
        return resp

    if msg_type == "omnibuf.conformance.TestAllTypes":
        pb_all = conformance_pb.TestAllTypes(
            f1_uint32=999999,
            f5_bool=True,
            f6_string="stale",
            f7_bytes=b"\xff",
            f8_sub_msg=conformance_pb.AllTypesSubMsg(id=999, label="stale", flag=True, score=-9),
            f9_string_arr=["stale"],
            f10_uint32_arr=[999],
            f11_sub_msg_arr=[conformance_pb.AllTypesSubMsg(id=999)],
            f12_map_str_uint={"stale": 999},
            f20_overflow_str="stale",
        )
        try:
            unmarshal(payload, pb_all)
        except OmniBufDecodeError as exc:
            resp.parse_error = str(exc)
            return resp
        try:
            resp.omnibuf_payload = marshal(
                pb_all,
                deterministic=True,
                self_describing=req.self_describing,
            )
        except OmniBufEncodeError as exc:
            resp.serialize_error = str(exc)
        return resp

    resp.skipped = "protobuf types tier exercises PeerUpdate and TestAllTypes"
    return resp


def _handle_annotated_struct_tier(
    req: ConformanceFrameRequest,
) -> ConformanceFrameResponse:
    resp = ConformanceFrameResponse()
    payload = req.omnibuf_payload
    msg_type = req.message_type

    target: object
    if msg_type == "omnibuf.bench.PeerUpdate":
        target = AnnotatedPeerUpdate(
            asn=999,
            router_id="stale",
            active=True,
            tags=["stale"],
            location=AnnotatedLocation(region="stale", city="stale"),
            neighbors=[AnnotatedNeighbor(peer_asn=999, router="stale")],
        )
    elif msg_type == "omnibuf.conformance.TreeNode":
        target = TreeNode(
            id=999,
            name="stale",
            primary=TreeNode(id=888, name="stale-child"),
            children=[TreeNode(id=777)],
            branches=[TreeNode(id=666)],
            labels={"stale": 1},
        )
    elif msg_type == "omnibuf.conformance.NestedCluster":
        target = NestedCluster(
            cluster_name="stale",
            racks=[NestedRack(rack_id=999, zone="stale")],
            epoch=999,
        )
    else:
        target = AnnotatedTestAllTypes(
            f1_uint32=999,
            f5_bool=True,
            f6_string="stale",
            f8_sub_msg=AnnotatedAllTypesSubMsg(id=999, label="stale"),
            f9_string_arr=["stale"],
            f12_map_str_uint={"stale": 1},
        )

    try:
        unmarshal(payload, target)
    except OmniBufDecodeError as exc:
        resp.parse_error = str(exc)
        return resp
    try:
        resp.omnibuf_payload = marshal(
            target,
            deterministic=True,
            self_describing=req.self_describing,
        )
    except OmniBufEncodeError as exc:
        resp.serialize_error = str(exc)
    return resp


def handle_request(req: ConformanceFrameRequest) -> ConformanceFrameResponse:
    """Dispatches a single ConformanceRequest across the 4 required OmniBuf tiers."""
    try:
        tier = req.tier
        if tier == TIER_BLIND:
            return _handle_blind(req)
        if tier == TIER_PLUGIN:
            return _handle_plugin_tier(req)
        if tier == TIER_PROTOBUF_TYPES:
            return _handle_protobuf_types_tier(req)
        if tier == TIER_ANNOTATED_STRUCT:
            return _handle_annotated_struct_tier(req)
        return ConformanceFrameResponse(runtime_error=f"unsupported tier: {tier}")
    except Exception as exc:  # noqa: BLE001
        return ConformanceFrameResponse(runtime_error=f"unhandled exception: {exc}")


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    if count == 0:
        return b""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def run_stdio_loop(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Runs the length-prefixed OmniBuf conformance IPC loop until EOF."""
    while True:
        len_buf = _read_exact(stdin, 4)
        if not len_buf:
            return 0
        if len(len_buf) < 4:
            sys.stderr.write("conformance-py: truncated frame length prefix\n")
            return 1
        (size,) = _FRAME_LEN.unpack(len_buf)
        if size > MAX_FRAME_BYTES:
            sys.stderr.write(f"conformance-py: frame size {size} exceeds {MAX_FRAME_BYTES}\n")
            return 1
        payload = _read_exact(stdin, size)
        if len(payload) < size:
            sys.stderr.write("conformance-py: unexpected EOF reading frame payload\n")
            return 1

        try:
            req = unmarshal(payload, ConformanceFrameRequest)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"conformance-py: decode request frame error: {exc}\n")
            return 1

        resp = handle_request(req)
        out_payload = marshal(resp)
        stdout.write(_FRAME_LEN.pack(len(out_payload)))
        if out_payload:
            stdout.write(out_payload)
        stdout.flush()


def main() -> None:
    """CLI entry point for conformance-py."""
    code = run_stdio_loop(sys.stdin.buffer, sys.stdout.buffer)
    if code != 0:
        sys.exit(code)


if __name__ == "__main__":
    main()
