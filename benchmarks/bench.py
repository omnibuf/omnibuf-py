"""Reproducible PeerUpdate benchmark suite for omnibuf-py."""

from __future__ import annotations

import gc
import json
import platform
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import msgpack
import msgspec

import omnibuf
from omnibuf.conformance import (
    AnnotatedLocation,
    AnnotatedNeighbor,
    AnnotatedPeerUpdate,
)
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb, peer_pb, peer_pb2

_PEER_PB2: Any = peer_pb2

_NEIGHBOR_SPECS: tuple[tuple[int, str, int, bool], ...] = (
    (3356, "ae0.fra1.level3.net", 850, True),
    (1299, "ffm-b5-link.telia.net", 920, True),
    (174, "be2040.ccr41.fra03.atlas.cogentco.com", 1120, True),
    (2914, "ae-12.r24.frnkge08.de.bb.gin.ntt.net", 980, False),
)

_PREFIXES: list[int] = [
    167772160,
    172032000,
    3232235520,
    2886729728,
    134744072,
    134743040,
]

_TAGS: list[str] = ["tier1", "ebgp", "eu-central", "ixp-de-cix"]


# ============================================================================
# 1. Canonical SamplePeerUpdate Builders (11 fields, OmniBuf=366B, Proto=341B)
# ============================================================================


class MsgspecLocation(msgspec.Struct):
    region: str = ""
    datacenter: str = ""
    city: str = ""
    rack: int = 0
    latitude: float = 0.0
    longitude: float = 0.0


class MsgspecNeighbor(msgspec.Struct):
    peer_asn: int = 0
    router: str = ""
    latency_us: int = 0
    established: bool = False


class MsgspecPeerUpdate(msgspec.Struct):
    asn: int = 0
    router_id: str = ""
    active: bool = False
    uptime_sec: int = 0
    rssi_dbm: int = 0
    cpu_load: float = 0.0
    tags: list[str] = []
    prefixes: list[int] = []
    location: MsgspecLocation | None = None
    neighbors: list[MsgspecNeighbor] = []
    sequence: int = 0


def build_sample_generated(*, neighbor_repeats: int = 1) -> peer_omnibuf_pb.PeerUpdate:
    return peer_omnibuf_pb.PeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=list(_TAGS),
        prefixes=list(_PREFIXES),
        location=peer_omnibuf_pb.Location(
            region="eu-central-1",
            datacenter="FRA-Equinix-FR5",
            city="Frankfurt",
            rack=42,
            latitude=50.1109,
            longitude=8.6821,
        ),
        neighbors=[
            peer_omnibuf_pb.Neighbor(
                peer_asn=pasn,
                router=rtr,
                latency_us=lat,
                established=est,
            )
            for _ in range(neighbor_repeats)
            for pasn, rtr, lat, est in _NEIGHBOR_SPECS
        ],
        sequence=9876543210,
    )


def build_sample_dataclass(*, neighbor_repeats: int = 1) -> AnnotatedPeerUpdate:
    return AnnotatedPeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=list(_TAGS),
        prefixes=list(_PREFIXES),
        location=AnnotatedLocation(
            region="eu-central-1",
            datacenter="FRA-Equinix-FR5",
            city="Frankfurt",
            rack=42,
            latitude=50.1109,
            longitude=8.6821,
        ),
        neighbors=[
            AnnotatedNeighbor(
                peer_asn=pasn,
                router=rtr,
                latency_us=lat,
                established=est,
            )
            for _ in range(neighbor_repeats)
            for pasn, rtr, lat, est in _NEIGHBOR_SPECS
        ],
        sequence=9876543210,
    )


def build_sample_pbpy(*, neighbor_repeats: int = 1) -> peer_pb.PeerUpdate:
    return peer_pb.PeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=list(_TAGS),
        prefixes=list(_PREFIXES),
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
                peer_asn=pasn,
                router=rtr,
                latency_us=lat,
                established=est,
            )
            for _ in range(neighbor_repeats)
            for pasn, rtr, lat, est in _NEIGHBOR_SPECS
        ],
        sequence=9876543210,
    )


def build_sample_upb(*, neighbor_repeats: int = 1) -> Any:
    msg: Any = _PEER_PB2.PeerUpdate()
    msg.asn = 64512
    msg.router_id = "edge-rtr-fra01.core.backbone.net"
    msg.active = True
    msg.uptime_sec = 1849203
    msg.rssi_dbm = -62
    msg.cpu_load = 0.42875
    msg.tags.extend(_TAGS)
    msg.prefixes.extend(_PREFIXES)
    msg.location.region = "eu-central-1"
    msg.location.datacenter = "FRA-Equinix-FR5"
    msg.location.city = "Frankfurt"
    msg.location.rack = 42
    msg.location.latitude = 50.1109
    msg.location.longitude = 8.6821
    for _ in range(neighbor_repeats):
        for pasn, rtr, lat, est in _NEIGHBOR_SPECS:
            nb = msg.neighbors.add()
            nb.peer_asn = pasn
            nb.router = rtr
            nb.latency_us = lat
            nb.established = est
    msg.sequence = 9876543210
    return msg


def build_sample_msgspec(*, neighbor_repeats: int = 1) -> MsgspecPeerUpdate:
    return MsgspecPeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=list(_TAGS),
        prefixes=list(_PREFIXES),
        location=MsgspecLocation(
            region="eu-central-1",
            datacenter="FRA-Equinix-FR5",
            city="Frankfurt",
            rack=42,
            latitude=50.1109,
            longitude=8.6821,
        ),
        neighbors=[
            MsgspecNeighbor(pasn, rtr, lat, est)
            for _ in range(neighbor_repeats)
            for pasn, rtr, lat, est in _NEIGHBOR_SPECS
        ],
        sequence=9876543210,
    )


def build_sample_dict(*, neighbor_repeats: int = 1) -> dict[str, Any]:
    return {
        "asn": 64512,
        "router_id": "edge-rtr-fra01.core.backbone.net",
        "active": True,
        "uptime_sec": 1849203,
        "rssi_dbm": -62,
        "cpu_load": 0.42875,
        "tags": list(_TAGS),
        "prefixes": list(_PREFIXES),
        "location": {
            "region": "eu-central-1",
            "datacenter": "FRA-Equinix-FR5",
            "city": "Frankfurt",
            "rack": 42,
            "latitude": 50.1109,
            "longitude": 8.6821,
        },
        "neighbors": [
            {
                "peer_asn": pasn,
                "router": rtr,
                "latency_us": lat,
                "established": est,
            }
            for _ in range(neighbor_repeats)
            for pasn, rtr, lat, est in _NEIGHBOR_SPECS
        ],
        "sequence": 9876543210,
    }


def consume_typed_peer_update(m: Any) -> int:
    """Reads every scalar, string, array element, and submessage field into an int sink."""
    acc = (
        int(m.asn)
        + len(m.router_id)
        + (1 if m.active else 0)
        + int(m.uptime_sec)
        + int(m.rssi_dbm)
        + int(m.cpu_load * 1000.0)
        + int(m.sequence)
    )
    for tag in m.tags:
        acc += len(tag)
    for prefix in m.prefixes:
        acc += int(prefix)
    loc = m.location
    if loc is not None:
        acc += (
            len(loc.region)
            + len(loc.datacenter)
            + len(loc.city)
            + int(loc.rack)
            + int(loc.latitude * 1000.0)
            + int(loc.longitude * 1000.0)
        )
    for nb in m.neighbors:
        acc += int(nb.peer_asn) + len(nb.router) + int(nb.latency_us) + (1 if nb.established else 0)
    return acc


def consume_dict_peer_update(m: dict[str, Any]) -> int:
    """Reads every field from a decoded dict representation into the matching int sink."""
    acc = (
        int(m["asn"])
        + len(m["router_id"])
        + (1 if m["active"] else 0)
        + int(m["uptime_sec"])
        + int(m["rssi_dbm"])
        + int(m["cpu_load"] * 1000.0)
        + int(m["sequence"])
    )
    for tag in m["tags"]:
        acc += len(tag)
    for prefix in m["prefixes"]:
        acc += int(prefix)
    loc = m.get("location")
    if loc is not None:
        acc += (
            len(loc["region"])
            + len(loc["datacenter"])
            + len(loc["city"])
            + int(loc["rack"])
            + int(loc["latitude"] * 1000.0)
            + int(loc["longitude"] * 1000.0)
        )
    for nb in m["neighbors"]:
        acc += (
            int(nb["peer_asn"])
            + len(nb["router"])
            + int(nb["latency_us"])
            + (1 if nb["established"] else 0)
        )
    return acc


# ============================================================================
# 2. Benchmark Harness
# ============================================================================


@dataclass(slots=True)
class BenchEntry:
    name: str
    ns_per_op: float
    ops_per_sec: float
    wire_bytes: int | None = None
    highlight: bool = False
    baseline: bool = False

    def to_json(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "name": self.name,
            "nsPerOp": round(self.ns_per_op),
            "opsPerSec": round(self.ops_per_sec),
        }
        if self.wire_bytes is not None:
            obj["wireBytes"] = self.wire_bytes
        if self.highlight:
            obj["highlight"] = True
        if self.baseline:
            obj["baseline"] = True
        return obj


def detect_cpu_model() -> str:
    if sys.platform == "darwin":
        try:
            res = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            )
            val = res.stdout.strip()
            if val:
                return val
        except Exception:  # noqa: BLE001
            pass
    proc = platform.processor()
    return proc if proc else "unknown"


def run_bench(
    name: str,
    fn: Callable[[], Any],
    *,
    wire_bytes: int | None = None,
    highlight: bool = False,
    baseline: bool = False,
    warmup_ms: float = 150.0,
    sample_ms: float = 450.0,
) -> BenchEntry:
    warmup_ns = int(warmup_ms * 1_000_000)
    sample_ns = int(sample_ms * 1_000_000)

    w_start = time.perf_counter_ns()
    while time.perf_counter_ns() - w_start < warmup_ns:
        for _ in range(32):
            fn()

    gc_was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        iterations = 0
        batch = 64
        start_ns = time.perf_counter_ns()
        elapsed_ns = 0
        while elapsed_ns < sample_ns:
            for _ in range(batch):
                fn()
            iterations += batch
            elapsed_ns = time.perf_counter_ns() - start_ns
    finally:
        if gc_was_enabled:
            gc.enable()

    ns_per_op = elapsed_ns / iterations
    ops_per_sec = (iterations * 1_000_000_000.0) / elapsed_ns
    return BenchEntry(
        name=name,
        ns_per_op=ns_per_op,
        ops_per_sec=ops_per_sec,
        wire_bytes=wire_bytes,
        highlight=highlight,
        baseline=baseline,
    )


def format_table(title: str, results: list[BenchEntry]) -> list[str]:
    lines: list[str] = [f"\n### {title}\n"]
    show_bytes = any(r.wire_bytes is not None for r in results)
    baseline_entry = next((r for r in results if r.baseline), results[0])
    base_ns = baseline_entry.ns_per_op

    if show_bytes:
        lines.append(
            "| Codec / Operation | Latency (ns/op) | Throughput (ops/sec) | Wire Size (B) | vs Baseline |"
        )
        lines.append("|---|---:|---:|---:|---:|")
    else:
        lines.append("| Codec / Operation | Latency (ns/op) | Throughput (ops/sec) | vs Baseline |")
        lines.append("|---|---:|---:|---:|")

    for r in results:
        ns_str = f"{round(r.ns_per_op):,}"
        ops_str = f"{round(r.ops_per_sec):,}"
        ratio = r.ns_per_op / base_ns
        if r.baseline or abs(ratio - 1.0) < 0.03:
            rel_str = "1.00x (baseline)"
        elif ratio > 1.0:
            rel_str = f"{ratio:.2f}x slower"
        else:
            rel_str = f"{(1.0 / ratio):.2f}x faster"

        if show_bytes:
            wb_str = str(r.wire_bytes) if r.wire_bytes is not None else "-"
            lines.append(f"| {r.name} | {ns_str} ns | {ops_str} | {wb_str} | {rel_str} |")
        else:
            lines.append(f"| {r.name} | {ns_str} ns | {ops_str} | {rel_str} |")
    return lines


def main() -> None:
    smoke = "--smoke" in sys.argv[1:]
    warmup_ms = 2.0 if smoke else 150.0
    sample_ms = 5.0 if smoke else 450.0

    sample_gen = build_sample_generated()
    sample_dc = build_sample_dataclass()
    sample_pbpy = build_sample_pbpy()
    sample_upb = build_sample_upb()
    sample_msgspec = build_sample_msgspec()
    sample_dict = build_sample_dict()

    msgspec_enc = msgspec.msgpack.Encoder()
    msgspec_dec = msgspec.msgpack.Decoder(MsgspecPeerUpdate)
    msgpack_packer = msgpack.Packer(use_bin_type=True)

    omnibuf_bytes = peer_omnibuf_pb.marshal_peer_update(sample_gen)
    omnibuf_dc_bytes = omnibuf.marshal_dataclass(sample_dc)
    pbpy_bytes = sample_pbpy.to_binary()
    upb_bytes: bytes = sample_upb.SerializeToString()
    msgspec_bytes = msgspec_enc.encode(sample_msgspec)
    msgpack_bytes: bytes = msgpack_packer.pack(sample_dict)
    json_bytes = json.dumps(sample_dict).encode("utf-8")

    assert len(omnibuf_bytes) == 366, f"expected 366B OmniBuf wire size, got {len(omnibuf_bytes)}"
    assert len(omnibuf_dc_bytes) == 366, (
        f"expected 366B OmniBuf dataclass wire size, got {len(omnibuf_dc_bytes)}"
    )
    assert len(pbpy_bytes) == 341, f"expected 341B protobuf-py wire size, got {len(pbpy_bytes)}"
    assert len(upb_bytes) == 341, f"expected 341B upb wire size, got {len(upb_bytes)}"

    cpu_model = detect_cpu_model()
    py_runtime = f"Python {platform.python_version()}"
    plat_name = "darwin" if sys.platform == "darwin" else sys.platform
    arch_name = platform.machine()

    output_lines: list[str] = [
        "============================================================================",
        f"OmniBuf-Py Benchmark Suite ({py_runtime} / {plat_name}-{arch_name} / {cpu_model})",
        "Workload: 11-field PeerUpdate (366B OmniBuf, 341B Protobuf) + >16 KiB stress cases",
        "Methodology: Full decode reads all 11 fields; mutations check city and increment/grow.",
        "============================================================================",
    ]

    # 1. Full Message Encode Speed
    encode_results = [
        run_bench(
            "OmniBuf (Generated)",
            lambda: peer_omnibuf_pb.marshal_peer_update(sample_gen),
            wire_bytes=len(omnibuf_bytes),
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "OmniBuf (@dataclass)",
            lambda: omnibuf.marshal_dataclass(sample_dc),
            wire_bytes=len(omnibuf_dc_bytes),
            highlight=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "protobuf-py",
            lambda: sample_pbpy.to_binary(),
            wire_bytes=len(pbpy_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "google.protobuf (upb)",
            lambda: sample_upb.SerializeToString(),
            wire_bytes=len(upb_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgspec",
            lambda: msgspec_enc.encode(sample_msgspec),
            wire_bytes=len(msgspec_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgpack",
            lambda: msgpack_packer.pack(sample_dict),
            wire_bytes=len(msgpack_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "json (stdlib)",
            lambda: json.dumps(sample_dict).encode("utf-8"),
            wire_bytes=len(json_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
    ]
    output_lines.extend(format_table("1. Full Message Encode Speed", encode_results))

    # 2. Full Message Decode Speed (materializing and reading all 11 fields)
    def decode_omnibuf_gen() -> int:
        return consume_typed_peer_update(peer_omnibuf_pb.unmarshal_peer_update(omnibuf_bytes))

    def decode_omnibuf_dc() -> int:
        return consume_typed_peer_update(
            omnibuf.unmarshal_dataclass(omnibuf_dc_bytes, AnnotatedPeerUpdate)
        )

    def decode_pbpy() -> int:
        return consume_typed_peer_update(peer_pb.PeerUpdate.from_binary(pbpy_bytes))

    def decode_upb() -> int:
        return consume_typed_peer_update(_PEER_PB2.PeerUpdate.FromString(upb_bytes))

    def decode_msgspec() -> int:
        return consume_typed_peer_update(msgspec_dec.decode(msgspec_bytes))

    def decode_msgpack() -> int:
        return consume_dict_peer_update(msgpack.unpackb(msgpack_bytes, raw=False))

    def decode_json() -> int:
        return consume_dict_peer_update(json.loads(json_bytes))

    expected_checksum = decode_omnibuf_gen()
    assert expected_checksum > 0
    assert decode_omnibuf_dc() == expected_checksum
    assert decode_pbpy() == expected_checksum
    assert decode_upb() == expected_checksum
    assert decode_msgspec() == expected_checksum
    assert decode_msgpack() == expected_checksum
    assert decode_json() == expected_checksum

    decode_results = [
        run_bench(
            "OmniBuf (Generated)",
            decode_omnibuf_gen,
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "OmniBuf (@dataclass)",
            decode_omnibuf_dc,
            highlight=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "protobuf-py",
            decode_pbpy,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "google.protobuf (upb)",
            decode_upb,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgspec",
            decode_msgspec,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgpack",
            decode_msgpack,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "json (stdlib)",
            decode_json,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
    ]
    output_lines.extend(format_table("2. Full Message Decode Speed", decode_results))

    # 3. Read a Single Nested Field
    def lookup_omnibuf() -> str:
        view = peer_omnibuf_pb.OpaquePeerUpdate(omnibuf_bytes)
        loc = view.opaque_location()
        return loc.get_city() if loc is not None else ""

    def lookup_pbpy() -> str:
        m = peer_pb.PeerUpdate.from_binary(pbpy_bytes)
        loc = m.location
        return loc.city if loc is not None else ""

    def lookup_upb() -> str:
        m: Any = _PEER_PB2.PeerUpdate.FromString(upb_bytes)
        res: str = m.location.city
        return res

    def lookup_msgspec() -> str:
        m = msgspec_dec.decode(msgspec_bytes)
        loc = m.location
        return loc.city if loc is not None else ""

    def lookup_msgpack() -> str:
        m = msgpack.unpackb(msgpack_bytes, raw=False)
        res: str = m["location"]["city"]
        return res

    def lookup_json() -> str:
        m = json.loads(json_bytes)
        res: str = m["location"]["city"]
        return res

    assert lookup_omnibuf() == "Frankfurt"
    assert lookup_pbpy() == "Frankfurt"
    assert lookup_upb() == "Frankfurt"
    assert lookup_msgspec() == "Frankfurt"
    assert lookup_msgpack() == "Frankfurt"
    assert lookup_json() == "Frankfurt"

    lookup_results = [
        run_bench(
            "OmniBuf (Generated)",
            lookup_omnibuf,
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench("protobuf-py", lookup_pbpy, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("google.protobuf (upb)", lookup_upb, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgspec", lookup_msgspec, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgpack", lookup_msgpack, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("json (stdlib)", lookup_json, warmup_ms=warmup_ms, sample_ms=sample_ms),
    ]
    output_lines.extend(format_table("3. Read a Single Nested Field", lookup_results))

    # 4. Selective Single-Field Mutation
    def mutate_omnibuf() -> bytes:
        view = peer_omnibuf_pb.OpaquePeerUpdate(omnibuf_bytes)
        loc = view.opaque_location()
        if loc is not None and loc.get_city() == "Frankfurt":
            view.set_sequence(view.get_sequence() + 1)
        return view.marshal()

    def mutate_pbpy() -> bytes:
        m = peer_pb.PeerUpdate.from_binary(pbpy_bytes)
        if m.location is not None and m.location.city == "Frankfurt":
            m.sequence = m.sequence + 1
        return m.to_binary()

    def mutate_upb() -> bytes:
        m: Any = _PEER_PB2.PeerUpdate.FromString(upb_bytes)
        if m.location.city == "Frankfurt":
            m.sequence = m.sequence + 1
        res: bytes = m.SerializeToString()
        return res

    def mutate_msgspec() -> bytes:
        m = msgspec_dec.decode(msgspec_bytes)
        if m.location is not None and m.location.city == "Frankfurt":
            m.sequence = m.sequence + 1
        return msgspec_enc.encode(m)

    def mutate_msgpack() -> bytes:
        m = msgpack.unpackb(msgpack_bytes, raw=False)
        if m["location"]["city"] == "Frankfurt":
            m["sequence"] = m["sequence"] + 1
        res: bytes = msgpack_packer.pack(m)
        return res

    def mutate_json() -> bytes:
        m = json.loads(json_bytes)
        if m["location"]["city"] == "Frankfurt":
            m["sequence"] = m["sequence"] + 1
        return json.dumps(m).encode("utf-8")

    assert peer_omnibuf_pb.unmarshal_peer_update(mutate_omnibuf()).sequence == 9876543211
    assert peer_pb.PeerUpdate.from_binary(mutate_pbpy()).sequence == 9876543211
    assert _PEER_PB2.PeerUpdate.FromString(mutate_upb()).sequence == 9876543211
    assert msgspec_dec.decode(mutate_msgspec()).sequence == 9876543211
    assert msgpack.unpackb(mutate_msgpack(), raw=False)["sequence"] == 9876543211
    assert json.loads(mutate_json())["sequence"] == 9876543211

    mutate_results = [
        run_bench(
            "OmniBuf (Generated)",
            mutate_omnibuf,
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench("protobuf-py", mutate_pbpy, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("google.protobuf (upb)", mutate_upb, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgspec", mutate_msgspec, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgpack", mutate_msgpack, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("json (stdlib)", mutate_json, warmup_ms=warmup_ms, sample_ms=sample_ms),
    ]
    output_lines.extend(format_table("4. Selective Single-Field Mutation", mutate_results))

    # 5. Large Embedded Message Encode (>16 KiB container length expansion)
    large_dc_str = "d" * 20480
    large_rtr_str = "n" * 18432

    large_gen = build_sample_generated()
    assert large_gen.location is not None
    large_gen.location.datacenter = large_dc_str
    large_gen.neighbors[0].router = large_rtr_str

    large_dc = build_sample_dataclass()
    large_dc.location.datacenter = large_dc_str
    large_dc.neighbors[0].router = large_rtr_str

    large_pbpy = build_sample_pbpy()
    assert large_pbpy.location is not None
    large_pbpy.location.datacenter = large_dc_str
    large_pbpy.neighbors[0].router = large_rtr_str

    large_upb = build_sample_upb()
    large_upb.location.datacenter = large_dc_str
    large_upb.neighbors[0].router = large_rtr_str

    large_msgspec = build_sample_msgspec()
    assert large_msgspec.location is not None
    large_msgspec.location.datacenter = large_dc_str
    large_msgspec.neighbors[0].router = large_rtr_str

    large_dict = build_sample_dict()
    large_dict["location"]["datacenter"] = large_dc_str
    large_dict["neighbors"][0]["router"] = large_rtr_str

    large_omnibuf_bytes = peer_omnibuf_pb.marshal_peer_update(large_gen)
    large_omnibuf_dc_bytes = omnibuf.marshal_dataclass(large_dc)
    large_pbpy_bytes = large_pbpy.to_binary()
    large_upb_bytes: bytes = large_upb.SerializeToString()
    large_msgspec_bytes = msgspec_enc.encode(large_msgspec)
    large_msgpack_bytes: bytes = msgpack_packer.pack(large_dict)
    large_json_bytes = json.dumps(large_dict).encode("utf-8")

    assert len(large_omnibuf_bytes) == len(large_omnibuf_dc_bytes)
    assert len(large_pbpy_bytes) == len(large_upb_bytes)

    encode_nested_shift_results = [
        run_bench(
            "OmniBuf (Generated)",
            lambda: peer_omnibuf_pb.marshal_peer_update(large_gen),
            wire_bytes=len(large_omnibuf_bytes),
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "OmniBuf (@dataclass)",
            lambda: omnibuf.marshal_dataclass(large_dc),
            wire_bytes=len(large_omnibuf_dc_bytes),
            highlight=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "protobuf-py",
            lambda: large_pbpy.to_binary(),
            wire_bytes=len(large_pbpy_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "google.protobuf (upb)",
            lambda: large_upb.SerializeToString(),
            wire_bytes=len(large_upb_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgspec",
            lambda: msgspec_enc.encode(large_msgspec),
            wire_bytes=len(large_msgspec_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "msgpack",
            lambda: msgpack_packer.pack(large_dict),
            wire_bytes=len(large_msgpack_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench(
            "json (stdlib)",
            lambda: json.dumps(large_dict).encode("utf-8"),
            wire_bytes=len(large_json_bytes),
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
    ]
    output_lines.extend(
        format_table("5. Large Embedded Message Encode", encode_nested_shift_results)
    )

    # 6. Embedded Message Growth (32-neighbor packet, growing location.datacenter to 20 KiB)
    grown_dc = "d" * 20480
    routing_gen = build_sample_generated(neighbor_repeats=8)
    routing_pbpy = build_sample_pbpy(neighbor_repeats=8)
    routing_upb = build_sample_upb(neighbor_repeats=8)
    routing_msgspec = build_sample_msgspec(neighbor_repeats=8)
    routing_dict = build_sample_dict(neighbor_repeats=8)

    routing_omnibuf_bytes = peer_omnibuf_pb.marshal_peer_update(routing_gen)
    routing_pbpy_bytes = routing_pbpy.to_binary()
    routing_upb_bytes: bytes = routing_upb.SerializeToString()
    routing_msgspec_bytes = msgspec_enc.encode(routing_msgspec)
    routing_msgpack_bytes: bytes = msgpack_packer.pack(routing_dict)
    routing_json_bytes = json.dumps(routing_dict).encode("utf-8")

    def grow_omnibuf() -> bytes:
        view = peer_omnibuf_pb.OpaquePeerUpdate(routing_omnibuf_bytes)
        loc = view.get_location()
        if loc is not None and loc.city == "Frankfurt":
            loc.datacenter = grown_dc
            view.set_location(loc)
        return view.marshal()

    def grow_pbpy() -> bytes:
        m = peer_pb.PeerUpdate.from_binary(routing_pbpy_bytes)
        if m.location is not None and m.location.city == "Frankfurt":
            m.location.datacenter = grown_dc
        return m.to_binary()

    def grow_upb() -> bytes:
        m: Any = _PEER_PB2.PeerUpdate.FromString(routing_upb_bytes)
        if m.location.city == "Frankfurt":
            m.location.datacenter = grown_dc
        res: bytes = m.SerializeToString()
        return res

    def grow_msgspec() -> bytes:
        m = msgspec_dec.decode(routing_msgspec_bytes)
        if m.location is not None and m.location.city == "Frankfurt":
            m.location.datacenter = grown_dc
        return msgspec_enc.encode(m)

    def grow_msgpack() -> bytes:
        m = msgpack.unpackb(routing_msgpack_bytes, raw=False)
        if m["location"]["city"] == "Frankfurt":
            m["location"]["datacenter"] = grown_dc
        res: bytes = msgpack_packer.pack(m)
        return res

    def grow_json() -> bytes:
        m = json.loads(routing_json_bytes)
        if m["location"]["city"] == "Frankfurt":
            m["location"]["datacenter"] = grown_dc
        return json.dumps(m).encode("utf-8")

    grown_verify = peer_omnibuf_pb.unmarshal_peer_update(grow_omnibuf())
    assert grown_verify.location is not None
    assert grown_verify.location.datacenter == grown_dc
    assert grown_verify.location.region == "eu-central-1"
    assert len(grown_verify.neighbors) == 32
    assert grown_verify.sequence == 9876543210
    assert len(grow_pbpy()) == len(grow_upb())
    assert len(grow_msgspec()) == len(grow_msgpack())
    assert json.loads(grow_json())["location"]["datacenter"] == grown_dc

    mutate_embedded_grow_results = [
        run_bench(
            "OmniBuf (Generated)",
            grow_omnibuf,
            highlight=True,
            baseline=True,
            warmup_ms=warmup_ms,
            sample_ms=sample_ms,
        ),
        run_bench("protobuf-py", grow_pbpy, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("google.protobuf (upb)", grow_upb, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgspec", grow_msgspec, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("msgpack", grow_msgpack, warmup_ms=warmup_ms, sample_ms=sample_ms),
        run_bench("json (stdlib)", grow_json, warmup_ms=warmup_ms, sample_ms=sample_ms),
    ]
    output_lines.extend(format_table("6. Embedded Message Growth", mutate_embedded_grow_results))

    full_text = "\n".join(output_lines) + "\n"
    sys.stdout.write(full_text)

    if smoke:
        sys.stdout.write("\nSmoke run complete (testdata/benchmarks.json left untouched).\n")
        return

    repo_root = Path(__file__).resolve().parent.parent
    testdata_dir = repo_root / "testdata"
    testdata_dir.mkdir(parents=True, exist_ok=True)

    txt_path = testdata_dir / "benchmarks.txt"
    json_path = testdata_dir / "benchmarks.json"

    txt_path.write_text(full_text, encoding="utf-8")
    payload = {
        "language": "python",
        "runtime": py_runtime,
        "platform": plat_name,
        "arch": arch_name,
        "cpu": cpu_model,
        "workload": "PeerUpdate",
        "categories": [
            {
                "id": "encode",
                "title": "Full Message Encode Speed",
                "unit": "ns",
                "results": [r.to_json() for r in encode_results],
            },
            {
                "id": "decode",
                "title": "Full Message Decode Speed",
                "unit": "ns",
                "results": [r.to_json() for r in decode_results],
            },
            {
                "id": "lookup_city",
                "title": "Read a Single Nested Field",
                "unit": "ns",
                "results": [r.to_json() for r in lookup_results],
            },
            {
                "id": "mutate_sequence",
                "title": "Selective Single-Field Mutation",
                "unit": "ns",
                "results": [r.to_json() for r in mutate_results],
            },
            {
                "id": "encode_nested_shift",
                "title": "Large Embedded Message Encode",
                "unit": "ns",
                "results": [r.to_json() for r in encode_nested_shift_results],
            },
            {
                "id": "mutate_embedded_grow",
                "title": "Embedded Message Growth",
                "unit": "ns",
                "results": [r.to_json() for r in mutate_embedded_grow_results],
            },
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"\nSaved benchmark results to {txt_path} and {json_path}\n")


if __name__ == "__main__":
    main()
