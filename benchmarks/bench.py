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

# ============================================================================
# 1. Canonical SamplePeerUpdate Workload (11 fields, OmniBuf=366B, Protobuf=341B)
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


def build_sample_generated() -> peer_omnibuf_pb.PeerUpdate:
    return peer_omnibuf_pb.PeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=["tier1", "ebgp", "eu-central", "ixp-de-cix"],
        prefixes=[167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040],
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
                peer_asn=3356,
                router="ae0.fra1.level3.net",
                latency_us=850,
                established=True,
            ),
            peer_omnibuf_pb.Neighbor(
                peer_asn=1299,
                router="ffm-b5-link.telia.net",
                latency_us=920,
                established=True,
            ),
            peer_omnibuf_pb.Neighbor(
                peer_asn=174,
                router="be2040.ccr41.fra03.atlas.cogentco.com",
                latency_us=1120,
                established=True,
            ),
            peer_omnibuf_pb.Neighbor(
                peer_asn=2914,
                router="ae-12.r24.frnkge08.de.bb.gin.ntt.net",
                latency_us=980,
                established=False,
            ),
        ],
        sequence=9876543210,
    )


def build_sample_dataclass() -> AnnotatedPeerUpdate:
    return AnnotatedPeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=["tier1", "ebgp", "eu-central", "ixp-de-cix"],
        prefixes=[167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040],
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
                peer_asn=3356,
                router="ae0.fra1.level3.net",
                latency_us=850,
                established=True,
            ),
            AnnotatedNeighbor(
                peer_asn=1299,
                router="ffm-b5-link.telia.net",
                latency_us=920,
                established=True,
            ),
            AnnotatedNeighbor(
                peer_asn=174,
                router="be2040.ccr41.fra03.atlas.cogentco.com",
                latency_us=1120,
                established=True,
            ),
            AnnotatedNeighbor(
                peer_asn=2914,
                router="ae-12.r24.frnkge08.de.bb.gin.ntt.net",
                latency_us=980,
                established=False,
            ),
        ],
        sequence=9876543210,
    )


def build_sample_pbpy() -> peer_pb.PeerUpdate:
    return peer_pb.PeerUpdate(
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


def build_sample_upb() -> Any:
    msg: Any = _PEER_PB2.PeerUpdate()
    msg.asn = 64512
    msg.router_id = "edge-rtr-fra01.core.backbone.net"
    msg.active = True
    msg.uptime_sec = 1849203
    msg.rssi_dbm = -62
    msg.cpu_load = 0.42875
    msg.tags.extend(["tier1", "ebgp", "eu-central", "ixp-de-cix"])
    msg.prefixes.extend([167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040])
    msg.location.region = "eu-central-1"
    msg.location.datacenter = "FRA-Equinix-FR5"
    msg.location.city = "Frankfurt"
    msg.location.rack = 42
    msg.location.latitude = 50.1109
    msg.location.longitude = 8.6821
    for pasn, rtr, lat, est in (
        (3356, "ae0.fra1.level3.net", 850, True),
        (1299, "ffm-b5-link.telia.net", 920, True),
        (174, "be2040.ccr41.fra03.atlas.cogentco.com", 1120, True),
        (2914, "ae-12.r24.frnkge08.de.bb.gin.ntt.net", 980, False),
    ):
        nb = msg.neighbors.add()
        nb.peer_asn = pasn
        nb.router = rtr
        nb.latency_us = lat
        nb.established = est
    msg.sequence = 9876543210
    return msg


def build_sample_msgspec() -> MsgspecPeerUpdate:
    return MsgspecPeerUpdate(
        asn=64512,
        router_id="edge-rtr-fra01.core.backbone.net",
        active=True,
        uptime_sec=1849203,
        rssi_dbm=-62,
        cpu_load=0.42875,
        tags=["tier1", "ebgp", "eu-central", "ixp-de-cix"],
        prefixes=[167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040],
        location=MsgspecLocation(
            region="eu-central-1",
            datacenter="FRA-Equinix-FR5",
            city="Frankfurt",
            rack=42,
            latitude=50.1109,
            longitude=8.6821,
        ),
        neighbors=[
            MsgspecNeighbor(3356, "ae0.fra1.level3.net", 850, True),
            MsgspecNeighbor(1299, "ffm-b5-link.telia.net", 920, True),
            MsgspecNeighbor(174, "be2040.ccr41.fra03.atlas.cogentco.com", 1120, True),
            MsgspecNeighbor(2914, "ae-12.r24.frnkge08.de.bb.gin.ntt.net", 980, False),
        ],
        sequence=9876543210,
    )


def build_sample_dict() -> dict[str, Any]:
    return {
        "asn": 64512,
        "router_id": "edge-rtr-fra01.core.backbone.net",
        "active": True,
        "uptime_sec": 1849203,
        "rssi_dbm": -62,
        "cpu_load": 0.42875,
        "tags": ["tier1", "ebgp", "eu-central", "ixp-de-cix"],
        "prefixes": [167772160, 172032000, 3232235520, 2886729728, 134744072, 134743040],
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
                "peer_asn": 3356,
                "router": "ae0.fra1.level3.net",
                "latency_us": 850,
                "established": True,
            },
            {
                "peer_asn": 1299,
                "router": "ffm-b5-link.telia.net",
                "latency_us": 920,
                "established": True,
            },
            {
                "peer_asn": 174,
                "router": "be2040.ccr41.fra03.atlas.cogentco.com",
                "latency_us": 1120,
                "established": True,
            },
            {
                "peer_asn": 2914,
                "router": "ae-12.r24.frnkge08.de.bb.gin.ntt.net",
                "latency_us": 980,
                "established": False,
            },
        ],
        "sequence": 9876543210,
    }


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
        for _ in range(100):
            fn()

    gc_was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        iterations = 0
        batch = 250
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
    sample_gen = build_sample_generated()
    sample_dc = build_sample_dataclass()
    sample_pbpy = build_sample_pbpy()
    sample_upb = build_sample_upb()
    sample_msgspec = build_sample_msgspec()
    sample_dict = build_sample_dict()

    omnibuf_bytes = peer_omnibuf_pb.marshal_peer_update(sample_gen)
    omnibuf_dc_bytes = omnibuf.marshal(sample_dc)
    pbpy_bytes = sample_pbpy.to_binary()
    upb_bytes: bytes = sample_upb.SerializeToString()
    msgspec_enc = msgspec.msgpack.Encoder()
    msgspec_dec = msgspec.msgpack.Decoder(MsgspecPeerUpdate)
    msgspec_bytes = msgspec_enc.encode(sample_msgspec)
    msgpack_bytes: bytes = msgpack.packb(sample_dict, use_bin_type=True)
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
        "Workload: Canonical PeerUpdate (nested submessage, 4 neighbors, arrays, scalars)",
        "============================================================================",
    ]

    # 1. Full Message Encode
    encode_results = [
        run_bench(
            "OmniBuf (Generated)",
            lambda: peer_omnibuf_pb.marshal_peer_update(sample_gen),
            wire_bytes=len(omnibuf_bytes),
            highlight=True,
            baseline=True,
        ),
        run_bench(
            "OmniBuf (@dataclass)",
            lambda: omnibuf.marshal_dataclass(sample_dc),
            wire_bytes=len(omnibuf_dc_bytes),
            highlight=True,
        ),
        run_bench(
            "protobuf-py",
            lambda: sample_pbpy.to_binary(),
            wire_bytes=len(pbpy_bytes),
        ),
        run_bench(
            "google.protobuf (upb)",
            lambda: sample_upb.SerializeToString(),
            wire_bytes=len(upb_bytes),
        ),
        run_bench(
            "msgspec",
            lambda: msgspec_enc.encode(sample_msgspec),
            wire_bytes=len(msgspec_bytes),
        ),
        run_bench(
            "msgpack",
            lambda: msgpack.packb(sample_dict, use_bin_type=True),
            wire_bytes=len(msgpack_bytes),
        ),
        run_bench(
            "json (stdlib)",
            lambda: json.dumps(sample_dict).encode("utf-8"),
            wire_bytes=len(json_bytes),
        ),
    ]
    output_lines.extend(format_table("1. Full Message Encode Speed (PeerUpdate)", encode_results))

    # 2. Full Message Decode
    decode_results = [
        run_bench(
            "OmniBuf (Generated)",
            lambda: peer_omnibuf_pb.unmarshal_peer_update(omnibuf_bytes),
            highlight=True,
            baseline=True,
        ),
        run_bench(
            "OmniBuf (@dataclass)",
            lambda: omnibuf.unmarshal_dataclass(omnibuf_dc_bytes, AnnotatedPeerUpdate),
            highlight=True,
        ),
        run_bench(
            "protobuf-py",
            lambda: peer_pb.PeerUpdate.from_binary(pbpy_bytes),
        ),
        run_bench(
            "google.protobuf (upb)",
            lambda: _PEER_PB2.PeerUpdate.FromString(upb_bytes),
        ),
        run_bench(
            "msgspec",
            lambda: msgspec_dec.decode(msgspec_bytes),
        ),
        run_bench(
            "msgpack",
            lambda: msgpack.unpackb(msgpack_bytes, raw=False),
        ),
        run_bench(
            "json (stdlib)",
            lambda: json.loads(json_bytes.decode("utf-8")),
        ),
    ]
    output_lines.extend(format_table("2. Full Message Decode Speed (PeerUpdate)", decode_results))

    # 3. Read a Single Nested Field (peer.location.city)
    def lookup_omnibuf() -> str:
        view = peer_omnibuf_pb.OpaquePeerUpdate(omnibuf_bytes)
        loc = view.opaque_location()
        assert loc is not None
        city = loc.get_city()
        assert len(city) == 9
        return city

    def lookup_pbpy() -> str:
        m = peer_pb.PeerUpdate.from_binary(pbpy_bytes)
        assert m.location is not None
        return m.location.city

    def lookup_upb() -> str:
        m: Any = _PEER_PB2.PeerUpdate.FromString(upb_bytes)
        res: str = m.location.city
        return res

    def lookup_msgspec() -> str:
        m = msgspec_dec.decode(msgspec_bytes)
        assert m.location is not None
        return m.location.city

    def lookup_msgpack() -> str:
        m = msgpack.unpackb(msgpack_bytes, raw=False)
        res: str = m["location"]["city"]
        return res

    def lookup_json() -> str:
        m = json.loads(json_bytes.decode("utf-8"))
        res: str = m["location"]["city"]
        return res

    assert lookup_omnibuf() == "Frankfurt"
    assert lookup_pbpy() == "Frankfurt"
    assert lookup_upb() == "Frankfurt"

    lookup_results = [
        run_bench("OmniBuf (Generated)", lookup_omnibuf, highlight=True, baseline=True),
        run_bench("protobuf-py", lookup_pbpy),
        run_bench("google.protobuf (upb)", lookup_upb),
        run_bench("msgspec", lookup_msgspec),
        run_bench("msgpack", lookup_msgpack),
        run_bench("json (stdlib)", lookup_json),
    ]
    output_lines.extend(
        format_table("3. Read a Single Nested Field (peer.location.city)", lookup_results)
    )

    # 4. Selective Single-Field Mutation (peer.sequence)
    def mutate_omnibuf() -> bytes:
        view = peer_omnibuf_pb.OpaquePeerUpdate(omnibuf_bytes)
        view.set_sequence(9876543211)
        return view.marshal()

    def mutate_pbpy() -> bytes:
        m = peer_pb.PeerUpdate.from_binary(pbpy_bytes)
        m.sequence = 9876543211
        return m.to_binary()

    def mutate_upb() -> bytes:
        m: Any = _PEER_PB2.PeerUpdate.FromString(upb_bytes)
        m.sequence = 9876543211
        res: bytes = m.SerializeToString()
        return res

    def mutate_msgspec() -> bytes:
        m = msgspec_dec.decode(msgspec_bytes)
        m.sequence = 9876543211
        return msgspec_enc.encode(m)

    def mutate_msgpack() -> bytes:
        m = msgpack.unpackb(msgpack_bytes, raw=False)
        m["sequence"] = 9876543211
        res: bytes = msgpack.packb(m, use_bin_type=True)
        return res

    def mutate_json() -> bytes:
        m = json.loads(json_bytes.decode("utf-8"))
        m["sequence"] = 9876543211
        return json.dumps(m).encode("utf-8")

    spliced_verify = peer_omnibuf_pb.unmarshal_peer_update(mutate_omnibuf())
    assert spliced_verify.sequence == 9876543211

    mutate_results = [
        run_bench("OmniBuf (Generated)", mutate_omnibuf, highlight=True, baseline=True),
        run_bench("protobuf-py", mutate_pbpy),
        run_bench("google.protobuf (upb)", mutate_upb),
        run_bench("msgspec", mutate_msgspec),
        run_bench("msgpack", mutate_msgpack),
        run_bench("json (stdlib)", mutate_json),
    ]
    output_lines.extend(
        format_table("4. Selective Single-Field Mutation (peer.sequence)", mutate_results)
    )

    full_text = "\n".join(output_lines) + "\n"
    sys.stdout.write(full_text)

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
                "title": "Full Message Encode Speed (PeerUpdate)",
                "unit": "ns",
                "results": [r.to_json() for r in encode_results],
            },
            {
                "id": "decode",
                "title": "Full Message Decode Speed (PeerUpdate)",
                "unit": "ns",
                "results": [r.to_json() for r in decode_results],
            },
            {
                "id": "lookup_city",
                "title": "Read a Single Nested Field (peer.location.city)",
                "unit": "ns",
                "results": [r.to_json() for r in lookup_results],
            },
            {
                "id": "mutate_sequence",
                "title": "Selective Single-Field Mutation (peer.sequence)",
                "unit": "ns",
                "results": [r.to_json() for r in mutate_results],
            },
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"\nSaved benchmark results to {txt_path} and {json_path}\n")


if __name__ == "__main__":
    main()
