"""Unit and real grpcio loopback integration tests for `omnibuf.grpc`."""

from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import grpc
import pytest

import omnibuf
from omnibuf import (
    OmniBufDecodeError,
    Sint32,
    Uint32,
    Uint64,
    omnibuf_field,
    omnibuf_message,
    read_field0_schema_meta,
)
from omnibuf.grpc import (
    CODEC_NAME,
    CONTENT_TYPE_GRPC,
    SELF_DESCRIBING_CODEC_NAME,
    grpc_deserializer,
    grpc_serializer,
)


@omnibuf_message("GrpcPeerRequest")
class GrpcPeerRequest:
    asn: Uint32 = omnibuf_field(1, default=0)
    router_id: str = omnibuf_field(2, default="")
    rssi_dbm: Sint32 = omnibuf_field(3, default=0)
    sequence: Uint64 = omnibuf_field(4, default=0)
    tags: list[str] = omnibuf_field(5, default_factory=list)
    labels: dict[str, str] = omnibuf_field(6, default_factory=dict)


@omnibuf_message("GrpcPeerResponse")
class GrpcPeerResponse:
    accepted: bool = omnibuf_field(1, default=False)
    echo_router: str = omnibuf_field(2, default="")
    adjusted_dbm: Sint32 = omnibuf_field(3, default=0)
    labels: dict[str, str] = omnibuf_field(4, default_factory=dict)


@omnibuf_message("GrpcNestedNode")
class GrpcNestedNode:
    label: str = omnibuf_field(1, default="")
    child: GrpcNestedNode | None = omnibuf_field(2, default=None)


def test_constants_and_detached_import() -> None:
    assert CODEC_NAME == "omnibuf"
    assert SELF_DESCRIBING_CODEC_NAME == "x-omnibuf"
    assert CONTENT_TYPE_GRPC == "application/grpc+omnibuf"
    assert "grpc" not in omnibuf.__all__

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, omnibuf; assert 'omnibuf.grpc' not in sys.modules; assert 'grpc' not in sys.modules",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_grpc_serializer_self_describing_and_deterministic() -> None:
    serialize = grpc_serializer(deterministic=True, self_describing=True)
    deserialize = grpc_deserializer(GrpcPeerRequest)

    msg_a = GrpcPeerRequest(asn=100, labels={"b": "2", "a": "1", "c": "3"})
    msg_b = GrpcPeerRequest(asn=100, labels={"c": "3", "a": "1", "b": "2"})

    wire_a = serialize(msg_a)
    wire_b = serialize(msg_b)
    assert wire_a == wire_b

    meta = read_field0_schema_meta(wire_a)
    assert meta is not None
    assert meta.type_name == "GrpcPeerRequest"
    assert meta.fields[1] == "asn"
    assert deserialize(wire_a) == msg_a


def test_grpc_deserializer_limits_and_errors() -> None:
    serialize = grpc_serializer()

    many_tags = GrpcPeerRequest(tags=["a", "b", "c", "d"])
    wire_tags = serialize(many_tags)
    with pytest.raises(OmniBufDecodeError):
        grpc_deserializer(GrpcPeerRequest, max_elements=2)(wire_tags)
    assert grpc_deserializer(GrpcPeerRequest, max_elements=4)(wire_tags) == many_tags

    nested = GrpcNestedNode(
        label="root",
        child=GrpcNestedNode(label="mid", child=GrpcNestedNode(label="leaf")),
    )
    wire_nested = serialize(nested)
    with pytest.raises(OmniBufDecodeError):
        grpc_deserializer(GrpcNestedNode, max_depth=1)(wire_nested)
    assert grpc_deserializer(GrpcNestedNode, max_depth=4)(wire_nested) == nested

    with pytest.raises(OmniBufDecodeError):
        grpc_deserializer(GrpcPeerRequest)(b"\x00")


def test_grpcio_loopback_unary_rpc_integration() -> None:
    def handle_ping(
        request: GrpcPeerRequest,
        context: grpc.ServicerContext,
    ) -> GrpcPeerResponse:
        del context
        return GrpcPeerResponse(
            accepted=request.asn == 64512,
            echo_router=f"{request.router_id}:ack",
            adjusted_dbm=request.rssi_dbm + 3,
            labels={"site": request.labels.get("site", ""), "tags": ",".join(request.tags)},
        )

    handler = grpc.method_handlers_generic_handler(
        "omnibuf.test.PeerService",
        {
            "Ping": grpc.unary_unary_rpc_method_handler(
                handle_ping,
                request_deserializer=grpc_deserializer(GrpcPeerRequest),
                response_serializer=grpc_serializer(deterministic=True, self_describing=True),
            ),
        },
    )

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((handler,))
    port = server.add_insecure_port("127.0.0.1:0")
    assert port > 0
    server.start()
    try:
        with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
            ping = channel.unary_unary(
                "/omnibuf.test.PeerService/Ping",
                request_serializer=grpc_serializer(),
                response_deserializer=grpc_deserializer(GrpcPeerResponse),
            )
            req = GrpcPeerRequest(
                asn=64512,
                router_id="edge-rtr-fra01",
                rssi_dbm=-62,
                sequence=7,
                tags=["bgp", "ipv6"],
                labels={"site": "fra"},
            )
            resp: GrpcPeerResponse = ping(req, timeout=5.0)
            assert resp == GrpcPeerResponse(
                accepted=True,
                echo_router="edge-rtr-fra01:ack",
                adjusted_dbm=-59,
                labels={"site": "fra", "tags": "bgp,ipv6"},
            )
    finally:
        server.stop(grace=None)
