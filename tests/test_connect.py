"""Unit and connect-python integration tests for `omnibuf.connect`."""

from __future__ import annotations

import subprocess
import sys

import pytest
from connectrpc._codec import Codec as ConnectCodecProtocol

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
from omnibuf.connect import (
    CODEC_NAME,
    SELF_DESCRIBING_CODEC_NAME,
    OmniBufConnectCodec,
)


@omnibuf_message("ConnectPeerEvent")
class ConnectPeerEvent:
    asn: Uint32 = omnibuf_field(1, default=0)
    router_id: str = omnibuf_field(2, default="")
    rssi_dbm: Sint32 = omnibuf_field(3, default=0)
    sequence: Uint64 = omnibuf_field(4, default=0)
    tags: list[str] = omnibuf_field(5, default_factory=list)
    labels: dict[str, str] = omnibuf_field(6, default_factory=dict)


@omnibuf_message("ConnectNestedNode")
class ConnectNestedNode:
    label: str = omnibuf_field(1, default="")
    child: ConnectNestedNode | None = omnibuf_field(2, default=None)


def test_constants_and_detached_import() -> None:
    assert CODEC_NAME == "omnibuf"
    assert SELF_DESCRIBING_CODEC_NAME == "x-omnibuf"
    assert "connect" not in omnibuf.__all__

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, omnibuf; assert 'omnibuf.connect' not in sys.modules; assert 'connectrpc' not in sys.modules",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_connect_python_codec_protocol_round_trip() -> None:
    def run_through_connect_codec(
        codec: ConnectCodecProtocol[ConnectPeerEvent, ConnectPeerEvent],
        msg: ConnectPeerEvent,
    ) -> tuple[str, bytes, ConnectPeerEvent]:
        wire = codec.encode(msg)
        decoded = codec.decode(wire, ConnectPeerEvent())
        return codec.name(), wire, decoded

    compact = OmniBufConnectCodec()
    assert not compact.self_describing
    assert not compact.deterministic

    original = ConnectPeerEvent(
        asn=65001,
        router_id="iad-01",
        rssi_dbm=-48,
        sequence=9,
        tags=["bgp", "ipv6"],
        labels={"site": "iad"},
    )
    name, wire, decoded = run_through_connect_codec(compact, original)
    assert name == CODEC_NAME
    assert read_field0_schema_meta(wire) is None
    assert decoded == original
    assert compact.decode(memoryview(wire), ConnectPeerEvent) == original


def test_connect_codec_self_describing_and_deterministic() -> None:
    sd = OmniBufConnectCodec(self_describing=True, deterministic=True)
    assert sd.name() == SELF_DESCRIBING_CODEC_NAME
    assert sd.self_describing
    assert sd.deterministic

    sd_wire_a = sd.encode(ConnectPeerEvent(asn=7, labels={"z": "1", "a": "2"}))
    sd_wire_b = sd.encode(ConnectPeerEvent(asn=7, labels={"a": "2", "z": "1"}))
    assert sd_wire_a == sd_wire_b

    meta = read_field0_schema_meta(sd_wire_a)
    assert meta is not None
    assert meta.type_name == "ConnectPeerEvent"
    assert sd.decode(sd_wire_a, ConnectPeerEvent) == ConnectPeerEvent(
        asn=7, labels={"a": "2", "z": "1"}
    )


def test_connect_codec_limits() -> None:
    codec = OmniBufConnectCodec(max_depth=1, max_elements=2)
    with pytest.raises(OmniBufDecodeError):
        codec.decode(codec.encode(ConnectPeerEvent(tags=["x", "y", "z"])), ConnectPeerEvent)

    nested = ConnectNestedNode(
        label="root",
        child=ConnectNestedNode(label="mid", child=ConnectNestedNode(label="leaf")),
    )
    with pytest.raises(OmniBufDecodeError):
        codec.decode(codec.encode(nested), ConnectNestedNode)
