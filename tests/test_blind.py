"""Unit tests for Field #0 SchemaMeta and blind schema-less decoding."""

from __future__ import annotations

import base64
import json
import math

import pytest

from omnibuf import (
    Encoder,
    OmniBufDecodeError,
    SchemaMeta,
    decode_blind,
    decode_blind_json,
    encode_field0_schema_meta,
    read_field0_schema_meta,
)


def test_late_field0_two_pass_and_concatenated_submessages() -> None:
    enc1 = Encoder()
    enc1.begin_submsg(1)
    enc1.write_string(1, "edge01")
    enc1.end_submsg()

    child_meta = SchemaMeta(type_name="Endpoint", fields={1: "host", 2: "port"})
    root_meta = SchemaMeta(
        type_name="Envelope",
        fields={1: "endpoint", 2: "seq"},
        children={1: child_meta},
    )

    enc2 = Encoder()
    enc2.begin_submsg(1)
    enc2.write_uint32(2, 443)
    enc2.end_submsg()
    enc2.write_uint(2, (1 << 55) + 9)

    # Append root Field #0 at the very end of the concatenated packet
    packet = enc1.finish() + enc2.finish() + encode_field0_schema_meta(root_meta)

    parsed_meta = read_field0_schema_meta(packet)
    assert parsed_meta is not None
    assert parsed_meta.type_name == "Envelope"
    assert parsed_meta.children[1].fields == {1: "host", 2: "port"}

    blind = decode_blind(packet)
    assert blind == {
        "endpoint": {"host": "edge01", "port": 443},
        "seq": (1 << 55) + 9,
    }


def test_blind_json_float32_shortest_base64_and_exact_int64() -> None:
    meta = SchemaMeta(
        type_name="Telemetry",
        fields={1: "lat", 2: "raw", 3: "big_u64", 4: "big_s64"},
    )
    enc = Encoder()
    enc.write_raw(encode_field0_schema_meta(meta))
    enc.write_float32(1, 50.1109)
    enc.write_bytes(2, b"\x00\x01\xfe\xff")
    enc.write_uint(3, 18446744073709551615)
    enc.write_sint(4, -9223372036854775808)

    raw_json = decode_blind_json(enc.finish())
    assert '"lat":50.1109' in raw_json
    assert '"big_u64":18446744073709551615' in raw_json
    assert '"big_s64":-9223372036854775808' in raw_json
    parsed = json.loads(raw_json)
    assert base64.b64decode(parsed["raw"]) == b"\x00\x01\xfe\xff"


def test_blind_json_nan_disallowed_by_default() -> None:
    enc = Encoder()
    enc.write_float64(1, math.nan)
    pkt = enc.finish()

    decoded = decode_blind(pkt)
    assert math.isnan(decoded["field_1"])

    with pytest.raises(ValueError):
        decode_blind_json(pkt, allow_nan=False)


def test_blind_rejects_wire_shape_conflict_and_name_collision() -> None:
    e1 = Encoder()
    e1.write_uint32(1, 10)
    e2 = Encoder()
    e2.write_string(1, "bad")
    with pytest.raises(OmniBufDecodeError):
        decode_blind(e1.finish() + e2.finish())

    bad_meta = SchemaMeta(type_name="Dup", fields={1: "dup", 2: "dup"})
    e3 = Encoder()
    e3.write_raw(encode_field0_schema_meta(bad_meta))
    e3.write_uint32(1, 1)
    e3.write_uint32(2, 2)
    with pytest.raises(OmniBufDecodeError):
        decode_blind(e3.finish())
