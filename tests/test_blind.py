"""Unit tests for Field #0 SchemaMeta and blind schema-less decoding."""

from __future__ import annotations

import base64
import json
import math

import pytest

from omnibuf import (
    WIRE_MAP,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Encoder,
    OmniBufDecodeError,
    OmniBufEncodeError,
    SchemaMeta,
    decode_blind,
    decode_blind_json,
    decode_schema_meta,
    encode_field0_schema_meta,
    read_field0_schema_meta,
    validate_message,
)
from omnibuf import wire as omnibuf_wire
from omnibuf.wire import encode_tag, encode_varint


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

    with pytest.raises(OmniBufEncodeError):
        decode_blind_json(pkt, allow_nan=False)
    assert decode_blind_json(pkt, allow_nan=True) == '{"field_1":NaN}'
    assert decode_blind_json(pkt, allow_nan=False, fallback_on_non_finite=True) == "{}"


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


def test_read_field0_schema_meta_raises_on_corrupt_field0() -> None:
    """read_field0_schema_meta must raise OmniBufDecodeError on corrupt Field #0 instead of None."""
    corrupt_field0 = bytes([0x19, 0x05, 0x21, 0x02])
    pkt = corrupt_field0 + encode_tag(65536, WIRE_UINT) + encode_varint(42)

    with pytest.raises(OmniBufDecodeError):
        validate_message(pkt)

    with pytest.raises(OmniBufDecodeError):
        read_field0_schema_meta(pkt)


def test_field0_unknown_empty_submsg_depth_limit() -> None:
    """Empty unknown WireSubMsg inside Field #0 exceeding MAX_NESTING_DEPTH must be rejected."""
    # Build 32 nested empty submessages inside unknown field #99 of Field #0 (depth 1 + 32 = 33 > 32)
    payload = b""
    for _ in range(omnibuf_wire.MAX_NESTING_DEPTH):
        payload = encode_tag(99, WIRE_SUB_MSG) + encode_varint(len(payload)) + payload
    pkt = encode_tag(0, WIRE_SUB_MSG) + encode_varint(len(payload)) + payload
    with pytest.raises(OmniBufDecodeError):
        validate_message(pkt)


def test_schema_meta_duplicate_map_key_overwrites_while_separate_blocks_merge() -> None:
    child_first = Encoder()
    child_first.write_string(1, "First")
    child_first.begin_map(2, WIRE_UINT, WIRE_STRING, 1)
    child_first.write_varint(1)
    child_first.write_varint(3)
    child_first.write_raw(b"old")
    child_first.end_map()
    b_first = child_first.finish()

    child_second = Encoder()
    child_second.write_string(1, "Second")
    child_second.begin_map(2, WIRE_UINT, WIRE_STRING, 1)
    child_second.write_varint(2)
    child_second.write_varint(3)
    child_second.write_raw(b"new")
    child_second.end_map()
    b_second = child_second.finish()

    # Single WireMap on field 3 with duplicate key 1: second entry MUST overwrite first (not merge)
    dup_map_body = bytearray()
    dup_map_body.append(WIRE_UINT)
    dup_map_body.append(WIRE_SUB_MSG)
    dup_map_body.extend(encode_varint(2))  # 2 entries, both key=1
    dup_map_body.extend(encode_varint(1))
    dup_map_body.extend(encode_varint(len(b_first)))
    dup_map_body.extend(b_first)
    dup_map_body.extend(encode_varint(1))
    dup_map_body.extend(encode_varint(len(b_second)))
    dup_map_body.extend(b_second)

    meta_wire = encode_tag(3, WIRE_MAP) + encode_varint(len(dup_map_body)) + bytes(dup_map_body)
    parsed_single = decode_schema_meta(meta_wire)
    assert parsed_single.children[1].type_name == "Second"
    assert parsed_single.children[1].fields == {2: "new"}

    # Separate Field #0 blocks: recursive merge keeps field 1 ("old") AND field 2 ("new")
    m1 = SchemaMeta(
        type_name="Root", children={1: SchemaMeta(type_name="First", fields={1: "old"})}
    )
    m2 = SchemaMeta(
        type_name="Root", children={1: SchemaMeta(type_name="Second", fields={2: "new"})}
    )
    enc_pkt = Encoder()
    enc_pkt.write_raw(encode_field0_schema_meta(m1))
    enc_pkt.write_raw(encode_field0_schema_meta(m2))
    enc_pkt.begin_submsg(1)
    enc_pkt.write_uint32(1, 10)
    enc_pkt.write_uint32(2, 20)
    enc_pkt.end_submsg()
    assert decode_blind(enc_pkt.finish()) == {"field_1": {"old": 10, "new": 20}}


def test_inner_empty_field0_name_clears_inherited_name_and_blind_json_neg_zero() -> None:
    outer_meta = SchemaMeta(
        type_name="Outer",
        fields={1: "sub"},
        children={1: SchemaMeta(type_name="Sub", fields={1: "inherited_x"})},
    )
    inner_clear = SchemaMeta(type_name="Sub", fields={1: ""})

    enc = Encoder()
    enc.write_raw(encode_field0_schema_meta(outer_meta))
    enc.begin_submsg(1)
    enc.write_raw(encode_field0_schema_meta(inner_clear))
    enc.write_uint32(1, 55)
    enc.end_submsg()
    assert decode_blind(enc.finish()) == {"sub": {"field_1": 55}}

    # Verify -0.0 preserved in decode_blind_json for both allow_nan=False and allow_nan=True
    enc_nz = Encoder()
    enc_nz.write_float32(1, -0.0)
    enc_nz.write_float64(2, -0.0)
    nz_pkt = enc_nz.finish()
    assert decode_blind_json(nz_pkt, allow_nan=False) == '{"field_1":-0.0,"field_2":-0.0}'
    assert decode_blind_json(nz_pkt, allow_nan=True) == '{"field_1":-0.0,"field_2":-0.0}'
