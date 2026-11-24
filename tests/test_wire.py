"""Unit tests for OmniBuf v1 DRAFT-1 Prefix-Varint, ZigZag, UTF-8, float32, locate_field, and splice_fields."""

from __future__ import annotations

import math
import struct

import pytest
from google.protobuf import descriptor_pb2

import omnibuf
from omnibuf import wire as omnibuf_wire
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb
from omnibuf.wire import (
    INT32_MAX,
    INT32_MIN,
    INT64_MAX,
    INT64_MIN,
    MAX_FIELD_NUMBER,
    TZCNT_WIDTH_TABLE,
    UINT64_MAX,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    OmniBufDecodeError,
    OmniBufEncodeError,
    SpliceField,
    append_varint,
    decode_tag,
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    encode_tag,
    encode_utf8_strict,
    encode_varint,
    encode_zigzag,
    encode_zigzag32,
    locate_field,
    round_float32_shortest,
    splice_fields,
    validate_message,
    validate_value,
    varint_size,
)


@pytest.mark.parametrize(
    ("value", "expected_width"),
    [
        (0, 1),
        (1, 1),
        (127, 1),
        (128, 2),
        (16_383, 2),
        (16_384, 4),
        (536_870_911, 4),
        (536_870_912, 9),
        (1 << 40, 9),
        (UINT64_MAX, 9),
    ],
)
def test_prefix_varint_roundtrip_and_widths(value: int, expected_width: int) -> None:
    raw = encode_varint(value)
    assert len(raw) == expected_width
    assert varint_size(value) == expected_width
    assert TZCNT_WIDTH_TABLE[raw[0]] == expected_width
    decoded, read_len = decode_varint(raw)
    assert read_len == expected_width
    assert decoded == value


@pytest.mark.parametrize("marker", [0x08, 0x10, 0x18, 0x20, 0x80, 0xF8])
def test_prefix_varint_rejects_reserved_markers(marker: int) -> None:
    assert (marker & 0x07) == 0 and marker != 0
    assert TZCNT_WIDTH_TABLE[marker] == 0
    payload = bytes([marker]) + b"\x00" * 10
    val, width = decode_varint(payload)
    assert (val, width) == (0, 0)


def test_prefix_varint_bounds_errors() -> None:
    with pytest.raises(OmniBufEncodeError):
        encode_varint(-1)
    with pytest.raises(OmniBufEncodeError):
        encode_varint(UINT64_MAX + 1)


@pytest.mark.parametrize("n32", [0, -1, 1, -64, 63, -65, 64, INT32_MIN, INT32_MAX])
def test_zigzag32_roundtrip(n32: int) -> None:
    u = encode_zigzag32(n32)
    assert 0 <= u <= 0xFFFF_FFFF
    assert decode_zigzag32(u) == n32


@pytest.mark.parametrize("n64", [0, -1, 1, -64, 63, INT32_MIN - 1, INT64_MIN, INT64_MAX])
def test_zigzag64_roundtrip(n64: int) -> None:
    u = encode_zigzag(n64)
    assert 0 <= u <= UINT64_MAX
    assert decode_zigzag(u) == n64


def test_zigzag_range_errors() -> None:
    with pytest.raises(OmniBufEncodeError):
        encode_zigzag32(INT32_MIN - 1)
    with pytest.raises(OmniBufEncodeError):
        encode_zigzag32(INT32_MAX + 1)
    with pytest.raises(OmniBufEncodeError):
        encode_zigzag(INT64_MIN - 1)
    with pytest.raises(OmniBufEncodeError):
        encode_zigzag(INT64_MAX + 1)


def test_tag_validation() -> None:
    t = encode_tag(7, WIRE_STRING)
    fnum, wt, n = decode_tag(t)
    assert (fnum, wt, n) == (7, WIRE_STRING, 1)

    f0 = encode_tag(0, WIRE_SUB_MSG)
    assert f0 == b"\x19"

    with pytest.raises(OmniBufEncodeError):
        encode_tag(0, WIRE_UINT)
    with pytest.raises(OmniBufEncodeError):
        encode_tag(MAX_FIELD_NUMBER + 1, WIRE_UINT)


def test_strict_utf8_rejects_surrogates_and_invalid_bytes() -> None:
    with pytest.raises(OmniBufEncodeError):
        encode_utf8_strict("\ud800")
    with pytest.raises(OmniBufDecodeError):
        decode_utf8_strict(b"\xff\xfe")
    with pytest.raises(OmniBufDecodeError):
        decode_utf8_strict(b"\xed\xa0\x80")


def test_round_float32_shortest() -> None:
    raw_lat = struct.pack("<f", 50.1109)
    assert round_float32_shortest(raw_lat) == 50.1109
    assert str(round_float32_shortest(raw_lat)) == "50.1109"

    flt_max = bytes.fromhex("ffff7f7f")
    rounded_max = round_float32_shortest(flt_max)
    assert struct.pack("<f", rounded_max) == flt_max

    flt_min_sub = bytes.fromhex("01000000")
    rounded_sub = round_float32_shortest(flt_min_sub)
    assert struct.pack("<f", rounded_sub) == flt_min_sub

    neg_zero = struct.pack("<f", -0.0)
    z = round_float32_shortest(neg_zero)
    assert z == 0.0 and math.copysign(1.0, z) == -1.0


def test_locate_field_and_aliased_splice() -> None:
    enc = omnibuf.Encoder()
    enc.write_uint32(1, 10)
    enc.write_string(2, "alpha")
    enc.write_uint32(1, 20)  # duplicate field 1: last wins
    enc.write_uint(3, 999)
    pkt = enc.finish()

    loc1 = locate_field(pkt, 1, 1 << WIRE_UINT)
    assert loc1.ok
    v1, _ = decode_varint(loc1.val_slice)
    assert v1 == 20

    rep_buf = bytearray()
    append_varint(rep_buf, (1 << 4) | WIRE_UINT)
    append_varint(rep_buf, 1 << 42)
    replacements = [
        SpliceField(field_num=1, encoded_field=bytes(rep_buf)),
        SpliceField(field_num=2, encoded_field=b""),
    ]

    prefix = b"\xaa\xbb\xcc"
    storage = bytearray(prefix + pkt)
    mv = memoryview(storage)
    spliced = splice_fields(mv[:3], mv[3:], replacements)

    assert spliced[:3] == prefix
    assert bytes(storage[3:]) == pkt  # source packet slice untouched

    body = spliced[3:]
    loc1_after = locate_field(body, 1, 1 << WIRE_UINT)
    assert loc1_after.ok
    v1_after, _ = decode_varint(loc1_after.val_slice)
    assert v1_after == (1 << 42)

    loc2_after = locate_field(body, 2, 1 << WIRE_STRING)
    assert not loc2_after.ok

    loc3_after = locate_field(body, 3, 1 << WIRE_UINT)
    assert loc3_after.ok
    v3_after, _ = decode_varint(loc3_after.val_slice)
    assert v3_after == 999


def test_locate_field_offset_rejects_corrupt_field0() -> None:
    """locate_field_offset and opaque_get_uint32 (#65536) must reject packets with corrupt Field #0."""
    corrupt_field0 = bytes([0x19, 0x05, 0x21, 0x02])
    pkt = corrupt_field0 + encode_tag(65536, WIRE_UINT) + encode_varint(42)

    assert omnibuf_wire.locate_field_offset(pkt, 65536) == (-1, 0)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_uint32(pkt, 65536, default=0)


def test_validate_message_and_splice_reject_invalid_utf8() -> None:
    """Python validate_message fallback and splice_fields_encode must reject invalid UTF-8."""
    bad_utf8 = encode_tag(1, WIRE_STRING) + encode_varint(2) + b"\xff\xfe"
    with pytest.raises(OmniBufDecodeError):
        validate_message(bad_utf8, depth=0, limit_depth=16)
    with pytest.raises(OmniBufDecodeError):
        validate_message(bad_utf8, depth=1, limit_depth=omnibuf_wire.MAX_NESTING_DEPTH)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque.splice_dirty_fields(None, bad_utf8, {2}, lambda _out, _f: None)


def test_splice_fields_many_replacements() -> None:
    """splice_fields with many replacements must produce exact expected wire output."""
    enc = omnibuf.Encoder()
    for i in range(1, 201):
        enc.write_uint32(i, i)
    src = enc.finish()
    reps = [SpliceField(i, encode_tag(i, WIRE_UINT) + encode_varint(i * 10)) for i in range(1, 201)]
    out = splice_fields(None, src, reps)
    validate_message(out)
    assert omnibuf.opaque_get_uint32(out, 1) == 10
    assert omnibuf.opaque_get_uint32(out, 200) == 2000


def test_unknown_wire_string_invalid_utf8_rejected() -> None:
    """Skipped/unknown WireString fields with invalid UTF-8 must be rejected consistently."""
    from omnibuf.protobuf_codec import unmarshal_proto

    bad_str_field = encode_tag(99, WIRE_STRING) + encode_varint(2) + b"\xff\xfe"

    # 1. Decoder.skip_field
    dec = omnibuf.Decoder(bad_str_field)
    tag = dec.read_tag()
    assert tag == (99, WIRE_STRING)
    with pytest.raises(OmniBufDecodeError):
        dec.skip_field(tag[0], tag[1])

    # 2. field0.decode_schema_meta (unknown WireString field inside SchemaMeta)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.decode_schema_meta(bad_str_field)

    # 3. wire.validate_field0_at / _validate_schema_meta_body
    f0_pkt = encode_tag(0, WIRE_SUB_MSG) + encode_varint(len(bad_str_field)) + bad_str_field
    with pytest.raises(OmniBufDecodeError):
        omnibuf_wire.validate_field0_at(f0_pkt, 1, WIRE_SUB_MSG)
    with pytest.raises(OmniBufDecodeError):
        validate_message(f0_pkt, depth=0, limit_depth=16)

    # 4. google.protobuf unknown WireString field in unmarshal_proto
    with pytest.raises(OmniBufDecodeError):
        unmarshal_proto(bad_str_field, descriptor_pb2.FileDescriptorProto)


def test_fixed_width_wire_array_rejects_trailing_bytes_and_unknown_string_skips_by_length() -> None:
    for elem_wt, elem_bytes in (
        (WIRE_BOOL_FALSE, b"\x01"),
        (WIRE_FIXED32, b"\x01\x02\x03\x04"),
        (WIRE_FIXED64, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    ):
        # Claim count=1 (varint 0x03) plus 1 extra trailing byte
        body = bytes([elem_wt, 0x03]) + elem_bytes + b"\x00"
        pkt = encode_tag(99, WIRE_ARRAY) + encode_varint(len(body)) + body
        with pytest.raises(OmniBufDecodeError):
            validate_message(pkt)
        with pytest.raises(OmniBufDecodeError):
            peer_omnibuf_pb.unmarshal_peer_update(pkt)

    # Spec §7: Unreferenced unknown WIRE_STRING skips by byte length in schema-aware decode,
    # whereas schema-less decode_blind validates UTF-8 on every string field!
    tag_bytes = encode_tag(99, WIRE_STRING)
    unknown_bad_utf8 = tag_bytes + encode_varint(2) + b"\xff\xfe"
    assert validate_value(memoryview(unknown_bad_utf8), len(tag_bytes), WIRE_STRING, 0) == len(
        unknown_bad_utf8
    )
    dec_peer = peer_omnibuf_pb.unmarshal_peer_update(unknown_bad_utf8)
    assert dec_peer.asn == 0
    with pytest.raises(OmniBufDecodeError):
        omnibuf.decode_blind(unknown_bad_utf8)
