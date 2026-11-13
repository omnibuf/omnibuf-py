"""Unit tests for streaming Encoder and Decoder containers, depth limits, and WireExtended."""

from __future__ import annotations

import pytest

from omnibuf import (
    MAX_CONTAINER_DEPTH,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_EXTENDED,
    WIRE_SINT,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Decoder,
    Encoder,
    OmniBufDecodeError,
)
from omnibuf.wire import encode_tag, encode_varint


def test_encoder_large_container_backpatch_over_16kb() -> None:
    payload_str = "x" * 20_000
    enc = Encoder()
    enc.begin_submsg(1)
    enc.write_string(2, payload_str)
    enc.end_submsg()
    pkt = enc.finish()

    dec = Decoder(pkt)
    tag = dec.read_tag()
    assert tag == (1, WIRE_SUB_MSG)
    sub = dec.read_submsg_decoder()
    assert sub.read_tag() == (2, WIRE_STRING)
    assert sub.read_string() == payload_str
    assert sub.read_tag() is None
    assert dec.read_tag() is None


def test_encoder_and_decoder_arrays_and_maps() -> None:
    enc = Encoder()
    enc.begin_array(1, WIRE_SINT, 3)
    for item in (-500, 0, 500):
        enc.write_elem_sint(item)
    enc.end_array()

    enc.begin_map(2, WIRE_STRING, WIRE_UINT, 2)
    for k, v in (("a", 1), ("b", 2)):
        enc.write_string(0, k) if False else None  # ensure untagged helpers used below
        raw_k = k.encode("utf-8")
        enc.write_varint(len(raw_k))
        enc.write_raw(raw_k)
        enc.write_elem_uint(v)
    enc.end_map()

    dec = Decoder(enc.finish())
    assert dec.read_tag() == (1, WIRE_ARRAY)
    assert dec.read_sint64_array() == [-500, 0, 500]

    assert dec.read_tag() == (2, 14)
    assert dec.read_map_str_uint() == {"a": 1, "b": 2}
    assert dec.read_tag() is None


def test_decoder_enforces_max_container_depth() -> None:
    inner = b""
    for _ in range(MAX_CONTAINER_DEPTH + 2):
        inner = encode_tag(1, WIRE_SUB_MSG) + encode_varint(len(inner)) + inner

    dec = Decoder(inner)
    with pytest.raises(OmniBufDecodeError):
        cur = dec
        for _ in range(MAX_CONTAINER_DEPTH + 2):
            assert cur.read_tag() == (1, WIRE_SUB_MSG)
            cur = cur.read_submsg_decoder()


def test_decoder_skips_valid_wire_extended_and_rejects_high_subtype() -> None:
    enc = Encoder()
    enc.write_extended(4, 0x2A, b"\x11\x22\x33")
    enc.write_uint32(5, 77)
    valid_pkt = enc.finish()

    dec = Decoder(valid_pkt)
    tag = dec.read_tag()
    assert tag == (4, WIRE_EXTENDED)
    dec.skip_field(4, WIRE_EXTENDED)
    assert dec.read_tag() == (5, WIRE_UINT)
    assert dec.read_uint32() == 77

    invalid_pkt = encode_tag(4, WIRE_EXTENDED) + encode_varint(1) + bytes([0x80])
    dec_bad = Decoder(invalid_pkt)
    bad_tag = dec_bad.read_tag()
    assert bad_tag == (4, WIRE_EXTENDED)
    with pytest.raises(OmniBufDecodeError):
        dec_bad.skip_field(4, WIRE_EXTENDED)


def test_decoder_rejects_trailing_container_bytes_and_bad_bool_byte() -> None:
    # Array claiming count=0 with 1 trailing byte inside ByteLen
    bad_arr = encode_tag(1, WIRE_ARRAY) + encode_varint(3) + bytes([WIRE_UINT, 0x01, 0xFF])
    dec = Decoder(bad_arr)
    assert dec.read_tag() == (1, WIRE_ARRAY)
    with pytest.raises(OmniBufDecodeError):
        dec.read_uint32_array()

    # Bool array with invalid byte 0x02
    bad_bool_arr = (
        encode_tag(1, WIRE_ARRAY) + encode_varint(3) + bytes([WIRE_BOOL_FALSE, 0x03, 0x02])
    )
    dec_b = Decoder(bad_bool_arr)
    assert dec_b.read_tag() == (1, WIRE_ARRAY)
    with pytest.raises(OmniBufDecodeError):
        dec_b.read_bool_array()
