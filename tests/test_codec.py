"""Unit tests for streaming Encoder and Decoder containers, depth limits, and WireExtended."""

from __future__ import annotations

import pytest

import omnibuf
from omnibuf import (
    MAX_CONTAINER_DEPTH,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_BYTES,
    WIRE_EXTENDED,
    WIRE_SINT,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Decoder,
    Encoder,
    OmniBufDecodeError,
    OmniBufEncodeError,
    validate_message,
)
from omnibuf.conformance import AnnotatedPeerUpdate
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


def test_decoder_skips_valid_wire_extended_and_rejects_empty_payload() -> None:
    enc = Encoder()
    enc.write_extended(4, 0x00, b"")
    enc.write_extended(5, 0x80, b"\xaa")
    enc.write_extended(6, 0xFF, b"\x11\x22\x33")
    enc.write_uint32(7, 77)
    valid_pkt = enc.finish()

    dec = Decoder(valid_pkt)
    for expected_fnum in (4, 5, 6):
        tag = dec.read_tag()
        assert tag == (expected_fnum, WIRE_EXTENDED)
        dec.skip_field(expected_fnum, WIRE_EXTENDED)
    assert dec.read_tag() == (7, WIRE_UINT)
    assert dec.read_uint32() == 77

    with pytest.raises(OmniBufEncodeError):
        enc.write_extended(4, -1, b"")
    with pytest.raises(OmniBufEncodeError):
        enc.write_extended(4, 0x100, b"")

    empty_ext_pkt = encode_tag(4, WIRE_EXTENDED) + encode_varint(0)
    dec_bad = Decoder(empty_ext_pkt)
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


def test_string_rejected_for_bool_fields() -> None:
    """Passing non-bool `'false'` to a bool field or Encoder.write_bool must raise, not encode True."""
    bad_dc = AnnotatedPeerUpdate(active="false")  # type: ignore[arg-type]
    with pytest.raises((TypeError, OmniBufEncodeError)):
        omnibuf.marshal(bad_dc)

    enc = Encoder()
    with pytest.raises((TypeError, OmniBufEncodeError)):
        enc.write_bool(1, "false")  # type: ignore[arg-type]


def test_encoder_rejects_mismatched_array_element_count() -> None:
    """Encoder.end_array() / finish() must raise OmniBufEncodeError when fewer elements were written."""
    enc = Encoder()
    enc.begin_array(1, WIRE_UINT, 5)
    with pytest.raises(OmniBufEncodeError):
        enc.end_array()
        enc.finish()


def test_encoder_handles_non_byte_memoryview() -> None:
    """Encoder must use byte length (nbytes) for non-byte memoryviews (itemsize > 1)."""
    import array

    arr = array.array("I", [0x11223344, 0x55667788])
    mv = memoryview(arr)
    expected = arr.tobytes()
    assert len(mv) == 2
    assert mv.nbytes == 8

    enc = Encoder()
    enc.write_bytes(1, mv)
    enc.write_extended(2, 0x07, mv)
    enc.begin_array(3, WIRE_BYTES, 1)
    enc.write_elem_bytes(mv)
    enc.end_array()
    pkt = enc.finish()

    validate_message(pkt)
    assert omnibuf.opaque_get_bytes(pkt, 1) == expected
    assert omnibuf.opaque_get_scalar_array(pkt, 3, WIRE_BYTES, "bytes") == [expected]


def test_python_311_syntax_compatibility_all_src_files() -> None:
    """Every .py and .pyi file under src/omnibuf/ must parse under Python 3.11 syntax."""
    import ast
    import pathlib

    src_root = pathlib.Path(omnibuf.__file__).resolve().parent
    files = sorted(list(src_root.rglob("*.py")) + list(src_root.rglob("*.pyi")))
    assert files
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 11))


def test_package_version_matches_pyproject() -> None:
    """omnibuf.__version__ must match pyproject.toml project.version."""
    import pathlib
    import tomllib

    pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert omnibuf.__version__ == expected
