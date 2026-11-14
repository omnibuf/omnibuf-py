"""Single-pass OmniBuf v0.1 binary Encoder with dynamic container length backpatching."""

from __future__ import annotations

import struct
from collections.abc import Callable, Mapping, Sequence

from .wire import (
    INT32_MAX,
    INT32_MIN,
    INT64_MAX,
    INT64_MIN,
    MAX_1B_VARINT,
    MAX_2B_VARINT,
    MAX_4B_VARINT,
    MAX_FIELD_NUMBER,
    UINT32_MAX,
    UINT64_MAX,
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_BOOL_TRUE,
    WIRE_BYTES,
    WIRE_EXTENDED,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_FLOAT32,
    WIRE_FLOAT64,
    WIRE_MAP,
    WIRE_SFIXED32,
    WIRE_SFIXED64,
    WIRE_SINT,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Buffer,
    OmniBufEncodeError,
    append_tag,
    append_varint,
    backpatch_container_len,
    encode_utf8_strict,
    encode_zigzag,
    encode_zigzag32,
    is_valid_map_types,
)

_U32_PACK = struct.Struct("<I").pack
_I32_PACK = struct.Struct("<i").pack
_U64_PACK = struct.Struct("<Q").pack
_I64_PACK = struct.Struct("<q").pack
_F32_PACK = struct.Struct("<f").pack
_F64_PACK = struct.Struct("<d").pack


class Encoder:
    """Single-pass OmniBuf v0.1 writer backed by a growable bytearray and container stack."""

    __slots__ = ("_buf", "_len_stack", "_count_stack")

    def __init__(self, initial: Buffer | None = None) -> None:
        self._buf = bytearray(initial) if initial is not None else bytearray()
        self._len_stack: list[int] = []
        self._count_stack: list[int] = []

    def reset(self) -> None:
        """Clears the buffer and container stacks for reuse."""
        self._buf.clear()
        self._len_stack.clear()
        self._count_stack.clear()

    def __len__(self) -> int:
        return len(self._buf)

    def finish(self) -> bytes:
        """Returns the encoded message as immutable bytes, verifying all containers are closed."""
        if self._len_stack:
            raise OmniBufEncodeError(
                f"omnibuf: {len(self._len_stack)} unclosed container(s) on Encoder stack"
            )
        return bytes(self._buf)

    def buffer_copy(self) -> bytearray:
        """Returns an independent bytearray copy of the current encoded bytes."""
        return bytearray(self._buf)

    def write_raw(self, raw: Buffer) -> None:
        """Appends raw pre-encoded bytes directly to the output buffer."""
        self._buf.extend(raw)

    def write_tag(self, field_num: int, wire_type: int) -> None:
        append_tag(self._buf, field_num, wire_type)

    def write_varint(self, v: int) -> None:
        append_varint(self._buf, v)

    # ------------------------------------------------------------------
    # Container framing (single-pass 2-byte reservation + backpatching)
    # ------------------------------------------------------------------

    def begin_container(self) -> int:
        """Reserves a 2-byte Prefix-Varint length slot and pushes its offset on the stack."""
        pos = len(self._buf)
        self._buf.extend(b"\x00\x00")
        self._len_stack.append(pos)
        return pos

    def end_container(self) -> None:
        """Pops the innermost container length slot and backpatches its byte length."""
        if not self._len_stack:
            raise OmniBufEncodeError("omnibuf: end_container called with empty stack")
        len_pos = self._len_stack.pop()
        backpatch_container_len(self._buf, len_pos)

    def begin_submsg(self, field_num: int) -> int:
        """Writes a WireSubMsg field tag and opens a length-backpatched sub-message frame."""
        append_tag(self._buf, field_num, WIRE_SUB_MSG)
        return self.begin_container()

    def end_submsg(self) -> None:
        """Closes the active sub-message frame."""
        self.end_container()

    def begin_array(self, field_num: int, elem_wt: int, count: int) -> int:
        """Writes a WireArray field tag, container length slot, ElemWT, and Count."""
        if elem_wt < 0 or elem_wt > WIRE_EXTENDED or elem_wt == WIRE_BOOL_TRUE:
            raise OmniBufEncodeError(f"omnibuf: invalid WireArray element type {elem_wt}")
        if count < 0:
            raise OmniBufEncodeError(f"omnibuf: negative WireArray count {count}")
        append_tag(self._buf, field_num, WIRE_ARRAY)
        pos = self.begin_container()
        self._buf.append(elem_wt)
        append_varint(self._buf, count)
        self._count_stack.append(count)
        return pos

    def end_array(self) -> None:
        """Closes the active WireArray frame."""
        if self._count_stack:
            self._count_stack.pop()
        self.end_container()

    def begin_map(self, field_num: int, key_wt: int, val_wt: int, count: int) -> int:
        """Writes a WireMap field tag, container length slot, KeyWT, ValWT, and Count."""
        if not is_valid_map_types(key_wt, val_wt):
            raise OmniBufEncodeError(f"omnibuf: invalid WireMap types ({key_wt}, {val_wt})")
        if count < 0:
            raise OmniBufEncodeError(f"omnibuf: negative WireMap count {count}")
        append_tag(self._buf, field_num, WIRE_MAP)
        pos = self.begin_container()
        self._buf.append(key_wt)
        self._buf.append(val_wt)
        append_varint(self._buf, count)
        self._count_stack.append(count)
        return pos

    def end_map(self) -> None:
        """Closes the active WireMap frame."""
        if self._count_stack:
            self._count_stack.pop()
        self.end_container()

    # ------------------------------------------------------------------
    # Tagged scalar field writers
    # ------------------------------------------------------------------

    def write_bool(self, field_num: int, val: bool) -> None:
        append_tag(self._buf, field_num, WIRE_BOOL_TRUE if val else WIRE_BOOL_FALSE)

    def write_uint(self, field_num: int, val: int) -> None:
        if val < 0 or val > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint64 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_UINT)
        append_varint(self._buf, val)

    def write_uint32(self, field_num: int, val: int) -> None:
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint32 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_UINT)
        append_varint(self._buf, val)

    def write_sint(self, field_num: int, val: int) -> None:
        zz = encode_zigzag(val)
        append_tag(self._buf, field_num, WIRE_SINT)
        append_varint(self._buf, zz)

    def write_sint32(self, field_num: int, val: int) -> None:
        zz = encode_zigzag32(val)
        append_tag(self._buf, field_num, WIRE_SINT)
        append_varint(self._buf, zz)

    def write_fixed32(self, field_num: int, val: int) -> None:
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed32 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_FIXED32)
        self._buf.extend(_U32_PACK(val))

    def write_sfixed32(self, field_num: int, val: int) -> None:
        if val < INT32_MIN or val > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed32 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_SFIXED32)
        self._buf.extend(_I32_PACK(val))

    def write_fixed64(self, field_num: int, val: int) -> None:
        if val < 0 or val > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed64 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_FIXED64)
        self._buf.extend(_U64_PACK(val))

    def write_sfixed64(self, field_num: int, val: int) -> None:
        if val < INT64_MIN or val > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed64 value {val} out of range")
        append_tag(self._buf, field_num, WIRE_SFIXED64)
        self._buf.extend(_I64_PACK(val))

    def write_float32(self, field_num: int, val: float) -> None:
        try:
            packed = _F32_PACK(val)
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: float32 overflow for {val}") from exc
        append_tag(self._buf, field_num, WIRE_FLOAT32)
        self._buf.extend(packed)

    def write_float64(self, field_num: int, val: float) -> None:
        append_tag(self._buf, field_num, WIRE_FLOAT64)
        self._buf.extend(_F64_PACK(val))

    def write_string(self, field_num: int, val: str) -> None:
        raw = encode_utf8_strict(val)
        append_tag(self._buf, field_num, WIRE_STRING)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)

    def write_bytes(self, field_num: int, val: Buffer) -> None:
        append_tag(self._buf, field_num, WIRE_BYTES)
        append_varint(self._buf, len(val))
        self._buf.extend(val)

    def write_extended(self, field_num: int, ext_type: int, payload: Buffer) -> None:
        if ext_type < 0 or ext_type > 0xFF:
            raise OmniBufEncodeError(
                f"omnibuf: WireExtended subtype {ext_type} out of 0..255 range"
            )
        append_tag(self._buf, field_num, WIRE_EXTENDED)
        append_varint(self._buf, 1 + len(payload))
        self._buf.append(ext_type)
        self._buf.extend(payload)

    # ------------------------------------------------------------------
    # Untagged element/map-entry payload writers
    # ------------------------------------------------------------------

    def write_elem_bool(self, val: bool) -> None:
        self._buf.append(1 if val else 0)

    def write_elem_uint(self, val: int) -> None:
        append_varint(self._buf, val)

    def write_elem_uint32(self, val: int) -> None:
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint32 element {val} out of range")
        append_varint(self._buf, val)

    def write_elem_sint(self, val: int) -> None:
        append_varint(self._buf, encode_zigzag(val))

    def write_elem_sint32(self, val: int) -> None:
        append_varint(self._buf, encode_zigzag32(val))

    def write_elem_fixed32(self, val: int) -> None:
        if val < 0 or val > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed32 element {val} out of range")
        self._buf.extend(_U32_PACK(val))

    def write_elem_sfixed32(self, val: int) -> None:
        if val < INT32_MIN or val > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed32 element {val} out of range")
        self._buf.extend(_I32_PACK(val))

    def write_elem_fixed64(self, val: int) -> None:
        if val < 0 or val > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed64 element {val} out of range")
        self._buf.extend(_U64_PACK(val))

    def write_elem_sfixed64(self, val: int) -> None:
        if val < INT64_MIN or val > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed64 element {val} out of range")
        self._buf.extend(_I64_PACK(val))

    def write_elem_float32(self, val: float) -> None:
        try:
            self._buf.extend(_F32_PACK(val))
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: float32 overflow for {val}") from exc

    def write_elem_float64(self, val: float) -> None:
        self._buf.extend(_F64_PACK(val))

    def write_elem_string(self, val: str) -> None:
        raw = encode_utf8_strict(val)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)

    def write_elem_bytes(self, val: Buffer) -> None:
        append_varint(self._buf, len(val))
        self._buf.extend(val)

    # ------------------------------------------------------------------
    # High-level array & map writers
    # ------------------------------------------------------------------

    def write_string_array(self, field_num: int, items: Sequence[str]) -> None:
        self.begin_array(field_num, WIRE_STRING, len(items))
        for item in items:
            self.write_elem_string(item)
        self.end_array()

    def write_bytes_array(self, field_num: int, items: Sequence[Buffer]) -> None:
        self.begin_array(field_num, WIRE_BYTES, len(items))
        for item in items:
            self.write_elem_bytes(item)
        self.end_array()

    def write_uint_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_UINT, len(items))
        for item in items:
            append_varint(self._buf, item)
        self.end_array()

    def write_uint32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_UINT, len(items))
        for item in items:
            if item < 0 or item > UINT32_MAX:
                raise OmniBufEncodeError(f"omnibuf: uint32 element {item} out of range")
            append_varint(self._buf, item)
        self.end_array()

    def write_sint_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SINT, len(items))
        for item in items:
            append_varint(self._buf, encode_zigzag(item))
        self.end_array()

    def write_sint32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SINT, len(items))
        for item in items:
            append_varint(self._buf, encode_zigzag32(item))
        self.end_array()

    def write_bool_array(self, field_num: int, items: Sequence[bool]) -> None:
        self.begin_array(field_num, WIRE_BOOL_FALSE, len(items))
        for item in items:
            self._buf.append(1 if item else 0)
        self.end_array()

    def write_fixed32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_FIXED32, len(items))
        for item in items:
            self.write_elem_fixed32(item)
        self.end_array()

    def write_sfixed32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SFIXED32, len(items))
        for item in items:
            self.write_elem_sfixed32(item)
        self.end_array()

    def write_fixed64_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_FIXED64, len(items))
        for item in items:
            self.write_elem_fixed64(item)
        self.end_array()

    def write_sfixed64_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SFIXED64, len(items))
        for item in items:
            self.write_elem_sfixed64(item)
        self.end_array()

    def write_float32_array(self, field_num: int, items: Sequence[float]) -> None:
        self.begin_array(field_num, WIRE_FLOAT32, len(items))
        for item in items:
            self.write_elem_float32(item)
        self.end_array()

    def write_float64_array(self, field_num: int, items: Sequence[float]) -> None:
        self.begin_array(field_num, WIRE_FLOAT64, len(items))
        for item in items:
            self.write_elem_float64(item)
        self.end_array()

    def write_submsg_array[T](
        self,
        field_num: int,
        items: Sequence[T],
        encode_fn: Callable[[Encoder, T], None],
    ) -> None:
        self.begin_array(field_num, WIRE_SUB_MSG, len(items))
        for item in items:
            self.begin_container()
            encode_fn(self, item)
            self.end_container()
        self.end_array()

    def write_map_str_uint(
        self,
        field_num: int,
        mapping: Mapping[str, int],
        *,
        deterministic: bool = True,
    ) -> None:
        self.begin_map(field_num, WIRE_STRING, WIRE_UINT, len(mapping))
        keys = sorted(mapping.keys()) if deterministic and len(mapping) > 1 else mapping.keys()
        for key in keys:
            val = mapping[key]
            if val < 0 or val > UINT64_MAX:
                raise OmniBufEncodeError(f"omnibuf: map uint64 value {val} out of range")
            self.write_elem_string(key)
            append_varint(self._buf, val)
        self.end_map()


__all__ = [
    "Encoder",
    "MAX_1B_VARINT",
    "MAX_2B_VARINT",
    "MAX_4B_VARINT",
    "MAX_FIELD_NUMBER",
]
