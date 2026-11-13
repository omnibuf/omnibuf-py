"""Cursor-based OmniBuf v2.1 binary Decoder enforcing depth, UTF-8, and container invariants."""

from __future__ import annotations

import struct
from collections.abc import Callable

from .wire import (
    MAX_CONTAINER_DEPTH,
    MAX_FIELD_NUMBER,
    WIRE_BOOL_FALSE,
    WIRE_BOOL_TRUE,
    WIRE_BYTES,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_FLOAT32,
    WIRE_FLOAT64,
    WIRE_SFIXED32,
    WIRE_SFIXED64,
    WIRE_SINT,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Buffer,
    OmniBufDecodeError,
    decode_utf8_strict,
    decode_varint,
    decode_zigzag,
    decode_zigzag32,
    parse_array_header,
    parse_map_header,
    read_len_slice,
    to_uint32,
    validate_field0_at,
    validate_value,
)

_U32_UNPACK = struct.Struct("<I").unpack_from
_I32_UNPACK = struct.Struct("<i").unpack_from
_U64_UNPACK = struct.Struct("<Q").unpack_from
_I64_UNPACK = struct.Struct("<q").unpack_from
_F32_UNPACK = struct.Struct("<f").unpack_from
_F64_UNPACK = struct.Struct("<d").unpack_from


class Decoder:
    """Streaming cursor over an OmniBuf v2.1 byte buffer with strict structural validation."""

    __slots__ = ("_mv", "_pos", "_end", "_depth", "_max_depth")

    def __init__(
        self,
        data: Buffer,
        *,
        pos: int = 0,
        end: int | None = None,
        depth: int = 0,
        max_depth: int = MAX_CONTAINER_DEPTH,
    ) -> None:
        mv = memoryview(data)
        limit = len(mv) if end is None else end
        if pos < 0 or limit > len(mv) or pos > limit:
            raise OmniBufDecodeError("omnibuf: Decoder slice bounds out of range")
        if depth > max_depth:
            raise OmniBufDecodeError(f"omnibuf: nesting depth {depth} exceeds limit {max_depth}")
        self._mv = mv
        self._pos = pos
        self._end = limit
        self._depth = depth
        self._max_depth = max_depth

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def end(self) -> int:
        return self._end

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    def done(self) -> bool:
        return self._pos >= self._end

    def read_tag(self) -> tuple[int, int] | None:
        """Reads the next (field_num, wire_type) pair, or returns None at end of buffer."""
        if self._pos >= self._end:
            return None
        b0 = self._mv[self._pos]
        if b0 & 1:
            self._pos += 1
            fnum = b0 >> 5
            wt = (b0 >> 1) & 0x0F
        elif b0 & 2:
            if self._pos + 2 > self._end:
                raise OmniBufDecodeError(f"omnibuf: truncated 2-byte tag at byte {self._pos}")
            u16 = (b0 | (self._mv[self._pos + 1] << 8)) >> 2
            self._pos += 2
            fnum = u16 >> 4
            wt = u16 & 0x0F
        else:
            tag, width = decode_varint(self._mv, self._pos, self._end)
            if width == 0 or (tag >> 4) > MAX_FIELD_NUMBER:
                raise OmniBufDecodeError(f"omnibuf: invalid tag at byte {self._pos}")
            self._pos += width
            fnum = tag >> 4
            wt = tag & 0x0F

        if fnum == 0 and wt != WIRE_SUB_MSG:
            raise OmniBufDecodeError(f"omnibuf: invalid wire type {wt} for Field #0")
        return fnum, wt

    def skip_field(self, field_num: int, wire_type: int) -> None:
        """Validates and advances past the value for (field_num, wire_type)."""
        if field_num == 0:
            self._pos = validate_field0_at(
                self._mv, self._pos, wire_type, self._depth, self._max_depth, self._end
            )
        else:
            self._pos = validate_value(
                self._mv, self._pos, wire_type, self._depth, self._max_depth, self._end
            )

    # ------------------------------------------------------------------
    # Scalar readers
    # ------------------------------------------------------------------

    def read_uint64(self) -> int:
        val, width = decode_varint(self._mv, self._pos, self._end)
        if width == 0:
            raise OmniBufDecodeError(f"omnibuf: invalid uint64 varint at byte {self._pos}")
        self._pos += width
        return val

    def read_uint32(self) -> int:
        return to_uint32(self.read_uint64())

    def read_sint64(self) -> int:
        return decode_zigzag(self.read_uint64())

    def read_sint32(self) -> int:
        return decode_zigzag32(self.read_uint64())

    def read_bool_from_tag(self, wire_type: int) -> bool:
        if wire_type == WIRE_BOOL_FALSE:
            return False
        if wire_type == WIRE_BOOL_TRUE:
            return True
        raise OmniBufDecodeError(f"omnibuf: invalid bool wire type {wire_type}")

    def read_elem_bool(self) -> bool:
        if self._pos >= self._end:
            raise OmniBufDecodeError("omnibuf: truncated bool element")
        b = self._mv[self._pos]
        if b > 1:
            raise OmniBufDecodeError(f"omnibuf: invalid bool byte 0x{b:02x} at byte {self._pos}")
        self._pos += 1
        return b == 1

    def read_fixed32(self) -> int:
        if self._pos + 4 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated fixed32 at byte {self._pos}")
        (val,) = _U32_UNPACK(self._mv, self._pos)
        self._pos += 4
        return int(val)

    def read_sfixed32(self) -> int:
        if self._pos + 4 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated sfixed32 at byte {self._pos}")
        (val,) = _I32_UNPACK(self._mv, self._pos)
        self._pos += 4
        return int(val)

    def read_fixed64(self) -> int:
        if self._pos + 8 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated fixed64 at byte {self._pos}")
        (val,) = _U64_UNPACK(self._mv, self._pos)
        self._pos += 8
        return int(val)

    def read_sfixed64(self) -> int:
        if self._pos + 8 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated sfixed64 at byte {self._pos}")
        (val,) = _I64_UNPACK(self._mv, self._pos)
        self._pos += 8
        return int(val)

    def read_float32(self) -> float:
        if self._pos + 4 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated float32 at byte {self._pos}")
        (val,) = _F32_UNPACK(self._mv, self._pos)
        self._pos += 4
        return float(val)

    def read_float64(self) -> float:
        if self._pos + 8 > self._end:
            raise OmniBufDecodeError(f"omnibuf: truncated float64 at byte {self._pos}")
        (val,) = _F64_UNPACK(self._mv, self._pos)
        self._pos += 8
        return float(val)

    def read_string(self) -> str:
        start = self._pos
        raw, self._pos = read_len_slice(self._mv, self._pos, 0, self._end)
        return decode_utf8_strict(raw, start)

    def read_bytes(self) -> bytes:
        raw, self._pos = read_len_slice(self._mv, self._pos, 0, self._end)
        return bytes(raw)

    # ------------------------------------------------------------------
    # Sub-message, array, and map readers
    # ------------------------------------------------------------------

    def read_submsg_decoder(self) -> Decoder:
        if self._depth + 1 > self._max_depth:
            raise OmniBufDecodeError(
                f"omnibuf: nesting depth {self._depth + 1} exceeds limit {self._max_depth}"
            )
        body, self._pos = read_len_slice(self._mv, self._pos, 0, self._end)
        return Decoder(
            body,
            pos=0,
            end=len(body),
            depth=self._depth + 1,
            max_depth=self._max_depth,
        )

    def read_array_decoder(self) -> tuple[int, int, Decoder]:
        """Reads a WireArray container and returns (elem_wt, count, element_decoder)."""
        if self._depth + 1 > self._max_depth:
            raise OmniBufDecodeError(
                f"omnibuf: array nesting depth {self._depth + 1} exceeds limit {self._max_depth}"
            )
        body, self._pos = read_len_slice(self._mv, self._pos, 2, self._end)
        elem_wt, count, elem_pos, ok = parse_array_header(body)
        if not ok:
            raise OmniBufDecodeError("omnibuf: invalid WireArray header")
        sub = Decoder(
            body,
            pos=elem_pos,
            end=len(body),
            depth=self._depth + 1,
            max_depth=self._max_depth,
        )
        return elem_wt, count, sub

    def read_map_decoder(self) -> tuple[int, int, int, Decoder]:
        """Reads a WireMap container and returns (key_wt, val_wt, count, entry_decoder)."""
        if self._depth + 1 > self._max_depth:
            raise OmniBufDecodeError(
                f"omnibuf: map nesting depth {self._depth + 1} exceeds limit {self._max_depth}"
            )
        body, self._pos = read_len_slice(self._mv, self._pos, 3, self._end)
        key_wt, val_wt, count, entry_pos, ok = parse_map_header(body)
        if not ok:
            raise OmniBufDecodeError("omnibuf: invalid WireMap header")
        sub = Decoder(
            body,
            pos=entry_pos,
            end=len(body),
            depth=self._depth + 1,
            max_depth=self._max_depth,
        )
        return key_wt, val_wt, count, sub

    def read_string_array(self, dst: list[str] | None = None) -> list[str]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_STRING:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireString>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_string())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in string WireArray")
        return out

    def read_bytes_array(self, dst: list[bytes] | None = None) -> list[bytes]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_BYTES:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireBytes>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_bytes())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in bytes WireArray")
        return out

    def read_uint64_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_UINT:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireUint>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_uint64())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in uint64 WireArray")
        return out

    def read_uint32_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_UINT:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireUint>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_uint32())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in uint32 WireArray")
        return out

    def read_sint64_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_SINT:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireSint>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_sint64())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in sint64 WireArray")
        return out

    def read_sint32_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_SINT:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireSint>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_sint32())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in sint32 WireArray")
        return out

    def read_bool_array(self, dst: list[bool] | None = None) -> list[bool]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_BOOL_FALSE:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireBool>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_elem_bool())
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in bool WireArray")
        return out

    def read_fixed32_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_FIXED32:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireFixed32>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_fixed32())
        return out

    def read_sfixed32_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_SFIXED32:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireSfixed32>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_sfixed32())
        return out

    def read_fixed64_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_FIXED64:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireFixed64>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_fixed64())
        return out

    def read_sfixed64_array(self, dst: list[int] | None = None) -> list[int]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_SFIXED64:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireSfixed64>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_sfixed64())
        return out

    def read_float32_array(self, dst: list[float] | None = None) -> list[float]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_FLOAT32:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireFloat32>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_float32())
        return out

    def read_float64_array(self, dst: list[float] | None = None) -> list[float]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_FLOAT64:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireFloat64>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            out.append(sub.read_float64())
        return out

    def read_submsg_array[T](
        self,
        decode_fn: Callable[[Decoder], T],
        dst: list[T] | None = None,
    ) -> list[T]:
        elem_wt, count, sub = self.read_array_decoder()
        if elem_wt != WIRE_SUB_MSG:
            raise OmniBufDecodeError(f"omnibuf: expected WireArray<WireSubMsg>, got {elem_wt}")
        out = dst if dst is not None else []
        for _ in range(count):
            elem_dec = sub.read_submsg_decoder()
            out.append(decode_fn(elem_dec))
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in submsg WireArray")
        return out

    def read_map_str_uint(self, dst: dict[str, int] | None = None) -> dict[str, int]:
        key_wt, val_wt, count, sub = self.read_map_decoder()
        if key_wt != WIRE_STRING or val_wt != WIRE_UINT:
            raise OmniBufDecodeError(
                f"omnibuf: expected WireMap<WireString, WireUint>, got ({key_wt}, {val_wt})"
            )
        out = dst if dst is not None else {}
        for _ in range(count):
            k = sub.read_string()
            v = sub.read_uint64()
            out[k] = v
        if not sub.done():
            raise OmniBufDecodeError("omnibuf: trailing bytes in WireMap")
        return out


__all__ = ["Decoder"]
