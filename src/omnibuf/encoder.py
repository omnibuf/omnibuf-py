"""Single-pass OmniBuf v0.1 binary Encoder with dynamic container length backpatching."""

from __future__ import annotations

import operator
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

from .wire import (
    INT32_MAX,
    INT32_MIN,
    INT64_MAX,
    INT64_MIN,
    MAX_1B_VARINT,
    MAX_2B_VARINT,
    MAX_4B_VARINT,
    MAX_CONTAINER_DEPTH,
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
    skip_validated_value,
)

_U32_PACK = struct.Struct("<I").pack
_I32_PACK = struct.Struct("<i").pack
_U64_PACK = struct.Struct("<Q").pack
_I64_PACK = struct.Struct("<q").pack
_F32_PACK = struct.Struct("<f").pack
_F64_PACK = struct.Struct("<d").pack

_FRAME_CONTAINER = 0
_FRAME_ARRAY = 1
_FRAME_MAP = 2

_T = TypeVar("_T")


def _require_bool(val: object, label: str = "bool") -> bool:
    if not isinstance(val, bool):
        raise OmniBufEncodeError(f"omnibuf: {label} expected bool, got {type(val).__name__}")
    return val


def _require_int(val: int, label: str = "integer") -> int:
    if isinstance(val, bool):
        raise OmniBufEncodeError(f"omnibuf: {label} expected int, got bool")
    try:
        return operator.index(val)
    except TypeError as exc:
        raise OmniBufEncodeError(
            f"omnibuf: {label} expected int, got {type(val).__name__}"
        ) from exc


def _require_float(val: float, label: str = "float") -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise OmniBufEncodeError(f"omnibuf: {label} expected float, got {type(val).__name__}")
    return float(val)


@dataclass(slots=True)
class _ContainerFrame:
    kind: int
    len_pos: int
    expected_items: int = 0
    actual_items: int = 0
    pure_tracked: bool = True
    elem_start: int = 0
    wt1: int = 0
    wt2: int = 0


class Encoder:
    """Single-pass OmniBuf v0.1 writer backed by a growable bytearray and container stack."""

    __slots__ = ("_buf", "_frames")

    def __init__(self, initial: Buffer | None = None) -> None:
        self._buf = bytearray(initial) if initial is not None else bytearray()
        self._frames: list[_ContainerFrame] = []

    def reset(self) -> None:
        """Clears the buffer and container stacks for reuse."""
        self._buf.clear()
        self._frames.clear()

    def __len__(self) -> int:
        return len(self._buf)

    def finish(self) -> bytes:
        """Returns the encoded message as immutable bytes, verifying all containers are closed."""
        if self._frames:
            raise OmniBufEncodeError(
                f"omnibuf: {len(self._frames)} unclosed container(s) on Encoder stack"
            )
        return bytes(self._buf)

    def buffer_copy(self) -> bytearray:
        """Returns an independent bytearray copy of the current encoded bytes."""
        return bytearray(self._buf)

    def _note_elem_written(self) -> None:
        if self._frames:
            top = self._frames[-1]
            if top.kind != _FRAME_CONTAINER:
                top.actual_items += 1

    def _note_raw_or_untracked(self) -> None:
        if self._frames:
            top = self._frames[-1]
            if top.kind != _FRAME_CONTAINER:
                top.pure_tracked = False

    def write_raw(self, raw: Buffer) -> None:
        """Appends raw pre-encoded bytes directly to the output buffer."""
        self._note_raw_or_untracked()
        self._buf.extend(raw)

    def write_tag(self, field_num: int, wire_type: int) -> None:
        self._note_raw_or_untracked()
        append_tag(self._buf, field_num, wire_type)

    def write_varint(self, v: int) -> None:
        self._note_raw_or_untracked()
        append_varint(self._buf, _require_int(v, "varint"))

    # ------------------------------------------------------------------
    # Container framing (single-pass 2-byte reservation + backpatching)
    # ------------------------------------------------------------------

    def _push_frame(self, frame: _ContainerFrame) -> None:
        if len(self._frames) >= MAX_CONTAINER_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: container nesting depth {len(self._frames) + 1} exceeds {MAX_CONTAINER_DEPTH}"
            )
        self._frames.append(frame)

    def begin_container(self) -> int:
        """Reserves a 2-byte Prefix-Varint length slot and pushes its offset on the stack."""
        pos = len(self._buf)
        frame = _ContainerFrame(kind=_FRAME_CONTAINER, len_pos=pos)
        self._push_frame(frame)
        self._buf.extend(b"\x00\x00")
        return pos

    def end_container(self) -> None:
        """Pops the innermost container length slot and backpatches its byte length."""
        if not self._frames:
            raise OmniBufEncodeError("omnibuf: end_container called with empty stack")
        top = self._frames[-1]
        if top.kind != _FRAME_CONTAINER:
            raise OmniBufEncodeError("omnibuf: end_container cannot close array or map frame")
        self._frames.pop()
        backpatch_container_len(self._buf, top.len_pos)
        self._note_elem_written()

    def begin_submsg(self, field_num: int) -> int:
        """Writes a WireSubMsg field tag and opens a length-backpatched sub-message frame."""
        if self._frames and self._frames[-1].kind != _FRAME_CONTAINER:
            raise OmniBufEncodeError("omnibuf: tagged submsg written directly inside array/map")
        if len(self._frames) >= MAX_CONTAINER_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: container nesting depth {len(self._frames) + 1} exceeds {MAX_CONTAINER_DEPTH}"
            )
        append_tag(self._buf, field_num, WIRE_SUB_MSG)
        return self.begin_container()

    def end_submsg(self) -> None:
        """Closes the active sub-message frame."""
        self.end_container()

    def begin_array(self, field_num: int, elem_wt: int, count: int) -> int:
        """Writes a WireArray field tag, container length slot, ElemWT, and Count."""
        elem_wt = _require_int(elem_wt, "elem_wt")
        count = _require_int(count, "count")
        if elem_wt < 0 or elem_wt > WIRE_EXTENDED or elem_wt == WIRE_BOOL_TRUE:
            raise OmniBufEncodeError(f"omnibuf: invalid WireArray element type {elem_wt}")
        if count < 0:
            raise OmniBufEncodeError(f"omnibuf: negative WireArray count {count}")
        if self._frames and self._frames[-1].kind != _FRAME_CONTAINER:
            raise OmniBufEncodeError("omnibuf: tagged array written directly inside array/map")
        if len(self._frames) >= MAX_CONTAINER_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: container nesting depth {len(self._frames) + 1} exceeds {MAX_CONTAINER_DEPTH}"
            )
        append_tag(self._buf, field_num, WIRE_ARRAY)
        pos = len(self._buf)
        self._buf.extend(b"\x00\x00")
        self._buf.append(elem_wt)
        append_varint(self._buf, count)
        elem_start = len(self._buf)
        self._push_frame(
            _ContainerFrame(
                kind=_FRAME_ARRAY,
                len_pos=pos,
                expected_items=count,
                elem_start=elem_start,
                wt1=elem_wt,
            )
        )
        return pos

    def _skip_container_item(self, pos: int, wt: int, end: int) -> int:
        if wt == WIRE_BOOL_FALSE:
            if pos >= end or self._buf[pos] > 1:
                return -1
            return pos + 1
        return skip_validated_value(self._buf, pos, wt, end)

    def end_array(self) -> None:
        """Closes the active WireArray frame and verifies the written element count."""
        if not self._frames or self._frames[-1].kind != _FRAME_ARRAY:
            raise OmniBufEncodeError("omnibuf: end_array called without matching begin_array")
        frame = self._frames.pop()
        count = frame.expected_items
        if frame.pure_tracked:
            if frame.actual_items != count:
                raise OmniBufEncodeError(
                    f"omnibuf: WireArray declared {count} element(s), wrote {frame.actual_items}"
                )
        else:
            end = len(self._buf)
            rem = end - frame.elem_start
            ewt = frame.wt1
            if ewt == WIRE_BOOL_FALSE:
                if rem != count or any(b > 1 for b in self._buf[frame.elem_start : end]):
                    raise OmniBufEncodeError("omnibuf: WireArray bool element count/value mismatch")
            elif ewt in (WIRE_FIXED32, WIRE_SFIXED32, WIRE_FLOAT32):
                if rem != count * 4:
                    raise OmniBufEncodeError("omnibuf: WireArray 32-bit element count mismatch")
            elif ewt in (WIRE_FIXED64, WIRE_SFIXED64, WIRE_FLOAT64):
                if rem != count * 8:
                    raise OmniBufEncodeError("omnibuf: WireArray 64-bit element count mismatch")
            else:
                p = frame.elem_start
                for _ in range(count):
                    p = self._skip_container_item(p, ewt, end)
                    if p < 0:
                        raise OmniBufEncodeError(
                            "omnibuf: WireArray fewer elements written than declared"
                        )
                if p != end:
                    raise OmniBufEncodeError(
                        "omnibuf: WireArray more bytes/elements written than declared"
                    )
        backpatch_container_len(self._buf, frame.len_pos)
        self._note_elem_written()

    def begin_map(self, field_num: int, key_wt: int, val_wt: int, count: int) -> int:
        """Writes a WireMap field tag, container length slot, KeyWT, ValWT, and Count."""
        key_wt = _require_int(key_wt, "key_wt")
        val_wt = _require_int(val_wt, "val_wt")
        count = _require_int(count, "count")
        if not is_valid_map_types(key_wt, val_wt):
            raise OmniBufEncodeError(f"omnibuf: invalid WireMap types ({key_wt}, {val_wt})")
        if count < 0:
            raise OmniBufEncodeError(f"omnibuf: negative WireMap count {count}")
        if self._frames and self._frames[-1].kind != _FRAME_CONTAINER:
            raise OmniBufEncodeError("omnibuf: tagged map written directly inside array/map")
        if len(self._frames) >= MAX_CONTAINER_DEPTH:
            raise OmniBufEncodeError(
                f"omnibuf: container nesting depth {len(self._frames) + 1} exceeds {MAX_CONTAINER_DEPTH}"
            )
        append_tag(self._buf, field_num, WIRE_MAP)
        pos = len(self._buf)
        self._buf.extend(b"\x00\x00")
        self._buf.append(key_wt)
        self._buf.append(val_wt)
        append_varint(self._buf, count)
        elem_start = len(self._buf)
        self._push_frame(
            _ContainerFrame(
                kind=_FRAME_MAP,
                len_pos=pos,
                expected_items=count * 2,
                elem_start=elem_start,
                wt1=key_wt,
                wt2=val_wt,
            )
        )
        return pos

    def end_map(self) -> None:
        """Closes the active WireMap frame and verifies the written entry count."""
        if not self._frames or self._frames[-1].kind != _FRAME_MAP:
            raise OmniBufEncodeError("omnibuf: end_map called without matching begin_map")
        frame = self._frames.pop()
        if frame.pure_tracked:
            if frame.actual_items != frame.expected_items:
                raise OmniBufEncodeError(
                    f"omnibuf: WireMap declared {frame.expected_items // 2} entry/entries, "
                    f"wrote {frame.actual_items} item(s)"
                )
        else:
            end = len(self._buf)
            p = frame.elem_start
            entries = frame.expected_items // 2
            for _ in range(entries):
                p = self._skip_container_item(p, frame.wt1, end)
                if p < 0:
                    raise OmniBufEncodeError("omnibuf: WireMap entry key count/payload mismatch")
                p = self._skip_container_item(p, frame.wt2, end)
                if p < 0:
                    raise OmniBufEncodeError("omnibuf: WireMap entry value count/payload mismatch")
            if p != end:
                raise OmniBufEncodeError("omnibuf: WireMap trailing bytes beyond declared count")
        backpatch_container_len(self._buf, frame.len_pos)
        self._note_elem_written()

    # ------------------------------------------------------------------
    # Tagged scalar field writers
    # ------------------------------------------------------------------

    def _check_tagged_context(self) -> None:
        if self._frames and self._frames[-1].kind != _FRAME_CONTAINER:
            raise OmniBufEncodeError("omnibuf: tagged field written directly inside array/map")

    def write_bool(self, field_num: int, val: bool) -> None:
        self._check_tagged_context()
        b = _require_bool(val)
        append_tag(self._buf, field_num, WIRE_BOOL_TRUE if b else WIRE_BOOL_FALSE)

    def write_uint(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "uint64")
        if iv < 0 or iv > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint64 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_UINT)
        append_varint(self._buf, iv)

    def write_uint32(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "uint32")
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint32 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_UINT)
        append_varint(self._buf, iv)

    def write_sint(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "sint64")
        zz = encode_zigzag(iv)
        append_tag(self._buf, field_num, WIRE_SINT)
        append_varint(self._buf, zz)

    def write_sint32(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "sint32")
        zz = encode_zigzag32(iv)
        append_tag(self._buf, field_num, WIRE_SINT)
        append_varint(self._buf, zz)

    def write_fixed32(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "fixed32")
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed32 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_FIXED32)
        self._buf.extend(_U32_PACK(iv))

    def write_sfixed32(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "sfixed32")
        if iv < INT32_MIN or iv > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed32 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_SFIXED32)
        self._buf.extend(_I32_PACK(iv))

    def write_fixed64(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "fixed64")
        if iv < 0 or iv > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed64 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_FIXED64)
        self._buf.extend(_U64_PACK(iv))

    def write_sfixed64(self, field_num: int, val: int) -> None:
        self._check_tagged_context()
        iv = _require_int(val, "sfixed64")
        if iv < INT64_MIN or iv > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed64 value {iv} out of range")
        append_tag(self._buf, field_num, WIRE_SFIXED64)
        self._buf.extend(_I64_PACK(iv))

    def write_float32(self, field_num: int, val: float) -> None:
        self._check_tagged_context()
        fv = _require_float(val, "float32")
        try:
            packed = _F32_PACK(fv)
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: float32 overflow for {val}") from exc
        append_tag(self._buf, field_num, WIRE_FLOAT32)
        self._buf.extend(packed)

    def write_float64(self, field_num: int, val: float) -> None:
        self._check_tagged_context()
        fv = _require_float(val, "float64")
        append_tag(self._buf, field_num, WIRE_FLOAT64)
        self._buf.extend(_F64_PACK(fv))

    def write_string(self, field_num: int, val: str) -> None:
        self._check_tagged_context()
        if not isinstance(val, str):
            raise OmniBufEncodeError(f"omnibuf: expected str, got {type(val).__name__}")
        raw = encode_utf8_strict(val)
        append_tag(self._buf, field_num, WIRE_STRING)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)

    @staticmethod
    def _normalize_bytes(val: Buffer) -> Buffer:
        if isinstance(val, (bytes, bytearray)):
            return val
        mv = val if isinstance(val, memoryview) else memoryview(val)
        if mv.itemsize == 1 and mv.ndim == 1:
            return mv
        if mv.c_contiguous:
            return mv.cast("B")
        return mv.tobytes()

    def write_bytes(self, field_num: int, val: Buffer) -> None:
        self._check_tagged_context()
        raw = self._normalize_bytes(val)
        append_tag(self._buf, field_num, WIRE_BYTES)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)

    def write_extended(self, field_num: int, ext_type: int, payload: Buffer) -> None:
        self._check_tagged_context()
        ext_iv = _require_int(ext_type, "ext_type")
        if ext_iv < 0 or ext_iv > 0xFF:
            raise OmniBufEncodeError(f"omnibuf: WireExtended subtype {ext_iv} out of 0..255 range")
        raw = self._normalize_bytes(payload)
        append_tag(self._buf, field_num, WIRE_EXTENDED)
        append_varint(self._buf, 1 + len(raw))
        self._buf.append(ext_iv)
        self._buf.extend(raw)

    # ------------------------------------------------------------------
    # Untagged element/map-entry payload writers
    # ------------------------------------------------------------------

    def write_elem_bool(self, val: bool) -> None:
        b = _require_bool(val)
        self._buf.append(1 if b else 0)
        self._note_elem_written()

    def write_elem_uint(self, val: int) -> None:
        append_varint(self._buf, _require_int(val, "uint64"))
        self._note_elem_written()

    def write_elem_uint32(self, val: int) -> None:
        iv = _require_int(val, "uint32")
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: uint32 element {iv} out of range")
        append_varint(self._buf, iv)
        self._note_elem_written()

    def write_elem_sint(self, val: int) -> None:
        append_varint(self._buf, encode_zigzag(_require_int(val, "sint64")))
        self._note_elem_written()

    def write_elem_sint32(self, val: int) -> None:
        append_varint(self._buf, encode_zigzag32(_require_int(val, "sint32")))
        self._note_elem_written()

    def write_elem_fixed32(self, val: int) -> None:
        iv = _require_int(val, "fixed32")
        if iv < 0 or iv > UINT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed32 element {iv} out of range")
        self._buf.extend(_U32_PACK(iv))
        self._note_elem_written()

    def write_elem_sfixed32(self, val: int) -> None:
        iv = _require_int(val, "sfixed32")
        if iv < INT32_MIN or iv > INT32_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed32 element {iv} out of range")
        self._buf.extend(_I32_PACK(iv))
        self._note_elem_written()

    def write_elem_fixed64(self, val: int) -> None:
        iv = _require_int(val, "fixed64")
        if iv < 0 or iv > UINT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: fixed64 element {iv} out of range")
        self._buf.extend(_U64_PACK(iv))
        self._note_elem_written()

    def write_elem_sfixed64(self, val: int) -> None:
        iv = _require_int(val, "sfixed64")
        if iv < INT64_MIN or iv > INT64_MAX:
            raise OmniBufEncodeError(f"omnibuf: sfixed64 element {iv} out of range")
        self._buf.extend(_I64_PACK(iv))
        self._note_elem_written()

    def write_elem_float32(self, val: float) -> None:
        fv = _require_float(val, "float32")
        try:
            self._buf.extend(_F32_PACK(fv))
        except OverflowError as exc:
            raise OmniBufEncodeError(f"omnibuf: float32 overflow for {val}") from exc
        self._note_elem_written()

    def write_elem_float64(self, val: float) -> None:
        fv = _require_float(val, "float64")
        self._buf.extend(_F64_PACK(fv))
        self._note_elem_written()

    def write_elem_string(self, val: str) -> None:
        if not isinstance(val, str):
            raise OmniBufEncodeError(f"omnibuf: expected str, got {type(val).__name__}")
        raw = encode_utf8_strict(val)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)
        self._note_elem_written()

    def write_elem_bytes(self, val: Buffer) -> None:
        raw = self._normalize_bytes(val)
        append_varint(self._buf, len(raw))
        self._buf.extend(raw)
        self._note_elem_written()

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
            self.write_elem_uint(item)
        self.end_array()

    def write_uint32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_UINT, len(items))
        for item in items:
            self.write_elem_uint32(item)
        self.end_array()

    def write_sint_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SINT, len(items))
        for item in items:
            self.write_elem_sint(item)
        self.end_array()

    def write_sint32_array(self, field_num: int, items: Sequence[int]) -> None:
        self.begin_array(field_num, WIRE_SINT, len(items))
        for item in items:
            self.write_elem_sint32(item)
        self.end_array()

    def write_bool_array(self, field_num: int, items: Sequence[bool]) -> None:
        self.begin_array(field_num, WIRE_BOOL_FALSE, len(items))
        for item in items:
            self.write_elem_bool(item)
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

    def write_submsg_array(
        self,
        field_num: int,
        items: Sequence[_T],
        encode_fn: Callable[[Encoder, _T], None],
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
            val = _require_int(mapping[key], "uint64")
            if val < 0 or val > UINT64_MAX:
                raise OmniBufEncodeError(f"omnibuf: map uint64 value {val} out of range")
            self.write_elem_string(key)
            self.write_elem_uint(val)
        self.end_map()


__all__ = [
    "Encoder",
    "MAX_1B_VARINT",
    "MAX_2B_VARINT",
    "MAX_4B_VARINT",
    "MAX_FIELD_NUMBER",
]
