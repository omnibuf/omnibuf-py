"""Schema-less blind decoding (decode_blind / decode_blind_json) with Field #0 support."""

from __future__ import annotations

from typing import Any

from . import _omnibuf_ext
from .wire import Buffer


def decode_blind(packet: Buffer) -> dict[str, Any]:
    """Decodes any OmniBuf packet without a schema into a Python dict.

    Raw WireBytes payloads are returned as Python bytes objects.
    """
    return _omnibuf_ext.decode_blind_py(packet)


def decode_blind_json(
    packet: Buffer,
    *,
    allow_nan: bool = False,
    indent: int | None = None,
) -> str:
    """Decodes any OmniBuf packet without a schema and formats it as JSON.

    WireBytes values are encoded as standard Base64 strings. Float32 values use
    shortest round-tripping decimal formatting, and uint64/sint64 preserve full
    64-bit integer precision. When allow_nan is False and a float field contains
    NaN or Inf, raises ValueError unless handled by the caller.
    """
    return _omnibuf_ext.decode_blind_json_py(packet, allow_nan=allow_nan, indent=indent)


__all__ = [
    "decode_blind",
    "decode_blind_json",
]
