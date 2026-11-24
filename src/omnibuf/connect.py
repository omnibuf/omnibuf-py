"""Connect RPC codec helpers for OmniBuf (`connect-python`)."""

from __future__ import annotations

from typing import Any, TypeVar, overload

from . import marshal, unmarshal
from .wire import Buffer, validate_message

_T = TypeVar("_T")

CODEC_NAME = "omnibuf"
SELF_DESCRIBING_CODEC_NAME = "x-omnibuf"


class OmniBufConnectCodec:
    """Connect RPC codec compatible with `connect-python`'s `Codec` protocol."""

    __slots__ = ("_deterministic", "_max_depth", "_max_elements", "_self_describing")

    def __init__(
        self,
        self_describing: bool = False,
        deterministic: bool = False,
        *,
        max_depth: int | None = None,
        max_elements: int | None = None,
    ) -> None:
        self._self_describing = self_describing
        self._deterministic = deterministic
        self._max_depth = max_depth
        self._max_elements = max_elements

    def name(self) -> str:
        """Returns the Connect codec name (`omnibuf` or `x-omnibuf`)."""
        return SELF_DESCRIBING_CODEC_NAME if self._self_describing else CODEC_NAME

    @property
    def self_describing(self) -> bool:
        return self._self_describing

    @property
    def deterministic(self) -> bool:
        return self._deterministic

    def encode(self, msg: Any) -> bytes:
        """Encodes a message to OmniBuf wire bytes."""
        return marshal(
            msg,
            deterministic=self._deterministic,
            self_describing=self._self_describing,
        )

    @overload
    def decode(self, data: Buffer, target: type[_T]) -> _T: ...

    @overload
    def decode(self, data: Buffer, target: _T) -> _T: ...

    def decode(self, data: Buffer, target: Any) -> Any:
        """Decodes OmniBuf wire bytes into `target` (a message class or instance)."""
        if self._max_depth is not None:
            validate_message(data, limit_depth=self._max_depth)
        return unmarshal(data, target, max_elements=self._max_elements)


__all__ = [
    "CODEC_NAME",
    "SELF_DESCRIBING_CODEC_NAME",
    "OmniBufConnectCodec",
]
