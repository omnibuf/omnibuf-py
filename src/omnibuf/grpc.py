"""gRPC codec helpers for OmniBuf (`grpcio`)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from . import marshal, unmarshal
from .wire import validate_message

_T = TypeVar("_T")

CODEC_NAME = "omnibuf"
SELF_DESCRIBING_CODEC_NAME = "x-omnibuf"
CONTENT_TYPE_GRPC = "application/grpc+omnibuf"


def grpc_serializer(
    deterministic: bool = False,
    self_describing: bool = False,
) -> Callable[[Any], bytes]:
    """Returns a `request_serializer` / `response_serializer` callable for `grpcio`."""

    def _serialize(msg: Any) -> bytes:
        return marshal(
            msg,
            deterministic=deterministic,
            self_describing=self_describing,
        )

    return _serialize


def grpc_deserializer(
    cls: type[_T],
    max_depth: int | None = None,
    max_elements: int | None = None,
) -> Callable[[bytes], _T]:
    """Returns a `request_deserializer` / `response_deserializer` callable for `grpcio`."""

    def _deserialize(data: bytes) -> _T:
        if max_depth is not None:
            validate_message(data, limit_depth=max_depth)
        return unmarshal(data, cls, max_elements=max_elements)

    return _deserialize


__all__ = [
    "CODEC_NAME",
    "CONTENT_TYPE_GRPC",
    "SELF_DESCRIBING_CODEC_NAME",
    "grpc_deserializer",
    "grpc_serializer",
]
