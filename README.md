# omnibuf-py

[![OmniBuf Spec: v1 DRAFT-1](https://img.shields.io/badge/OmniBuf%20Spec-v1%20DRAFT--1-FF4F18)](https://omnibuf.com/spec)

Python 3.11+ implementation of the [OmniBuf v1 DRAFT-1 wire specification](https://omnibuf.com/spec), backed by a compiled Rust PyO3 extension. Documentation and benchmarks live at [omnibuf.com/py](https://omnibuf.com/py).

## Install

```bash
uv add omnibuf
```

For `protoc-gen-omnibuf-py` or legacy `google.protobuf` `_pb2` classes, install the `protobuf` extra (`uv add "omnibuf[protobuf]"`).

## Quick Usage

```python
import omnibuf
from omnibuf import Sint32, Uint32, Uint64, omnibuf_field, omnibuf_message


@omnibuf_message("PeerSummary")
class PeerSummary:
    asn: Uint32 = omnibuf_field(1, default=0)
    rssi_dbm: Sint32 = omnibuf_field(5, default=0)
    sequence: Uint64 = omnibuf_field(11, default=0)


raw = omnibuf.marshal(PeerSummary(asn=64512, rssi_dbm=-62, sequence=7), self_describing=True)
restored = omnibuf.unmarshal(raw, PeerSummary)
```

## gRPC and Connect

`omnibuf.grpc` and `omnibuf.connect` are separate detached modules with zero runtime dependency on `grpcio` or `connect-python`:

```python
from omnibuf.grpc import grpc_deserializer, grpc_serializer

# grpcio unary handler or channel call
serialize = grpc_serializer()
deserialize = grpc_deserializer(PeerSummary)
```

```python
from omnibuf.connect import OmniBufConnectCodec

# connect-python custom codec ("omnibuf" or "x-omnibuf" when self_describing=True)
codec = OmniBufConnectCodec()
wire = codec.encode(PeerSummary(asn=64512, rssi_dbm=-62, sequence=7))
msg = codec.decode(wire, PeerSummary)
```

## Implementation Details

- **Rust PyO3 core**: Wire encoding, decoding, and `Field #0` inspection run in a native Rust extension with strict `py.typed` annotations for Python 3.11+.
- **Dataclass schemas**: `@omnibuf_message` and `omnibuf_field` annotate Python classes with explicit scalar aliases (`Uint32`, `Uint64`, `Sint32`, `Sint64`, `Float32`, `Float64`) and `IntEnum` support.
- **`protobuf-py` interop**: `omnibuf.marshal` and `omnibuf.unmarshal` work directly on `protobuf-py` `_pb.py` classes and `DescMessage` descriptors, with optional `google.protobuf` `_pb2.py` support.
- **Codegen**: `protoc-gen-omnibuf-py` emits slotted dataclasses, compiled codecs, and lazy `Opaque` views for in-place wire splicing.
- **Blind decode**: `decode_blind` and `decode_blind_json` decode packets with embedded `Field #0` metadata.

## Development

```bash
just install && just test && just conformance
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
