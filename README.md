# omnibuf

Explicit-typed, header-hop binary wire codec for Python (`v2.1`).

`omnibuf` implements the complete OmniBuf v2.1 wire format for Python 3.11+ on top of a compiled Rust extension (`omnibuf._omnibuf_ext` powered by `omnibuf-rs` and PyO3), with strict type annotations (`py.typed`), `buf` CLI code generation, native [`protobuf-py`](https://github.com/bufbuild/protobuf-py) integration, `@omnibuf_message` dataclasses, lazy `Opaque` header-hop views, and schema-less `Field #0` inspection.

## Highlights

- **Prefix-Varint (`TZCNT`) Framing**: The first byte determines integer width (`1`, `2`, `4`, or `9` bytes) via trailing-zero count. Reserved markers (`(b & 0x07) == 0` with `b != 0`) fail fast on decode.
- **16 Explicit Wire Types**: Signed integers, unsigned integers, booleans, 32-bit/64-bit floats, strings, raw bytes, sub-messages, typed arrays, and typed maps carry distinct 4-bit wire tags.
- **Four Integration Tiers**:
  - `protoc-gen-omnibuf-py` codegen producing slotted dataclasses, unrolled codecs, and lazy `Opaque<Message>` views
  - Direct `marshal` / `unmarshal` over `protobuf-py` (`_pb.py` classes and `DescMessage` descriptors), plus `google.protobuf` (`_pb2.py`) compatibility
  - Annotated Python dataclasses via `@omnibuf_message` and `omnibuf_field(...)`
  - Schema-less `decode_blind` and `decode_blind_json` powered by embedded `Field #0` metadata
- **584/584 Conformance Verified**: Passes every case in the cross-language OmniBuf conformance suite with zero skips.

## Installation

```bash
uv add omnibuf protobuf-py protobuf-py-ext
```

For schema linting and code generation, install `buf` and add `protoc-gen-py` to development dependencies:

```bash
uv add --dev protoc-gen-py
```

## Code Generation with Buf

Configure `buf.yaml` and `buf.gen.yaml` at your repository root:

```yaml
# buf.yaml
version: v2
modules:
  - path: proto
lint:
  use:
    - STANDARD
  except:
    - PACKAGE_VERSION_SUFFIX
breaking:
  use:
    - FILE
```

```yaml
# buf.gen.yaml
version: v2
plugins:
  - local: ["uv", "run", "--no-sync", "protoc-gen-py"]
    out: src/omnibuf/gen
  - local: ["uv", "run", "--no-sync", "protoc-gen-omnibuf-py"]
    out: src/omnibuf/gen
```

Run `buf lint` and `buf generate` to emit `<name>_pb.py` (`protobuf-py`) and `<name>_omnibuf_pb.py` (`omnibuf`) modules.

## Usage

### 1. `protobuf-py` Messages

`omnibuf.marshal` and `omnibuf.unmarshal` work directly with `protobuf-py` generated `_pb.py` message classes, instances, and `DescMessage` descriptors.

```python
import omnibuf
from omnibuf.gen.omnibuf.bench import peer_pb

msg = peer_pb.PeerUpdate(
    asn=64512,
    router_id="edge-rtr-fra01.core.backbone.net",
    active=True,
    rssi_dbm=-62,
    location=peer_pb.Location(region="eu-central-1", city="Frankfurt", rack=42),
    sequence=9876543210,
)

packet = omnibuf.marshal(msg, deterministic=True)
decoded = omnibuf.unmarshal(packet, peer_pb.PeerUpdate)
assert decoded.location.city == "Frankfurt"
```

### 2. Generated Codec and Lazy `Opaque` Views

`protoc-gen-omnibuf-py` emits slotted dataclasses bound to `CompiledCodec` descriptors alongside `Opaque<Message>` views. `Opaque` views hop across length headers in `O(1)` time per field, reading nested slices directly from `bytes` buffers or splicing single-field edits in place.

```python
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb

view = peer_omnibuf_pb.OpaquePeerUpdate(packet)
loc = view.opaque_location()
assert loc is not None
assert loc.get_city() == "Frankfurt"

view.set_sequence(9876543211)
updated_packet = view.marshal()
```

### 3. Annotated Python Dataclasses

Plain Python projects can define wire schemas directly with `@omnibuf_message`, `omnibuf_field`, and explicit scalar type aliases (`Uint32`, `Uint64`, `Sint32`, `Sint64`, `Fixed32`, `Sfixed32`, `Fixed64`, `Sfixed64`, `Float32`, `Float64`).

```python
import omnibuf
from omnibuf import Float32, Sint32, Uint32, Uint64, omnibuf_field, omnibuf_message


@omnibuf_message("Location")
class Location:
    region: str = omnibuf_field(1, default="")
    city: str = omnibuf_field(3, default="")
    rack: Uint32 = omnibuf_field(4, default=0)
    latitude: Float32 = omnibuf_field(5, default=0.0)


@omnibuf_message("PeerSummary")
class PeerSummary:
    asn: Uint32 = omnibuf_field(1, default=0)
    rssi_dbm: Sint32 = omnibuf_field(5, default=0)
    location: Location = omnibuf_field(9, default_factory=Location)
    sequence: Uint64 = omnibuf_field(11, default=0)


raw = omnibuf.marshal(
    PeerSummary(asn=64512, rssi_dbm=-62, location=Location(city="Frankfurt"), sequence=7),
    self_describing=True,
)
restored = omnibuf.unmarshal(raw, PeerSummary)
```

### 4. Schema-less Inspection via `Field #0`

Packets serialized with `self_describing=True` carry recursive field names inside `Field #0`. `decode_blind` and `decode_blind_json` inspect arbitrary packets with two-pass `Field #0` resolution, shortest round-trip `float32` formatting, Base64 bytes, and full 64-bit integer precision.

```python
import omnibuf

payload_dict = omnibuf.decode_blind(raw)
payload_json = omnibuf.decode_blind_json(raw)
```

## Development Workflow

Toolchains (`python`, `rust`, `uv`, `buf`, `just`) are managed via `mise`:

```bash
just install      # Build Rust extension via maturin and sync .venv
just proto        # Run buf lint and buf generate
just fmt          # Format Rust and Python code with cargo fmt and ruff
just lint         # Run buf lint, cargo clippy, ruff check, and strict mypy
just test         # Run pytest unit suite
just conformance  # Run all 584 cross-language conformance cases
just bench        # Run PeerUpdate benchmark suite -> testdata/benchmarks.json
just ci           # Run fmt-check, lint, test, and conformance
```

## License

MIT
