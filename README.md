# omnibuf

Explicit-typed, header-hop binary wire codec for Python (`v0.1`).

`omnibuf` implements the OmniBuf v0.1 wire format for Python 3.11+ backed by a compiled Rust extension. Every package distribution ships strict type annotations (`py.typed`), `buf` CLI code generation, native [`protobuf-py`](https://github.com/bufbuild/protobuf-py) support, `@omnibuf_message` dataclasses, lazy `Opaque` views, and schema-less `Field #0` inspection.

## Highlights

- **Prefix-Varint Framing**: A single leading byte fixes integer width (`1`, `2`, `4`, or `9` bytes) through trailing-zero count. Reserved markers (`(b & 0x07) == 0` with `b != 0`) fail immediately during decode.
- **16 Explicit Wire Types**: Distinct 4-bit tags separate signed integers, unsigned integers, booleans, 32-bit and 64-bit floats, UTF-8 strings, raw bytes, sub-messages, typed arrays, typed maps, and extended payloads.
- **Four Integration Tiers**:
  - `protoc-gen-omnibuf-py` codegen emitting slotted dataclasses, compiled codecs, `oneof` tracking, and lazy `Opaque<Message>` views
  - Direct `marshal` and `unmarshal` over `protobuf-py` (`_pb.py` classes and `DescMessage` descriptors), plus optional `google.protobuf` (`_pb2.py`) support
  - Annotated Python dataclasses via `@omnibuf_message`, `omnibuf_field(...)`, and `enum.IntEnum` or integer-valued `enum.Enum` types
  - Schema-less `decode_blind` and `decode_blind_json` driven by embedded `Field #0` metadata
- **758/758 Conformance Verified**: Passes the entire cross-language OmniBuf conformance suite with zero skips.

## Installation

```bash
uv add omnibuf protobuf-py protobuf-py-ext
```

Projects that run `protoc-gen-omnibuf-py` or decode legacy `google.protobuf` `_pb2` classes install the `protobuf` extra alongside `protoc-gen-py`:

```bash
uv add "omnibuf[protobuf]"
uv add --dev protoc-gen-py
```

## Code Generation with Buf

Add `buf.yaml` and `buf.gen.yaml` at the repository root:

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

Run `buf lint` and `buf generate`. Buf emits `<name>_pb.py` (`protobuf-py`) and `<name>_omnibuf_pb.py` (`omnibuf`) modules in one pass.

## Usage

### 1. `protobuf-py` Messages

`omnibuf.marshal` and `omnibuf.unmarshal` accept `protobuf-py` generated `_pb.py` message classes, instances, and `DescMessage` descriptors directly.

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

### 2. Generated Codecs and Lazy `Opaque` Views

`protoc-gen-omnibuf-py` emits slotted dataclasses paired with `Opaque<Message>` views. `Opaque` views hop across length headers in `O(1)` time per field. Nested slices read directly from `bytes` buffers, and single-field edits splice into existing wire bytes.

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

Pure Python schemas declare wire field numbers with `@omnibuf_message`, `omnibuf_field`, and explicit scalar aliases (`Uint32`, `Uint64`, `Sint32`, `Sint64`, `Fixed32`, `Sfixed32`, `Fixed64`, `Sfixed64`, `Float32`, `Float64`).

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

Self-describing packets embed recursive field names inside `Field #0`. `decode_blind` and `decode_blind_json` resolve `Field #0` metadata in two passes, format shortest round-trip `float32` decimals, encode raw bytes as Base64, and preserve full 64-bit integer precision.

```python
import omnibuf

payload_dict = omnibuf.decode_blind(raw)
payload_json = omnibuf.decode_blind_json(raw)
```

## Benchmarks

`benchmarks/bench.py` measures `PeerUpdate` across six categories:

- Full Message Encode Speed
- Full Message Decode Speed
- Read a Single Nested Field
- Selective Single-Field Mutation
- Large Embedded Message Encode
- Embedded Message Growth

Methodology: canonical `PeerUpdate` carries 11 fields (`366 B` in OmniBuf, `341 B` in Protobuf). Full decode materializes and reads all 11 fields across every codec. Mutation benchmarks check `location.city == "Frankfurt"` before incrementing `sequence` or growing `location.datacenter` past `16 KiB` ahead of 32 trailing `Neighbor` entries.

## Development Workflow

Toolchains (`python`, `rust`, `uv`, `buf`, `just`) are pinned in `mise.toml`:

```bash
just install      # Build Rust extension and sync .venv
just proto        # Run buf lint and buf generate
just fmt          # Format Rust and Python sources
just lint         # Run buf lint, cargo clippy, ruff check, and strict mypy
just test         # Run pytest suite
just conformance  # Run all 758 cross-language conformance cases
just bench        # Run PeerUpdate benchmarks -> testdata/benchmarks.json
just ci           # Run fmt-check, lint, test, and conformance
```

## License

MIT
