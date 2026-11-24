# AGENTS.md

Repository guide for autonomous coding agents working inside `omnibuf-py`.

## Toolchain & Commands

Tools are pinned in `mise.toml` (`python = "3.14.7"`, `uv`, `just = "1.58.0"`, `protobuf = "35.1"`, `buf = "1.75.0"`).

- `just install`: Sync `.venv` and build the compiled Rust extension via `uv sync`.
- `just proto`: Run `buf lint` and `buf generate` (`buf.yaml` + `buf.gen.yaml`). Never invoke raw `protoc` CLI commands directly.
- `just fmt` / `just fmt-check`: Format or verify Rust (`cargo fmt`) and Python (`ruff format`) sources.
- `just lint`: Run `buf lint`, `cargo clippy --all-targets -- -D warnings`, `ruff check .`, and strict `mypy src tests benchmarks`.
- `just test`: Run unit tests (`uv run pytest`).
- `just conformance`: Run the 758-case cross-language conformance runner (`0 skipped, 0 failed` required).
- `just bench`: Run `benchmarks/bench.py` and write `testdata/benchmarks.json` plus `testdata/benchmarks.txt` (pass `--smoke` to smoke-check timing logic leaving `testdata/benchmarks.json` untouched).
- `just ci`: Full verification gate (`fmt-check`, `lint`, `test`, `conformance`).

## Architecture

- `rust/lib.rs`, `rust/codec.rs`, `rust/opaque.rs`, `rust/blind.rs`: Compiled PyO3 + Rust extension (`omnibuf._omnibuf_ext`, typed in `src/omnibuf/_omnibuf_ext.pyi`) backed by `omnibuf-rs`. Uses `LeafBytes` (`Py_buffer` RAII guard) and `InputBytes` (upfront snapshot for mutable buffers) for UAF-safe buffer handling.
- `src/omnibuf/wire.py`: OmniBuf v1 DRAFT-1 Prefix-Varint (`TZCNT_WIDTH_TABLE`), ZigZag 32/64, container length backpatching, strict UTF-8, shortest round-trip `float32`, `locate_field`, and aliased-safe `splice_fields`.
- `src/omnibuf/encoder.py` & `src/omnibuf/decoder.py`: Streaming single-pass writer and depth-bounded reader (`MAX_CONTAINER_DEPTH = 32`).
- `src/omnibuf/field0.py` & `src/omnibuf/blind.py`: `SchemaMeta` encoding/merging and two-pass `decode_blind` / `decode_blind_json`.
- `src/omnibuf/protobuf_codec.py`: Compiled reflection codec with primary support for `protobuf-py` (`bufbuild/protobuf-py` `_pb.py` messages and `DescMessage` descriptors) and lazy optional compatibility for `google.protobuf` (`_pb2.py`).
- `src/omnibuf/dataclass_codec.py`: `@omnibuf_message` and `omnibuf_field` codec supporting recursive types, `enum.IntEnum` / integer-valued `enum.Enum`, explicit wire overrides, `omitempty`, and instance-aware `self_describing=True`.
- `src/omnibuf/opaque.py` & `src/omnibuf/plugin.py`: `protoc-gen-omnibuf-py` code generator emitting slotted message dataclasses, `oneof` and explicit-presence tracking, compiled codecs, and `Opaque<Message>` header-hop views.
- `src/omnibuf/conformance.py`: Length-prefixed stdin/stdout conformance adapter exercising `TIER_PLUGIN`, `TIER_PROTOBUF_TYPES`, `TIER_ANNOTATED_STRUCT`, and `TIER_BLIND`.

## Invariants

1. `MAX_NESTING_DEPTH` and `MAX_CONTAINER_DEPTH` are `32`. Arrays and maps increment container depth.
2. Reserved Prefix-Varint markers (`(b & 0x07) == 0` when `b != 0`) must always fail decoding.
3. `WireExtended` (`15`) requires at least 1 payload byte whose subtype byte is in `0x00..0xFF`.
4. `Field #0` (`tag = 0x19`) requires `WireSubMsg` (`12`) everywhere it appears and may appear anywhere in a message or concatenated stream.
5. Never use em-dashes in documentation, comments, or strings.
