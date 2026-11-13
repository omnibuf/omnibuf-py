# AGENTS.md

Repository guide for autonomous coding agents working inside `omnibuf-py`.

## Toolchain & Commands

Tools are pinned in `mise.toml` (`python = "3.14.7"`, `uv`, `just = "1.58.0"`, `protobuf = "35.1"`, `buf = "1.75.0"`).

- `just install`: Sync `.venv` via `uv sync`.
- `just proto`: Run `buf lint` and `buf generate` (`buf.yaml` + `buf.gen.yaml`). Never invoke raw `protoc` CLI commands directly.
- `just fmt` / `just fmt-check`: Format or verify Python formatting with `ruff`.
- `just lint`: Run `buf lint`, `ruff check .`, and strict `mypy src tests benchmarks`.
- `just test`: Run unit tests (`uv run pytest`).
- `just conformance`: Run the 584-case cross-language conformance runner (`0 skipped, 0 failed` required).
- `just bench`: Run `benchmarks/bench.py` and write `testdata/benchmarks.json` plus `testdata/benchmarks.txt`.
- `just ci`: Full verification gate (`fmt-check`, `lint`, `test`, `conformance`).

## Architecture

- `src/omnibuf/wire.py`: OmniBuf v2.1 Prefix-Varint (`TZCNT_WIDTH_TABLE`), ZigZag 32/64, container length backpatching, strict UTF-8, shortest round-trip `float32`, `locate_field`, and aliased-safe `splice_fields`.
- `src/omnibuf/encoder.py` & `src/omnibuf/decoder.py`: Streaming single-pass writer and depth-bounded reader (`MAX_CONTAINER_DEPTH = 32`).
- `src/omnibuf/field0.py` & `src/omnibuf/blind.py`: `SchemaMeta` encoding/merging and two-pass `decode_blind` / `decode_blind_json`.
- `src/omnibuf/protobuf_codec.py`: Compiled reflection codec with primary support for `protobuf-py` (`bufbuild/protobuf-py` `_pb.py` messages and `DescMessage` descriptors) and secondary compatibility for `google.protobuf` (`_pb2.py`).
- `src/omnibuf/dataclass_codec.py`: `@omnibuf_message` and `omnibuf_field` codec supporting recursive types, explicit wire overrides, `omitempty`, and `self_describing=True`.
- `src/omnibuf/opaque.py` & `src/omnibuf/plugin.py`: `protoc-gen-omnibuf-py` code generator emitting slotted message dataclasses, unrolled encoders/decoders, and `Opaque<Message>` header-hop views.
- `src/omnibuf/conformance.py`: Length-prefixed stdin/stdout conformance adapter exercising `TIER_PLUGIN`, `TIER_PROTOBUF_TYPES`, `TIER_ANNOTATED_STRUCT`, and `TIER_BLIND`.

## Invariants

1. `MAX_NESTING_DEPTH` and `MAX_CONTAINER_DEPTH` are `32`. Arrays and maps increment container depth.
2. Reserved Prefix-Varint markers (`(b & 0x07) == 0` when `b != 0`) must always fail decoding.
3. `WireExtended` (`15`) requires at least 1 payload byte whose subtype byte is in `0x00..0x7F`.
4. `Field #0` (`tag = 0x19`) requires `WireSubMsg` (`12`) everywhere it appears and may appear anywhere in a message or concatenated stream.
5. Never use em-dashes in documentation, comments, or strings.
