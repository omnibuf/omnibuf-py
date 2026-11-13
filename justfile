set shell := ["zsh", "-cu"]

conformance_runner := "../omnibuf-go/bin/conformance-runner"

default: ci

# Sync runtime and development dependencies into .venv
install:
    uv sync

# Lint .proto schemas and regenerate protobuf-py, omnibuf, and google.protobuf modules via buf
proto:
    buf lint
    buf generate

# Alias for proto code generation
generate: proto

# Format all source, test, and benchmark files
fmt:
    uv run ruff format .

# Check formatting without modifying files
fmt-check:
    uv run ruff format --check .

# Run buf lint, ruff linter, and strict mypy type checking
lint:
    buf lint
    uv run ruff check .
    uv run mypy src tests benchmarks

# Run unit tests with pytest
test:
    uv run pytest

# Run the language-independent 584-case OmniBuf conformance suite across all 4 tiers
conformance:
    {{conformance_runner}} uv run python -m omnibuf.conformance

# Run the reproducible PeerUpdate benchmark suite and write testdata/benchmarks.json
bench:
    uv run python benchmarks/bench.py

# Run all formatting, linting, type-checking, unit test, and conformance gates
ci: fmt-check lint test conformance
