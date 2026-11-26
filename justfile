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

# Format all Rust, Python, test, and benchmark files
fmt:
    cargo fmt
    uv run ruff format .

# Check formatting without modifying files
fmt-check:
    cargo fmt --check
    uv run ruff format --check .

# Run buf lint, cargo clippy, ruff linter, and strict mypy type checking
lint:
    buf lint
    cargo clippy --all-targets -- -D warnings
    uv run ruff check .
    uv run mypy src tests benchmarks

# Run unit tests with pytest
test:
    uv run pytest

# Run the language-independent 758-case OmniBuf conformance suite across all 4 tiers
conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${CONFORMANCE_RUNNER:-}" ]]; then
        RUNNER="$CONFORMANCE_RUNNER"
    elif [[ -x "../omnibuf-go/bin/conformance-runner" ]]; then
        RUNNER="../omnibuf-go/bin/conformance-runner"
    elif command -v conformance-runner >/dev/null 2>&1; then
        RUNNER="conformance-runner"
    elif command -v go >/dev/null 2>&1; then
        exec go run github.com/omnibuf/omnibuf-go/cmd/conformance-runner@v0.2.11 uv run python -m omnibuf.conformance
    else
        echo "conformance-runner binary not found; set CONFORMANCE_RUNNER or install conformance-runner" >&2
        exit 1
    fi
    "$RUNNER" uv run python -m omnibuf.conformance

# Run the reproducible PeerUpdate benchmark suite and write testdata/benchmarks.json
bench:
    uv run python benchmarks/bench.py

# Run all formatting, linting, type-checking, unit test, and conformance gates
ci: fmt-check lint test conformance
