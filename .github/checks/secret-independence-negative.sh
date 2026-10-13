#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
manifest="$repo_root/tests/secret-independence-controls/Cargo.toml"
target_dir="${TMPDIR:-/tmp}/ablation-secret-independence-controls"

node "$repo_root/.github/checks/secret-independence-boundary.mjs"

CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$target_dir" \
    cargo check --quiet --locked --manifest-path "$manifest" --bin allowed

for fixture in secret-branch secret-index raw-hash-boundary; do
    case "$fixture" in
        secret-branch) expected=E0369 ;;
        secret-index) expected=E0277 ;;
        raw-hash-boundary) expected=E0308 ;;
    esac
    log_file="$target_dir/$fixture.log"
    if CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$target_dir" \
        cargo check --quiet --locked --manifest-path "$manifest" --bin "$fixture" \
        >"$log_file" 2>&1; then
        echo "negative control unexpectedly compiled: $fixture" >&2
        exit 1
    fi
    if ! grep -Fq "error[$expected]" "$log_file" || \
        ! grep -Fq "$fixture.rs" "$log_file"; then
        echo "negative control failed for an unexpected reason: $fixture" >&2
        cat "$log_file" >&2
        exit 1
    fi
done

echo "secret-independence compiler controls passed"
