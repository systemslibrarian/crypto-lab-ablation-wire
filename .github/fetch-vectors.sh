#!/usr/bin/env bash
# Fetch the NIST ACVP vectors that tests/kat.rs verifies against.
#
# These are not vendored: they are large, they are NIST's, and pinning a copy
# in this repository would mean the tests check what we last copied rather than
# what NIST publishes.
#
# Note the file names. `prompt.json` carries inputs and *no* expected answers —
# fetching it and calling the result a known-answer test was the bug this
# script exists to prevent. `internalProjection.json` carries the answers.
set -euo pipefail

base="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
dest="codetalker-core/tests/vectors"
mkdir -p "$dest"

fetch() {
  local url="$1" out="$2"
  echo "fetching $(basename "$out") ..."
  curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url"
  # A truncated or error-page download would otherwise surface much later as a
  # confusing JSON parse failure inside the test.
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out"
}

fetch "$base/ML-KEM-encapDecap-FIPS203/internalProjection.json" "$dest/mlkem768.json"
fetch "$base/ML-DSA-sigVer-FIPS204/internalProjection.json" "$dest/mldsa65.json"

echo "vectors ready in $dest"
