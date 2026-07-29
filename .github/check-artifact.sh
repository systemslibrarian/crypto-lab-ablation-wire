#!/usr/bin/env bash
# Verify the Pages artifact is self-contained.
#
# `deploy` uploads `web/` and nothing above it, so every relative reference the
# page makes has to resolve inside that directory. Nothing in the Rust test
# suite can see this: it is a property of the published tree, not of the crate.
#
# It caught two real defects the first time it ran. The footer linked
# `../README.md`, `../THREAT_MODEL.md` and `../SOURCES.md` -- one directory above
# the site root, so all three 404ed on the deployed site while resolving fine in
# a local editor preview. And `favicon.ico` was requested and never shipped, a
# console 404 on a page whose argument is that nothing on it is faked.
#
# Absolute URLs are deliberately out of scope: this checks that the artifact is
# complete, not that the internet is up. A link checker that fails when an
# unrelated host is briefly down teaches people to ignore it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE="$ROOT/web"
HTML="$SITE/index.html"
fail=0

note() { printf '  %s\n' "$1"; }

echo "Checking $HTML against artifact root $SITE"

# Every href/src that is not absolute, not a fragment, and not a data: URI.
refs=$(grep -oE '(href|src)="[^"]+"' "$HTML" \
  | sed -E 's/^(href|src)="//; s/"$//' \
  | grep -vE '^(https?:|data:|mailto:|#|//)' \
  | sort -u || true)

# ES module imports resolve the same way and break the same way.
imports=$(grep -oE 'import\("[^"]+"\)' "$HTML" \
  | sed -E 's/^import\("//; s/"\)$//' \
  | grep -vE '^(https?:|data:)' \
  | sort -u || true)

echo "--- relative references ---"
for ref in $refs $imports; do
  clean="${ref%%\?*}"; clean="${clean%%#*}"
  [ -z "$clean" ] && continue

  # A reference that climbs above the artifact root can never resolve, whether
  # or not the file exists in the repository.
  case "$clean" in
    ../*|*/../*)
      note "ESCAPES ARTIFACT  $ref"
      note "                  resolves above the Pages root; web/ is the site"
      fail=1
      continue
      ;;
  esac

  target="$SITE/${clean#./}"
  if [ -e "$target" ]; then
    note "ok                $ref"
  else
    note "MISSING           $ref"
    note "                  expected at web/${clean#./}"
    fail=1
  fi
done

# Requests the page makes without ever naming them in markup. A browser asks
# for /favicon.ico unprompted; shipping nothing means a 404 in every console.
echo "--- implicit requests ---"
if grep -qE '<link[^>]+rel="(icon|shortcut icon)"' "$HTML"; then
  note "ok                favicon declared in <head>"
else
  if [ -e "$SITE/favicon.ico" ]; then
    note "ok                favicon.ico present"
  else
    note "MISSING           favicon.ico, and no <link rel=\"icon\"> declared"
    note "                  the browser will request it and get a 404"
    fail=1
  fi
fi

# The reason .nojekyll is committed rather than only touched by the deploy job:
# Jekyll drops underscore-prefixed paths, and wasm-pack emits them.
echo "--- Pages preconditions ---"
if [ -e "$SITE/.nojekyll" ]; then
  note "ok                .nojekyll committed"
else
  note "MISSING           web/.nojekyll"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "artifact is self-contained"
else
  echo "artifact is NOT self-contained -- the deployed site would break" >&2
fi
exit "$fail"
