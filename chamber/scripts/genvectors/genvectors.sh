#!/usr/bin/env bash
# Regenerate the tests/vectors files from the gno Go implementation.
#
#   GNOROOT=/path/to/gnolang/gno ./genvectors.sh
#
# gno signs the tx fee differently on its two lines (PR #6173), so run this once
# per checkout. The line is detected from GNOROOT and picks the files written:
#
#   master line (has std.GetSignaturePayloadLegacy)  -> keys.json, txs.json
#   chain/mainnet line (built before #6173)          -> txs_legacy.json
set -euo pipefail

: "${GNOROOT:?set GNOROOT env to point to your gnolang/gno local repository}"
GNOROOT=$(cd "$GNOROOT" && pwd)

# The sign payload code lives in tm2/pkg/std/doc.go on both lines
if grep -q GetSignaturePayloadLegacy "$GNOROOT/tm2/pkg/std/doc.go"; then
  flavour=current
else
  flavour=legacy
fi
echo "Detected the gno $flavour sign payload in $GNOROOT"

here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../tests/vectors"
fixture="$here/../../tests/fixtures/hello"

# Throwaway module dir so we don't need a go.mod in the repo just for this
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$here/main.go" "$work/main.go"
cat > "$work/go.mod" <<EOM
module genvectors

go 1.25

require github.com/gnolang/gno v0.0.0

replace github.com/gnolang/gno => $GNOROOT
EOM

cd "$work"

# Resolve main.go's imports against the local gno checkout
go mod tidy

# Generate vectors into a temp dir first and move them into place only
# on success, so a failing run never leaves $out truncated/empty.
mkdir -p "$work/vectors" "$out"
go run . "$work/vectors" "$fixture"
if [ "$flavour" = current ]; then
  mv "$work/vectors/keys.json" "$out/keys.json"
  mv "$work/vectors/txs.json" "$out/txs.json"
  echo "Wrote $out/keys.json and $out/txs.json"
else
  # keys.json doesn't depend on the payload, so the master run owns it
  mv "$work/vectors/txs.json" "$out/txs_legacy.json"
  echo "Wrote $out/txs_legacy.json"
fi
