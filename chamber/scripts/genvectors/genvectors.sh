#!/usr/bin/env bash
# Regenerate tests/vectors/keys.json from the gno Go implementation.
#
#   GNOROOT=/path/to/gnolang/gno ./gen.sh
set -euo pipefail

: "${GNOROOT:?set GNOROOT env to point to your gnolang/gno local repository}"
GNOROOT=$(cd "$GNOROOT" && pwd)

here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../tests/vectors/keys.json"

# Throwaway module dir so we don't need a go.mod in the repo just for this
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$here/main.go" "$work/main.go"
cat > "$work/go.mod" <<EOF
module genvectors

go 1.25

require github.com/gnolang/gno v0.0.0

replace github.com/gnolang/gno => $GNOROOT
EOF

cd "$work"

# Resolve main.go's imports against the local gno checkout
go mod tidy

# Generate vector into a temp file first and move it into place only
# on success, so a failing run never leaves $out truncated/empty.
mkdir -p "$(dirname "$out")"
go run . > "$work/keys.json"
mv "$work/keys.json" "$out"
echo "Wrote $out"
