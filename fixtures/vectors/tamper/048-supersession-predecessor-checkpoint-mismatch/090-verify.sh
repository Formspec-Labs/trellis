#!/bin/sh
set -eu

# Trellis export verifier invocation (§18.8).
#
# Pass the export ZIP path as the only argument; the operator CLI
# verifies it through trellis-verify-wos.

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <export.zip>" >&2
  exit 2
fi

if command -v trellis-cli >/dev/null 2>&1; then
  exec trellis-cli verify-export "$1"
fi

echo "trellis-cli not found in PATH." >&2
echo "Run `trellis-cli verify-export $1`." >&2
exit 2
