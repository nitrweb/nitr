#!/bin/sh
# Refreshes the vendored Swagger UI from the pinned npm release.
#
# Exactly two files are shipped — the UMD bundle and its stylesheet — plus
# the upstream licence texts. The tarball is verified against the sha512
# npm publishes for that release (its `dist.integrity`), so a mirror or a
# proxy cannot swap the bundle unnoticed. To bump: change VERSION and
# SHA512 together (`npm view swagger-ui-dist@<ver> dist.integrity`, then
# base64-decode it into hex), run this script, review the diff, and update
# the version in the README's third-party note.
set -eu

VERSION="5.32.15"
SHA512="4d214447eac54257f59f393a5af2a431a1d3c403d0dde000c628054e19f141e7524446a77d98126c915ac9956cfd42e749b35dac939bf7dbcb0fac696f74777a"

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/swagger-ui-dist.tgz" \
  "https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-${VERSION}.tgz"
actual="$(sha512sum "$tmp/swagger-ui-dist.tgz" | cut -d' ' -f1)"
if [ "$actual" != "$SHA512" ]; then
  echo "swagger-ui-dist ${VERSION}: sha512 mismatch" >&2
  echo "  expected $SHA512" >&2
  echo "  got      $actual" >&2
  exit 1
fi
tar -xzf "$tmp/swagger-ui-dist.tgz" -C "$tmp"
cp "$tmp/package/swagger-ui-bundle.js" "$here/swagger-ui-bundle.js"
cp "$tmp/package/swagger-ui.css" "$here/swagger-ui.css"
cp "$tmp/package/LICENSE" "$here/LICENSE"
cp "$tmp/package/swagger-ui-bundle.js.LICENSE.txt" "$here/swagger-ui-bundle.js.LICENSE.txt"
printf '%s\n' "$VERSION" > "$here/VERSION"
echo "vendored swagger-ui-dist ${VERSION}"
