#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Package the conformance executable with its own nextest scheduler.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "Usage: $0 <rust-target> <output-directory>" >&2
  exit 2
fi
target=$1
mkdir -p "$2"
out=$(cd "$2" && pwd)
manifest="$(cd "$(dirname "$0")" && pwd)/Cargo.toml"
# Keep this release and its checksums in sync with the cargo-nextest pin in
# mise.toml and the version provided by the Nix dev shell (flake.nix).
version=0.9.143
case "$target" in
  aarch64-apple-darwin|x86_64-apple-darwin)
    upstream=universal-apple-darwin
    sha=4830d430411148d17602a75cc880bfb4dc8dac153dea59a48a2ef4cc93577f07
    ;;
  aarch64-unknown-linux-musl)
    upstream=$target
    sha=0560ce0ce017f368c54b5db86588370fc03b470985490fa81200e62a657dda05
    ;;
  x86_64-unknown-linux-musl)
    upstream=$target
    sha=6d891c18105ec2d33f6e441a4f92b7ccab47ba263e22055c8bb66884243f3389
    ;;
  *)
    echo "Unsupported conformance bundle target: $target (arm64 or x86-64, macOS or Linux musl)" >&2
    exit 2
    ;;
esac

if [[ $(cargo nextest --version | awk '$1 == "release:" {print $2}') != "$version" ]]; then
  echo "Build requires cargo-nextest $version" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/conformance-package.XXXXXXXX")
trap 'rm -r -- "$work"' EXIT
work=$(cd "$work" && pwd -P)
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${manifest%/*}/target}"
unset OPENSHELL_CONFORMANCE_BUNDLE

asset="cargo-nextest-$version-$upstream.tar.gz"
curl -fsSL "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/$asset" -o "$work/$asset"
printf '%s  %s\n' "$sha" "$work/$asset" | shasum -a 256 -c -
tar -xOzf "$work/$asset" cargo-nextest > "$work/nextest-upstream"
if [[ $upstream == universal-apple-darwin ]]; then
  arch=${target%%-*}
  lipo -thin "${arch/aarch64/arm64}" "$work/nextest-upstream" -output "$work/cargo-nextest"
  codesign --verify "$work/cargo-nextest"
else
  mv "$work/nextest-upstream" "$work/cargo-nextest"
fi

build=(--locked --release --manifest-path "$manifest" --target "$target")
cargo nextest archive "${build[@]}" --bin openshell-conformance --archive-file "$work/suite.tar.zst"
# Discard the archive's unbundled test executable. The metadata still names
# its target-relative path; at runtime a symlink there points to the final
# bundled executable, which exposes the same test harness.
for name in cargo-metadata.json binaries-metadata.json; do
  zstd -dc "$work/suite.tar.zst" | tar -xOf - "target/nextest/$name" > "$work/$name"
done
jq -er '
  .["rust-build-meta"]["target-directory"] as $target |
  .["rust-binaries"] | to_entries |
  if length != 1 or .[0].key != "conformance::bin/openshell-conformance"
  then error("expected one conformance test binary") else .[0].value["binary-path"] end |
  if startswith($target + "/") then ltrimstr($target + "/")
  else error("test binary is outside the target directory") end |
  select(test("^[A-Za-z0-9_/-]+$") and (split("/") | all(length > 0)))
' "$work/binaries-metadata.json" > "$work/binary-path"

export OPENSHELL_CONFORMANCE_BUNDLE="$work"
cargo build "${build[@]}" --bin openshell-conformance
cp "$CARGO_TARGET_DIR/$target/release/openshell-conformance" "$out/"
wc -c "$out/openshell-conformance"
