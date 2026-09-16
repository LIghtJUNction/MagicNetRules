#!/usr/bin/env bash
# The pinned upstream Linux compiler is a build tool, never an Android payload.
set -euo pipefail
version=1.11.4
archive="sing-box-${version}-linux-amd64.tar.gz"
sha256=0bb762ef286b36c2016d9107fc1f089be7a75f6d579b33f067d31e696c05927e
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 \
  "https://github.com/SagerNet/sing-box/releases/download/v${version}/${archive}" -o "$work/$archive"
printf '%s  %s\n' "$sha256" "$work/$archive" | sha256sum --check --strict
mkdir -p "$work/extract"
tar -xzf "$work/$archive" -C "$work/extract" --strip-components=1 "sing-box-${version}-linux-amd64/sing-box"
destination=${SING_BOX_INSTALL_DIR:-"${RUNNER_TEMP:-/tmp}/magicnet-rules-tools"}
mkdir -p "$destination"
install -m 0755 "$work/extract/sing-box" "$destination/sing-box"
"$destination/sing-box" version
if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$destination" >> "$GITHUB_PATH"; fi
