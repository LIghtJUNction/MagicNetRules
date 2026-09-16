#!/usr/bin/env python3
"""Fetch one immutable Release bundle, verify it, then replace local dist."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from package_release import runtime_files

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "LIghtJUNction/MagicNetRules"
MAX_ARCHIVE = 64 * 1024 * 1024


def fetch(url: str, limit: int) -> bytes:
    for attempt in range(3):
        headers = {"User-Agent": "MagicNetRules/release-consumer"}
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token and url.startswith("https://api.github.com/"):
            headers["Authorization"] = f"Bearer {token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("Refusing insecure redirect")
                data = response.read(limit + 1)
            if not data or len(data) > limit:
                raise ValueError("Empty or oversized release response")
            return data
        except urllib.error.HTTPError as error:
            if error.code not in (408, 429) and error.code < 500:
                raise
            if attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def checksum(text: str) -> str:
    matches = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "magicnet-rules.tar.gz":
            if not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                raise ValueError("Malformed bundle checksum")
            matches.append(parts[0])
    if len(matches) != 1:
        raise ValueError("Missing or duplicate bundle checksum")
    return matches[0]


def extract_verified(data: bytes, expected: str, stage: Path) -> None:
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Release archive SHA-256 mismatch")
    dist = stage / "dist"
    dist.mkdir()
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            name = member.name
            if (name in names or len(names) >= 512 or not member.isfile()
                    or not re.fullmatch(r"(?:[A-Za-z0-9_@!.-]+\.srs|manifest\.json)", name)
                    or member.size < 0 or member.size > 32 * 1024 * 1024):
                raise ValueError(f"Unsafe or duplicate archive member: {name}")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError("Unpacked archive exceeds limit")
            names.add(name)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"Unreadable archive member: {name}")
            with stream:
                contents = stream.read(member.size + 1)
            if len(contents) != member.size:
                raise ValueError(f"Truncated archive member: {name}")
            (dist / name).write_bytes(contents)
    verified = runtime_files(stage)
    if names != {name for _, name in verified}:
        raise ValueError("Archive file inventory does not match manifest")


def download_release(output: Path, tag: str = "") -> str:
    if output.is_symlink():
        raise ValueError("Refusing symlink output")
    output = output.absolute()
    if output.resolve() in (ROOT, Path.cwd().resolve(), Path("/")):
        raise ValueError("Refusing to replace a repository or filesystem root")
    output.parent.mkdir(parents=True, exist_ok=True)
    if not tag:
        release = json.loads(fetch(f"https://api.github.com/repos/{REPOSITORY}/releases/latest", 1024 * 1024))
        if release.get("draft") or release.get("prerelease"):
            raise ValueError("Expected a published stable Release")
        tag = release["tag_name"]
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", tag):
        raise ValueError("Invalid Release tag")
    base = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
    expected = checksum(fetch(f"{base}/SHA256SUMS", 16384).decode("utf-8"))
    # Resolve latest once, then obtain checksums and bundle from the SAME tag.
    data = fetch(f"{base}/magicnet-rules.tar.gz", MAX_ARCHIVE)
    with tempfile.TemporaryDirectory(prefix=".release-", dir=output.parent) as temporary:
        stage = Path(temporary)
        extract_verified(data, expected, stage)
        backup = stage / "previous"
        existed = output.exists()
        if existed:
            if not output.is_dir():
                raise ValueError("Output exists and is not a directory")
            output.rename(backup)
        try:
            (stage / "dist").rename(output)
        except OSError:
            if existed:
                backup.rename(output)
            raise
    print(f"Verified MagicNetRules {tag}: sha256:{expected}")
    return tag


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default=os.environ.get("MAGICNET_RULES_TAG", ""),
                        help="Pin a Release tag; default resolves latest once")
    args = parser.parse_args()
    download_release(args.output, args.tag)


if __name__ == "__main__":
    main()
