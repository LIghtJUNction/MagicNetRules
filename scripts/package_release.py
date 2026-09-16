#!/usr/bin/env python3
"""Validate and produce reproducible runtime/audit archives outside Git."""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def runtime_files(root: Path) -> list[tuple[Path, str]]:
    dist = root / "dist"
    if dist.is_symlink():
        raise ValueError("Refusing symlink dist")
    manifest_path = dist / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Refusing symlink manifest")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or not manifest.get("rulesets"):
        raise ValueError("Invalid or empty build manifest")
    files = [(manifest_path, "manifest.json")]
    for name, metadata in sorted(manifest["rulesets"].items()):
        if not re.fullmatch(r"[A-Za-z0-9_@!.-]+", name) or name in (".", ".."):
            raise ValueError(f"Unsafe rule name: {name}")
        path = dist / f"{name}.srs"
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or unsafe rule: {name}")
        with path.open("rb") as stream:
            if stream.read(3) != b"SRS":
                raise ValueError(f"Invalid SRS header: {name}")
        if digest(path) != metadata["sha256_srs"] or path.stat().st_size != metadata["srs_size"]:
            raise ValueError(f"Rule checksum/size mismatch: {name}")
        files.append((path, path.name))
    if {path.name for path in dist.glob("*.srs")} != {name for _, name in files[1:]}:
        raise ValueError("Unlisted SRS files in dist")
    return files


def archive(output: Path, files: list[tuple[Path, str]]) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path, name in sorted(files, key=lambda item: item[1]):
                    if path.is_symlink() or not path.is_file():
                        raise ValueError(f"Missing or unsafe archive input: {path}")
                    info = tar.gettarinfo(str(path), arcname=name)
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o644
                    info.pax_headers = {}
                    with path.open("rb") as stream:
                        tar.addfile(info, stream)


def package(root: Path = ROOT) -> None:
    files = runtime_files(root)
    provenance = root / ".cache/upstream-manifest.json"
    snapshot = json.loads(provenance.read_text())
    if snapshot.get("version") != 1 or not snapshot.get("sources"):
        raise ValueError("Missing upstream provenance")
    audit = [(provenance, "upstream-manifest.json")]
    for directory in ("sources", "sources_binary"):
        folder = root / directory
        if folder.is_symlink():
            raise ValueError(f"Unsafe source directory: {directory}")
        audit.extend((path, f"{directory}/{path.name}") for path in sorted(folder.iterdir()))
    for name in ("config/rulesets.json", "config/text-sources.json", "scripts/builder.py",
                 "scripts/fetch_upstream.py", "scripts/text_sources.py", "scripts/install-compiler.sh",
                 "docs/primary-sources.md", "LICENSE"):
        audit.append((root / name, name))
    release = root / "release"
    if release.is_symlink():
        raise ValueError("Refusing symlink release directory")
    with tempfile.TemporaryDirectory(prefix=".release-", dir=root) as temporary:
        stage = Path(temporary)
        archive(stage / "magicnet-rules.tar.gz", files)
        archive(stage / "magicnet-rules-sources.tar.gz", audit)
        shutil.copyfile(provenance, stage / "upstream-manifest.json")
        names = ("magicnet-rules.tar.gz", "magicnet-rules-sources.tar.gz", "upstream-manifest.json")
        (stage / "SHA256SUMS").write_text("".join(f"{digest(stage / name)}  {name}\n" for name in names))
        release.mkdir(exist_ok=True)
        for path in stage.iterdir():
            path.replace(release / path.name)
    print("Validated runtime bundle, audit snapshot, provenance and SHA256SUMS are in release/")


if __name__ == "__main__":
    package()
