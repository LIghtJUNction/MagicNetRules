#!/usr/bin/env python3
"""Build offline-capable MagicBox rules from hash-pinned upstream data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

from catalog import build_catalog, compact

ROOT = Path(__file__).resolve().parent
LIMIT = 16 * 1024 * 1024
LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")
SENTINELS = {"play.googleapis.com", "android.clients.google.com", "accounts.google.com",
             "mtalk.google.com", "weixin.qq.com", "res.wx.qq.com", "login.weixin.qq.com", "github.com"}


def fetch(entry, override=None):
    with (open(override, "rb") if override else urlopen(entry["url"], timeout=75)) as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("source size or digest mismatch for " + entry["url"])
    return data


def parse_exact(data):
    domains = set()
    count = 0
    for n, raw in enumerate(data.decode("ascii").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = line.removesuffix(".").lower()
        if len(name) > 253 or not all(LABEL.fullmatch(part) for part in name.split(".")):
            raise ValueError(f"invalid domain at line {n}")
        domains.add(name)
        count += 1
    if domains & SENTINELS:
        raise ValueError("blocklist includes a protected service name")
    if not domains:
        raise ValueError("empty blocklist")
    return sorted(domains), count


def write_changed(directory, files):
    # A packaging job stages a fresh output tree. Rebuilding in place touches
    # only changed objects. Publish the index after writing all new objects.
    for name in sorted(files, key=lambda key: (key == "catalog/index.json", key)):
        target = directory / name
        data = files[name]
        if target.is_file() and target.read_bytes() == data:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as f:
            temp = Path(f.name)
            try:
                f.write(data)
                f.flush()
                os.fchmod(f.fileno(), 0o644)
                os.fsync(f.fileno())
            except BaseException:
                temp.unlink(missing_ok=True)
                raise
        try:
            os.replace(temp, target)
        finally:
            temp.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--archive", help="local MagicNetRules source tar.gz, used with --all")
    p.add_argument("--light", help="local pinned HaGeZi source")
    p.add_argument("--license", help="local pinned GPL license text")
    p.add_argument("--all", action="store_true", help="also compile all source-readable category sets")
    args = p.parse_args()
    lock = json.loads((ROOT / "sources.lock.json").read_text())
    data = fetch(lock["light"], args.light)
    license_text = fetch(lock["license"], args.license)
    names, count = parse_exact(data)
    if not 1000 <= len(names) <= 350_000:
        raise ValueError("unexpected protection list size")
    block = ("magicbox-exact-v1\n" + "\n".join(names) + "\n").encode("ascii")
    stats = {"exact_input_entries": count, "exact_output_entries": len(names),
             "exact_pack_bytes": len(block), "exact_pack_sha256": hashlib.sha256(block).hexdigest()}
    # The source is text. The immutable URL and corresponding GPL license travel
    # with the runtime package; the catalog index stays out of a normal install.
    notice = ("HaGeZi DNS Blocklists, Multi LIGHT. GPL-3.0. Exact-name projection.\n"
              + "Source and version: " + lock["light"]["url"] + "\n"
              + "Original SHA-256: " + lock["light"]["sha256"] + "\n"
              + "Changes: ASCII case/root-dot normalization, unique sort and format header.\n")
    files = {"block.txt": block, "COPYING.HaGeZi": license_text, "NOTICE.txt": notice.encode()}
    if args.all:
        more, report = build_catalog(fetch(lock["archive"], args.archive), names)
        files.update(more)
        stats["catalog"] = report
        files["catalog/source-lock.json"] = compact(lock) + b"\n"
    write_changed(args.out, files)
    print(json.dumps(stats, sort_keys=True))


if __name__ == "__main__":
    main()
