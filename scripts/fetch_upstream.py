#!/usr/bin/env python3
"""Fetch and refresh raw rule sets from remote upstream repositories."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES_DIR = ROOT / "sources"
BINARY_DIR = ROOT / "sources_binary"

UPSTREAMS = [
    {
        "name": "MetaCubeX",
        "repo": "https://github.com/MetaCubeX/meta-rules-dat.git",
        "branch": "sing",
        "path_prefix": "geo/geosite",
    },
    {
        "name": "lyc8503-geosite",
        "repo": "https://github.com/lyc8503/sing-box-rules.git",
        "branch": "rule-set-geosite",
        "path_prefix": "",
    },
    {
        "name": "lyc8503-geoip",
        "repo": "https://github.com/lyc8503/sing-box-rules.git",
        "branch": "rule-set-geoip",
        "path_prefix": "",
    },
    {
        "name": "KaringX",
        "repo": "https://github.com/KaringX/karing-ruleset.git",
        "branch": "sing",
        "path_prefix": "ACL4SSR",
    },
]


def resolve_branch_commit(repo: str, branch: str) -> str:
    res = subprocess.run(["git", "ls-remote", repo, f"refs/heads/{branch}"], capture_output=True, text=True)
    if res.returncode == 0 and res.stdout:
        return res.stdout.split()[0]
    raise RuntimeError(f"Failed to resolve {repo}@{branch}")


def decompile_srs(srs_path: Path, output_json: Path) -> bool:
    core = shutil.which("sing-box")
    if not core:
        return False
    res = subprocess.run([core, "rule-set", "decompile", str(srs_path), "--output", str(output_json)], capture_output=True)
    return res.returncode == 0


def fetch_chatgpt_voice() -> None:
    """Fetch OpenAI voice prefixes from SukkaW's feed."""
    url = "https://gitlab.com/SukkaW/ruleset.skk.moe/-/raw/master/sing-box/ip/ai.json"
    print("Fetching SukkaLab ChatGPT voice rule-set...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MagicNetRules/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
        target = SOURCES_DIR / "sukka-chatgpt-voice.json"
        target.write_bytes(data)
        print("Updated sukka-chatgpt-voice.json")
    except Exception as e:
        print(f"Warning: Failed to fetch chatgpt voice: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch rule-sets from upstream repositories")
    parser.add_argument("--voice-only", action="store_true", help="Only refresh ChatGPT voice rules")
    args = parser.parse_args()

    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    BINARY_DIR.mkdir(parents=True, exist_ok=True)

    if args.voice_only:
        fetch_chatgpt_voice()
        return

    fetch_chatgpt_voice()
    print("Upstream fetch logic ready.")


if __name__ == "__main__":
    main()
