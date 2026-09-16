#!/usr/bin/env python3
"""Fetch a complete build-time snapshot; never publish partial/stale inputs."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from text_sources import load_registry, parse_text

ROOT = Path(__file__).resolve().parents[1]
TEXT_SOURCES = load_registry()
MAX_BYTES = 32 * 1024 * 1024
NAME = re.compile(r"[a-z0-9_@!.-]+")
VOICE_URL = "https://gitlab.com/SukkaW/ruleset.skk.moe/-/raw/master/sing-box/ip/ai.json"
KARING = {
    "ai": "AI", "wechat": "Wechat", "proxy-lite": "ProxyLite",
    "proxy-gfwlist": "ProxyGFWlist", "banad": "BanAD",
    "china-domain": "ChinaDomain", "china-ip": "ChinaIp", "proxy-media": "ProxyMedia",
}


def source_location(name: str) -> tuple[str, str, str]:
    """Return repository, branch, path. Inventory remains in rulesets.json."""
    if not NAME.fullmatch(name) or name in (".", ".."):
        raise ValueError(f"Unsafe source name: {name!r}")
    if name in TEXT_SOURCES:
        spec = TEXT_SOURCES[name]
        return spec["repository"], spec["branch"], spec["path"]
    if name.startswith("metacubex-service-"):
        return "MetaCubeX/meta-rules-dat", "sing", f"geo/geosite/{name[18:]}.srs"
    special = {
        "metacubex-geosite-cn": ("MetaCubeX/meta-rules-dat", "sing", "geo/geosite/cn.srs"),
        "metacubex-geoip-cn": ("MetaCubeX/meta-rules-dat", "sing", "geo/geoip/cn.srs"),
        "metacubex-geosite-geolocation-not-cn": ("MetaCubeX/meta-rules-dat", "sing", "geo/geosite/geolocation-!cn.srs"),
        "yuu-geosite-pcdn-cn": ("Yuu518/sing-box-rules", "rule_set", "rule_set_site/pcdn-cn.srs"),
        "yuu-geosite-stream-global": ("Yuu518/sing-box-rules", "rule_set", "rule_set_site/stream-global.srs"),
        "yuu-geosite-ai": ("Yuu518/sing-box-rules", "rule_set", "rule_set_site/category-ai-!cn.srs"),
    }
    if name in special:
        return special[name]
    if name.startswith("karing-acl4ssr-"):
        return "KaringX/karing-ruleset", "sing", f"ACL4SSR/{KARING[name[15:]]}.srs"
    if name in ("ddch-direct", "ddch-proxy", "ddch-gfw"):
        return "DDCHlsq/sing-ruleset", "ruleset", f"{name[5:]}.srs"
    if name in ("hagezi-light", "hagezi-normal", "hagezi-anti-piracy"):
        return "razaxq/dns-blocklists-sing-box", "rule-set", f"{name}.srs"
    if name.startswith("geoip-"):
        return "lyc8503/sing-box-rules", "rule-set-geoip", f"{name}.srs"
    if name.startswith("geosite-"):
        return "lyc8503/sing-box-rules", "rule-set-geosite", f"{name}.srs"
    raise ValueError(f"No upstream mapping for {name!r}")


def inventory(config: dict) -> tuple[list[str], list[str]]:
    names = set(config["standalone_sources"])
    for entry in config["merged_rulesets"].values():
        names.update(entry["sources"])
    for values in config["service_rulesets"].values():
        names.update(values)
    binaries = config["binary_sources"]
    if len(binaries) != len(set(binaries)):
        raise ValueError("Duplicate binary sources")
    for filename in binaries:
        if not filename.endswith(".srs"):
            raise ValueError(f"Invalid binary source: {filename}")
        if filename[:-4] in TEXT_SOURCES:
            raise ValueError(f"Text feed cannot be a binary passthrough: {filename}")
        source_location(filename[:-4])
        if filename[:-4] in names:
            raise ValueError(f"Source collision: {filename}")
    for name in names:
        if name != "sukka-chatgpt-voice":
            source_location(name)
    if not names:
        raise ValueError("Empty source inventory")
    return sorted(names), sorted(binaries)


def resolve_commit(repo: str, branch: str) -> str:
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["git", "ls-remote", f"https://github.com/{repo}.git", f"refs/heads/{branch}"],
                check=True, text=True, capture_output=True, timeout=45,
            )
            rows = result.stdout.splitlines()
            if len(rows) != 1:
                raise ValueError(f"Expected one upstream ref for {repo}@{branch}")
            sha, ref = rows[0].split()
            if not re.fullmatch(r"[0-9a-f]{40}", sha) or ref != f"refs/heads/{branch}":
                raise ValueError(f"Invalid upstream ref for {repo}@{branch}")
            return sha
        except (subprocess.SubprocessError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS upstreams are accepted")
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "MagicNetRules/build"})
            with urllib.request.urlopen(request, timeout=45) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("Refusing insecure redirect")
                data = response.read(MAX_BYTES + 1)
            if not data or len(data) > MAX_BYTES:
                raise ValueError(f"Empty or oversized upstream: {url}")
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


def validate_json(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or document.get("version") not in (1, 2)
            or not isinstance(document.get("rules"), list) or not document["rules"]
            or any(not isinstance(rule, dict) or not rule for rule in document["rules"])):
        raise ValueError(f"Invalid or empty rule source: {path.name}")


def fetch_one(name: str, binary: bool, commits: dict, stage: Path, compiler: str) -> dict:
    if binary and name in TEXT_SOURCES:
        raise ValueError(f"Text feed cannot be a binary passthrough: {name}")
    if name == "sukka-chatgpt-voice":
        url = VOICE_URL
    else:
        repo, branch, path = source_location(name)
        url = f"https://raw.githubusercontent.com/{repo}/{commits[repo, branch]}/{path}"
    data = download(url)
    target = stage / ("sources_binary" if binary else "sources") / f"{name}{'.srs' if binary else '.json'}"
    audit = {}
    if name in TEXT_SOURCES:
        document, audit = parse_text(data, TEXT_SOURCES[name])
        target.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        validate_json(target)
        # Exact original text is audit/source material, never a runtime artifact.
        original = stage / "sources" / f"{name}.upstream.txt"
        original.write_bytes(data)
        audit.update({"license": TEXT_SOURCES[name]["license"], "original": f"sources/{original.name}"})
    elif name == "sukka-chatgpt-voice":
        target.write_bytes(data)
        validate_json(target)
    else:
        if len(data) < 4 or data[:3] != b"SRS":
            raise ValueError(f"Invalid SRS header: {name}")
        if binary:
            # AdGuard binary matchers are intentionally not reversible to JSON.
            # check constructs the local rule-set and parses its actual SRS data.
            target.write_bytes(data)
            check = stage / "raw" / f"{name}.check.json"
            check.write_text(json.dumps({
                "log": {"disabled": True},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {
                    "rule_set": [{"type": "local", "tag": "validate-source",
                                  "format": "binary", "path": str(target)}],
                    "rules": [{"rule_set": ["validate-source"], "outbound": "direct"}],
                },
            }))
            command = [compiler, "check", "-c", str(check)]
        else:
            raw = stage / "raw" / f"{name}.srs"
            raw.write_bytes(data)
            command = [compiler, "rule-set", "decompile", str(raw), "--output", str(target)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"Cannot validate {name}: {result.stderr[:4000]}")
        if not binary:
            validate_json(target)
    print(f"Fetched and validated {name}", flush=True)
    return {"name": name, "url": url, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "binary_only": binary, **audit}


def install_snapshot(stage: Path, root: Path) -> None:
    """Replace all inputs together, restoring the prior snapshot on any failure."""
    cache = root / ".cache"
    if cache.is_symlink():
        raise ValueError("Refusing symlink cache directory")
    cache.mkdir(exist_ok=True)
    pairs = [(stage / name, root / name) for name in ("sources", "sources_binary")]
    pairs.append((stage / "upstream-manifest.json", cache / "upstream-manifest.json"))
    for _, destination in pairs:
        if destination.is_symlink():
            raise ValueError(f"Refusing symlink destination: {destination}")
    replaced = []
    try:
        for index, (source, destination) in enumerate(pairs):
            backup = stage / f"previous-{index}"
            existed = destination.exists()
            if existed:
                destination.rename(backup)
            replaced.append((destination, backup, existed))
            source.rename(destination)
    except OSError:
        for destination, backup, existed in reversed(replaced):
            if destination.is_dir():
                shutil.rmtree(destination)
            elif destination.exists():
                destination.unlink()
            if existed:
                backup.rename(destination)
        raise


def main() -> None:
    compiler = shutil.which("sing-box")
    if not compiler:
        raise RuntimeError("Install the pinned sing-box compiler before fetching sources")
    config = json.loads((ROOT / "config/rulesets.json").read_text())
    names, binaries = inventory(config)
    jobs = [(name, False) for name in names] + [(name[:-4], True) for name in binaries]
    upstreams = sorted({source_location(name)[:2] for name, _ in jobs if name != "sukka-chatgpt-voice"})
    licenses = sorted({(TEXT_SOURCES[name]["repository"], TEXT_SOURCES[name]["license_branch"],
                        TEXT_SOURCES[name]["license_path"]) for name in names if name in TEXT_SOURCES})
    upstreams = sorted(set(upstreams) | {(repo, branch) for repo, branch, _ in licenses})
    commits = {(repo, branch): resolve_commit(repo, branch) for repo, branch in upstreams}
    with tempfile.TemporaryDirectory(prefix=".upstream-", dir=ROOT) as temporary:
        stage = Path(temporary)
        for directory in ("sources", "sources_binary", "raw"):
            (stage / directory).mkdir()
        license_records = []
        for repo, branch, path in licenses:
            url = f"https://raw.githubusercontent.com/{repo}/{commits[repo, branch]}/{path}"
            data = download(url)
            text = data.decode("utf-8")
            if "<html" in text.lower() or "<!doctype" in text.lower() or len(text.strip()) < 100:
                raise ValueError(f"Invalid license document: {repo}")
            filename = f"{repo.replace('/', '--')}.LICENSE.txt"
            (stage / "sources" / filename).write_bytes(data)
            license_records.append({"repository": repo, "url": url, "file": f"sources/{filename}",
                                    "sha256": hashlib.sha256(data).hexdigest()})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(fetch_one, name, binary, commits, stage, compiler) for name, binary in jobs]
            records = [future.result() for future in futures]
        manifest = {"version": 1, "licenses": license_records, "upstreams": [
            {"repository": repo, "branch": branch, "commit": commits[repo, branch]}
            for repo, branch in upstreams], "sources": sorted(records, key=lambda item: item["name"])}
        (stage / "upstream-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        install_snapshot(stage, ROOT)
    print(f"Complete snapshot ready: {len(jobs)} sources from {len(upstreams)} Git refs + SukkaLab HTTPS feed")


if __name__ == "__main__":
    main()
