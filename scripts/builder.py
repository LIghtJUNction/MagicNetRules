#!/usr/bin/env python3
"""Rule-set optimizer, deduplicator, merger, and compiler for sing-box.

Builds consolidated, service-specific, and standalone rule-sets for MagicNet.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "rulesets.json"
SOURCES_DIR = ROOT / "sources"
BINARY_DIR = ROOT / "sources_binary"
DIST_DIR = ROOT / "dist"


class DomainTrie:
    """Trie for domain suffixes to identify and prune redundant subdomains and sub-suffixes."""

    def __init__(self) -> None:
        self.root: Dict[str, Any] = {}

    def insert_suffix(self, domain: str) -> bool:
        """Insert a domain suffix into the trie.

        Returns True if the suffix is new and kept.
        Returns False if it is redundant (already covered by a broader suffix).
        """
        clean = domain.strip(".").lower()
        if not clean:
            return False
        parts = clean.split(".")[::-1]
        node = self.root
        for part in parts:
            if "_term" in node:
                return False  # An existing broader suffix covers this
            if part not in node:
                node[part] = {}
            node = node[part]
        if "_term" in node:
            return False
        # Clear child nodes as this new suffix is broader than any prior longer suffixes
        node.clear()
        node["_term"] = True
        return True

    def matches(self, domain: str) -> bool:
        """Return True if the domain is covered by any existing suffix in the trie."""
        clean = domain.strip(".").lower()
        if not clean:
            return False
        parts = clean.split(".")[::-1]
        node = self.root
        for part in parts:
            if "_term" in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return "_term" in node


class IpOptimizer:
    """Aggregates and collapses IPv4 and IPv6 subnets into minimal supernets."""

    @staticmethod
    def optimize(cidrs: List[str]) -> List[str]:
        v4_nets: List[ipaddress.IPv4Network] = []
        v6_nets: List[ipaddress.IPv6Network] = []
        for c in cidrs:
            c = c.strip()
            if not c:
                continue
            try:
                net = ipaddress.ip_network(c, strict=False)
                if net.version == 4:
                    v4_nets.append(net)
                else:
                    v6_nets.append(net)
            except ValueError:
                continue

        collapsed_v4 = sorted(
            list(ipaddress.collapse_addresses(v4_nets)),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        collapsed_v6 = sorted(
            list(ipaddress.collapse_addresses(v6_nets)),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )

        return [f"{net.network_address}/{net.prefixlen}" for net in collapsed_v4 + collapsed_v6]


def optimize_rule_components(
    domains: Set[str],
    suffixes: Set[str],
    keywords: Set[str],
    regexes: Set[str],
    cidrs: Set[str],
) -> Dict[str, Any]:
    """Deduplicate and optimize individual rule components."""
    # 1. Optimize domain suffixes using trie
    trie = DomainTrie()
    # Sort suffixes by ascending label count, then length (broader suffixes first)
    sorted_suffixes = sorted(suffixes, key=lambda s: (len(s.split(".")), len(s)))
    kept_suffixes = sorted([s for s in sorted_suffixes if trie.insert_suffix(s)])

    # 2. Prune exact domains covered by any suffix
    kept_domains = sorted([d for d in domains if not trie.matches(d)])

    # 3. Collapse IP CIDRs
    collapsed_cidrs = IpOptimizer.optimize(list(cidrs))

    # 4. Deduplicate keywords and regexes
    cleaned_keywords = sorted(list(keywords))
    cleaned_regexes = sorted(list(regexes))

    rule_obj: Dict[str, Any] = {}
    if kept_domains:
        rule_obj["domain"] = kept_domains
    if kept_suffixes:
        rule_obj["domain_suffix"] = kept_suffixes
    if cleaned_keywords:
        rule_obj["domain_keyword"] = cleaned_keywords
    if cleaned_regexes:
        rule_obj["domain_regex"] = cleaned_regexes
    if collapsed_cidrs:
        rule_obj["ip_cidr"] = collapsed_cidrs

    return rule_obj


def load_source_rules(source_name: str) -> List[Dict[str, Any]]:
    """Load raw rule objects from sources/<source_name>.json."""
    path = SOURCES_DIR / f"{source_name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("rules", [])


def merge_and_optimize_sources(source_names: List[str]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Merge multiple rule sources into a single optimized rule-set."""
    domains: Set[str] = set()
    suffixes: Set[str] = set()
    keywords: Set[str] = set()
    regexes: Set[str] = set()
    cidrs: Set[str] = set()

    raw_stats = {"domains": 0, "suffixes": 0, "keywords": 0, "regexes": 0, "cidrs": 0}

    for name in source_names:
        rules = load_source_rules(name)
        for r in rules:
            raw_d = r.get("domain", [])
            raw_s = r.get("domain_suffix", [])
            raw_k = r.get("domain_keyword", [])
            raw_rx = r.get("domain_regex", [])
            raw_c = r.get("ip_cidr", [])

            for item in raw_d if isinstance(raw_d, list) else ([raw_d] if raw_d else []):
                domains.add(item.strip().lower())
                raw_stats["domains"] += 1
            for item in raw_s if isinstance(raw_s, list) else ([raw_s] if raw_s else []):
                suffixes.add(item.strip().lower())
                raw_stats["suffixes"] += 1
            for item in raw_k if isinstance(raw_k, list) else ([raw_k] if raw_k else []):
                keywords.add(item.strip())
                raw_stats["keywords"] += 1
            for item in raw_rx if isinstance(raw_rx, list) else ([raw_rx] if raw_rx else []):
                regexes.add(item.strip())
                raw_stats["regexes"] += 1
            for item in raw_c if isinstance(raw_c, list) else ([raw_c] if raw_c else []):
                cidrs.add(item.strip())
                raw_stats["cidrs"] += 1

    optimized_rule = optimize_rule_components(domains, suffixes, keywords, regexes, cidrs)
    result = {
        "version": 2,
        "rules": [optimized_rule] if optimized_rule else [],
    }

    opt_stats = {
        "domains": len(optimized_rule.get("domain", [])),
        "suffixes": len(optimized_rule.get("domain_suffix", [])),
        "keywords": len(optimized_rule.get("domain_keyword", [])),
        "regexes": len(optimized_rule.get("domain_regex", [])),
        "cidrs": len(optimized_rule.get("ip_cidr", [])),
        "raw_total": sum(raw_stats.values()),
    }
    opt_stats["opt_total"] = (
        opt_stats["domains"]
        + opt_stats["suffixes"]
        + opt_stats["keywords"]
        + opt_stats["regexes"]
        + opt_stats["cidrs"]
    )
    return result, opt_stats


def compile_ruleset(json_path: Path, srs_path: Path) -> None:
    """Compile a sing-box JSON rule-set to binary SRS format."""
    core = shutil.which("sing-box")
    if not core:
        raise RuntimeError("sing-box binary not found in PATH")

    cmd = [core, "rule-set", "compile", str(json_path), "--output", str(srs_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to compile {json_path.name}: {res.stderr}")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_all(check: bool = False) -> Dict[str, Any]:
    """Execute build pipeline: optimize, merge, write JSON, compile SRS, and generate manifest."""
    start_time = time.time()
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    targets: Dict[str, List[str]] = {}

    # 1. Merged rulesets
    for tag, meta in config.get("merged_rulesets", {}).items():
        targets[tag] = meta["sources"]

    # 2. Service rulesets
    for tag, sources in config.get("service_rulesets", {}).items():
        targets[tag] = sources

    # 3. Standalone rulesets (1:1 preservation and optimization)
    for src in config.get("standalone_sources", []):
        targets[src] = [src]

    manifest: Dict[str, Any] = {
        "version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rulesets": {},
    }

    print(f"Building {len(targets)} rule sets into dist/ ...")
    total_raw_rules = 0
    total_opt_rules = 0

    for target_name, source_names in targets.items():
        json_file = DIST_DIR / f"{target_name}.json"
        srs_file = DIST_DIR / f"{target_name}.srs"

        rule_data, stats = merge_and_optimize_sources(source_names)
        json_content = json.dumps(rule_data, ensure_ascii=False, indent=2) + "\n"

        if check and json_file.is_file():
            current_content = json_file.read_text(encoding="utf-8")
            if current_content != json_content:
                raise AssertionError(f"Rule-set output out of date: {json_file.name}")
        else:
            json_file.write_text(json_content, encoding="utf-8")

        # Compile to .srs
        compile_ruleset(json_file, srs_file)

        total_raw_rules += stats["raw_total"]
        total_opt_rules += stats["opt_total"]

        manifest["rulesets"][target_name] = {
            "json_size": json_file.stat().st_size,
            "srs_size": srs_file.stat().st_size,
            "sha256_srs": file_sha256(srs_file),
            "stats": stats,
            "sources": source_names,
        }

    # Copy binary sources (e.g. AdGuard rule sets) into dist/
    if BINARY_DIR.is_dir():
        for bin_file in BINARY_DIR.glob("*.srs"):
            dest_bin = DIST_DIR / bin_file.name
            shutil.copy2(bin_file, dest_bin)
            manifest["rulesets"][bin_file.stem] = {
                "srs_size": dest_bin.stat().st_size,
                "sha256_srs": file_sha256(dest_bin),
                "binary_only": True,
            }

    # Save manifest
    manifest_path = DIST_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    elapsed = time.time() - start_time
    saved = total_raw_rules - total_opt_rules
    pct = (saved / total_raw_rules * 100) if total_raw_rules > 0 else 0
    print(f"Build completed in {elapsed:.2f}s:")
    print(f"  Total raw rules: {total_raw_rules}")
    print(f"  Optimized rules: {total_opt_rules}")
    print(f"  Reduction: {saved} rules pruned / merged ({pct:.1f}% reduction)")
    print(f"  Generated files saved to: {DIST_DIR}")

    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile and optimize sing-box rule sets")
    parser.add_argument("--check", action="store_true", help="Verify dist/ files are up to date without writing")
    args = parser.parse_args()

    try:
        build_all(check=args.check)
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
