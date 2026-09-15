"""Tests verifying deduplication and optimization guarantees."""

import ipaddress
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"


class DeduplicationTests(unittest.TestCase):
    def test_no_exact_duplicates(self):
        """Ensure no duplicate items exist in any domain or suffix array in dist/."""
        for jf in DIST_DIR.glob("*.json"):
            if jf.name == "manifest.json":
                continue
            with self.subTest(file=jf.name):
                data = json.loads(jf.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    for field in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"):
                        if field in rule and isinstance(rule[field], list):
                            items = rule[field]
                            self.assertEqual(len(items), len(set(items)), f"{jf.name} has duplicate {field}")

    def test_no_redundant_domain_covered_by_suffix(self):
        """Ensure no exact domain is redundant when an ancestor domain_suffix is present."""
        for jf in DIST_DIR.glob("*.json"):
            if jf.name == "manifest.json":
                continue
            with self.subTest(file=jf.name):
                data = json.loads(jf.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    suffixes = set(rule.get("domain_suffix", []))
                    if not suffixes:
                        continue
                    domains = rule.get("domain", [])
                    for d in domains:
                        parts = d.lower().split(".")
                        # Check all possible suffix tails
                        for i in range(len(parts)):
                            sub = ".".join(parts[i:])
                            self.assertNotIn(
                                sub,
                                suffixes,
                                f"{jf.name}: domain '{d}' is redundant because suffix '{sub}' is present",
                            )

    def test_no_redundant_suffix_covered_by_broader_suffix(self):
        """Ensure no suffix is redundant with a broader suffix in the same rule."""
        for jf in DIST_DIR.glob("*.json"):
            if jf.name == "manifest.json":
                continue
            with self.subTest(file=jf.name):
                data = json.loads(jf.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    suffixes = sorted(rule.get("domain_suffix", []), key=lambda s: len(s.split(".")))
                    seen = set()
                    for s in suffixes:
                        parts = s.lower().split(".")
                        for i in range(1, len(parts)):
                            parent = ".".join(parts[i:])
                            self.assertNotIn(
                                parent,
                                seen,
                                f"{jf.name}: suffix '{s}' is redundant because parent suffix '{parent}' is present",
                            )
                        seen.add(s.lower())

    def test_ip_cidrs_collapsed(self):
        """Ensure IP CIDRs are fully collapsed (no overlapping or contiguous mergeable blocks)."""
        for jf in DIST_DIR.glob("*.json"):
            if jf.name == "manifest.json":
                continue
            with self.subTest(file=jf.name):
                data = json.loads(jf.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    cidrs = rule.get("ip_cidr", [])
                    if not cidrs:
                        continue
                    v4 = [ipaddress.ip_network(c) for c in cidrs if ":" not in c]
                    v6 = [ipaddress.ip_network(c) for c in cidrs if ":" in c]
                    collapsed_v4 = list(ipaddress.collapse_addresses(v4))
                    collapsed_v6 = list(ipaddress.collapse_addresses(v6))
                    self.assertEqual(len(v4), len(collapsed_v4), f"{jf.name}: IPv4 CIDRs were not fully collapsed")
                    self.assertEqual(len(v6), len(collapsed_v6), f"{jf.name}: IPv6 CIDRs were not fully collapsed")


if __name__ == "__main__":
    unittest.main()
