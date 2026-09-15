"""Parity tests verifying that optimized rule sets match upstream coverage."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"
CONFIG_PATH = ROOT / "config" / "rulesets.json"
SOURCES_DIR = ROOT / "sources"


def as_list(val):
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


class ParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = shutil.which("sing-box")
        if not cls.core:
            raise unittest.SkipTest("sing-box binary not found in PATH")
        cls.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    def match(self, rule_name: str, target: str) -> bool:
        path = DIST_DIR / f"{rule_name}.srs"
        cmd = [self.core, "rule-set", "match", "-f", "binary", str(path), target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout.strip() or proc.stderr.strip()
        return "match rules" in output or "matched" in output

    def test_merged_ruleset_parity_with_sources(self):
        """Verify that representative items from constituent sources match the merged rule set."""
        merged = self.config.get("merged_rulesets", {})
        for merged_tag, meta in merged.items():
            sources = meta["sources"]
            sample_domains = []
            sample_cidrs = []
            for src in sources:
                src_path = SOURCES_DIR / f"{src}.json"
                if not src_path.is_file():
                    continue
                data = json.loads(src_path.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    suffixes = as_list(rule.get("domain_suffix"))
                    if suffixes:
                        sample_domains.append(suffixes[0])
                    domains = as_list(rule.get("domain"))
                    if domains:
                        sample_domains.append(domains[0])
                    cidrs = as_list(rule.get("ip_cidr"))
                    if cidrs:
                        ip = cidrs[0].split("/")[0]
                        sample_cidrs.append(ip)

            # Test up to 5 sample domains per merged set
            for domain in sample_domains[:5]:
                with self.subTest(merged=merged_tag, target=domain):
                    self.assertTrue(
                        self.match(merged_tag, domain),
                        f"Domain '{domain}' from source failed to match merged rule set {merged_tag}",
                    )

            # Test up to 3 sample IPs per merged set
            for ip in sample_cidrs[:3]:
                with self.subTest(merged=merged_tag, target=ip):
                    self.assertTrue(
                        self.match(merged_tag, ip),
                        f"IP '{ip}' from source failed to match merged rule set {merged_tag}",
                    )


if __name__ == "__main__":
    unittest.main()
