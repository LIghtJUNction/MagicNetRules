"""Schema and syntax validation for sing-box rule sets."""

import ipaddress
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"
ALLOWED_RULE_KEYS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "source_ip_cidr",
    "port",
    "port_range",
    "network",
    "package_name",
    "user",
    "user_id",
    "inbound",
    "outbound",
    "process_name",
    "process_path",
    "wifi_ssid",
    "wifi_bssid",
    "invert",
}


class RuleSetSchemaTests(unittest.TestCase):
    def test_dist_json_files_schema(self):
        json_files = list(DIST_DIR.glob("*.json"))
        self.assertGreater(len(json_files), 0, "No JSON files found in dist/")

        for jf in json_files:
            if jf.name == "manifest.json":
                continue
            with self.subTest(file=jf.name):
                data = json.loads(jf.read_text(encoding="utf-8"))
                self.assertIn("version", data, f"{jf.name} missing 'version'")
                self.assertIn(data["version"], (1, 2, 3), f"{jf.name} unsupported version: {data['version']}")
                self.assertIn("rules", data, f"{jf.name} missing 'rules'")
                self.assertIsInstance(data["rules"], list, f"{jf.name} 'rules' must be a list")

                for idx, rule in enumerate(data["rules"]):
                    self.assertIsInstance(rule, dict, f"{jf.name} rules[{idx}] is not an object")
                    unknown_keys = set(rule.keys()) - ALLOWED_RULE_KEYS
                    self.assertFalse(unknown_keys, f"{jf.name} rules[{idx}] has unknown keys: {unknown_keys}")

                    if "ip_cidr" in rule:
                        cidrs = rule["ip_cidr"] if isinstance(rule["ip_cidr"], list) else [rule["ip_cidr"]]
                        for c in cidrs:
                            net = ipaddress.ip_network(c, strict=False)
                            self.assertGreater(net.prefixlen, 0, f"{jf.name} catch-all prefix forbidden: {c}")

                    if "domain" in rule:
                        domains = rule["domain"] if isinstance(rule["domain"], list) else [rule["domain"]]
                        for d in domains:
                            self.assertIsInstance(d, str)
                            self.assertTrue(len(d.strip()) > 0, f"{jf.name} empty domain")

                    if "domain_suffix" in rule:
                        suffixes = rule["domain_suffix"] if isinstance(rule["domain_suffix"], list) else [rule["domain_suffix"]]
                        for s in suffixes:
                            self.assertIsInstance(s, str)
                            self.assertTrue(len(s.strip()) > 0, f"{jf.name} empty domain suffix")


if __name__ == "__main__":
    unittest.main()
