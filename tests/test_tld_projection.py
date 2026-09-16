"""Regression cases from the real primary feeds, not permissive DNS parsing."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from text_sources import domain, load_registry, parse_text


class TldProjectionTests(unittest.TestCase):
    def test_domestic_tlds_require_explicit_source_allowance(self):
        allowed = ["cn", "xn--55qx5d", "xn--fiqs8s", "xn--io0a7i"]
        descriptor = {"format": "dnsmasq", "min_entries": 1, "max_entries": 100,
                      "allow_tlds": allowed}
        data = "".join(f"server=/{tld}/114.114.114.114\n" for tld in allowed).encode()
        document, _ = parse_text(data, descriptor)
        self.assertEqual(document["rules"], [{"domain_suffix": sorted(allowed)}])
        for tld in ["com", "net", "org"]:
            with self.subTest(tld=tld), self.assertRaises(ValueError):
                parse_text(f"server=/{tld}/114.114.114.114".encode(), descriptor)
        for tld in allowed:
            with self.assertRaises(ValueError):
                domain(tld)

    def test_registry_has_only_reviewed_domestic_tlds(self):
        registry = load_registry()
        self.assertEqual(set(registry["felixonmars-cn"]["allow_tlds"]),
                         {"cn", "xn--55qx5d", "xn--fiqs8s", "xn--io0a7i"})
        self.assertEqual(registry["blackmatrix-wechat"]["omit_types"], ["IP-ASN"])

    def test_registry_rejects_tld_allowance_in_other_formats(self):
        source = load_registry()["blackmatrix-github"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(json.dumps({"example": {**source, "allow_tlds": ["cn"]}}))
            with self.assertRaises(ValueError):
                load_registry(path)

    def test_registry_rejects_malformed_tlds(self):
        source = load_registry()["felixonmars-cn"]
        for value in [["example.com"], ["../cn"], ["CN"], ["*"], ["1"], "cn", [None]]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "sources.json"
                path.write_text(json.dumps({"example": {**source, "allow_tlds": value}}))
                with self.assertRaises(ValueError):
                    load_registry(path)


if __name__ == "__main__":
    unittest.main()
