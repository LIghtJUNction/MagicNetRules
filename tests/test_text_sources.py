import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_upstream as fetcher
from text_sources import domain, load_registry, parse_text


def spec(fmt="clash-domain", **extra):
    return {"format": fmt, "min_entries": 1, "max_entries": 100, **extra}


class TextFormatTests(unittest.TestCase):
    def test_domain_fields_and_deduplication(self):
        doc, audit = parse_text(b"# upstream\nDOMAIN,EXAMPLE.com\nDOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,github\n", spec())
        self.assertEqual(doc["rules"], [{"domain": ["example.com"], "domain_keyword": ["github"], "domain_suffix": ["example.net"]}])
        self.assertEqual(audit["duplicates_removed"], 1)

    def test_plain_domains_are_exact_not_implicit_wildcards(self):
        doc, _ = parse_text(b"ads.example.com\n", spec("domains-exact"))
        self.assertEqual(doc["rules"], [{"domain": ["ads.example.com"]}])

    def test_dnsmasq_server_is_not_a_routing_target(self):
        doc, _ = parse_text(b"server=/Example.cn/114.114.114.114\n", spec("dnsmasq"))
        self.assertEqual(doc["rules"], [{"domain_suffix": ["example.cn"]}])

    def test_ipv4_and_ipv6_are_separate(self):
        for fmt, prefix in [("cidr4", "1.0.1.0/24"), ("cidr6", "240e::/20")]:
            doc, _ = parse_text((prefix + "\n").encode(), spec(fmt))
            self.assertEqual(doc["rules"], [{"ip_cidr": [prefix]}])
        with self.assertRaises(ValueError):
            parse_text(b"240e::/20", spec("cidr4"))

    def test_no_resolve_and_asn_are_explicitly_projected_out(self):
        doc, audit = parse_text(b"DOMAIN,example.com\nIP-CIDR,1.0.1.0/24,no-resolve\nIP-ASN,20473,no-resolve\n", spec(omit_types=["IP-CIDR", "IP-ASN"]))
        self.assertEqual(doc["rules"], [{"domain": ["example.com"]}])
        self.assertEqual(audit["omitted_types"], {"IP-ASN": 1, "IP-CIDR": 1})

    def test_undeclared_projection_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_text(b"DOMAIN,example.com\nIP-ASN,20473", spec())

    def test_unknown_semantics_are_not_silently_dropped(self):
        for line in ["AND,((DOMAIN,example.com))", "RULE-SET,remote", "MATCH,DIRECT", "DOMAIN,example.com,PROXY", "DOMAIN-SUFFIX,example.com,no-resolve", "DOMAIN-REGEX,.*", "NOT,DOMAIN,example.com", "@@||example.com^"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_text(line.encode(), spec())

    def test_malformed_omitted_rules_fail(self):
        for line in ["IP-CIDR,garbage,no-resolve", "IP-ASN,0", "IP-ASN,20473,PROXY", "PROCESS-NAME,"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_text(("DOMAIN,example.com\n" + line).encode(), spec(omit_types=["IP-CIDR", "IP-ASN", "PROCESS-NAME"]))

    def test_empty_html_and_truncated_feeds_fail(self):
        for data in [b"", b"# comments only", b"<html>upstream error</html>", b"server=/example.cn/"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_text(data, spec("dnsmasq"))

    def test_rejects_wildcards_urls_hosts_ips_and_public_suffixes(self):
        for value in ["*.example.com", ".example.com", "||example.com^", "https://example.com", "0.0.0.0 example.com", "1.1.1.1", "com", "example..com", "example.com..", "example.com/path"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain(value)

    def test_unicode_and_bom(self):
        doc, _ = parse_text("\ufeff例子.测试\n".encode(), spec("domains-exact"))
        self.assertEqual(doc["rules"][0]["domain"], ["xn--fsqu00a.xn--0zwm56d"])

    def test_invalid_utf8_fails(self):
        with self.assertRaises(UnicodeError):
            parse_text(b"\xff", spec("domains-exact"))

    def test_catchall_private_and_noncanonical_cidrs_fail(self):
        for data in [b"0.0.0.0/0", b"10.0.0.0/8", b"127.0.0.0/8", b"1.0.1.1/24", b"1.0.1.0"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_text(data, spec("cidr4"))

    def test_count_guards(self):
        with self.assertRaises(ValueError):
            parse_text(b"example.com", spec("domains-exact", min_entries=2))
        with self.assertRaises(ValueError):
            parse_text(b"example.com\nexample.net", spec("domains-exact", max_entries=1))

    def test_protected_domain_detects_suffix_and_exact_collisions(self):
        for data in [b"DOMAIN,play.googleapis.com", b"DOMAIN-SUFFIX,googleapis.com", b"DOMAIN-KEYWORD,google"]:
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "protected"):
                parse_text(data, spec(must_not_match=["play.googleapis.com"]))

    def test_exact_domain_does_not_block_unlisted_children(self):
        parse_text(b"googleapis.com", spec("domains-exact", must_not_match=["play.googleapis.com"]))


class TextSourceIntegrationTests(unittest.TestCase):
    def test_registry_is_consumed_without_new_srs_targets(self):
        config = json.loads((ROOT / "config/rulesets.json").read_text())
        registry = load_registry()
        names, binaries = fetcher.inventory(config)
        self.assertTrue(set(registry) <= set(names))
        self.assertFalse(set(registry) & set(config["standalone_sources"]))
        self.assertEqual(len(config["merged_rulesets"]) + len(config["service_rulesets"]) + len(config["standalone_sources"]) + len(binaries), 115)

    def test_google_push_is_not_misclassified_as_play_download_or_cn(self):
        config = json.loads((ROOT / "config/rulesets.json").read_text())
        self.assertIn("blackmatrix-google-fcm", config["service_rulesets"]["service-google"])
        self.assertNotIn("blackmatrix-google-fcm", config["service_rulesets"]["service-google-play"])
        self.assertNotIn("blackmatrix-google", config["merged_rulesets"]["magicnet-cn-domain"]["sources"])

    def test_binary_passthrough_cannot_take_text(self):
        config = json.loads((ROOT / "config/rulesets.json").read_text())
        config["binary_sources"] = ["hagezi-light-domains.srs"]
        with self.assertRaises(ValueError):
            fetcher.inventory(config)

    def test_fetch_keeps_original_and_immutable_provenance(self):
        name = "blackmatrix-github"
        original = b"DOMAIN,example.com\n"
        override = {**fetcher.TEXT_SOURCES[name], "min_entries": 1}
        commits = {(override["repository"], override["branch"]): "a" * 40}
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            (stage / "sources").mkdir()
            with patch.dict(fetcher.TEXT_SOURCES, {name: override}), patch.object(fetcher, "download", return_value=original) as download:
                record = fetcher.fetch_one(name, False, commits, stage, "/unused")
            self.assertIn("/" + "a" * 40 + "/", download.call_args.args[0])
            self.assertEqual((stage / record["original"]).read_bytes(), original)
            self.assertEqual(record["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(record["unique_entries"], 1)

    def test_registry_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            path.write_text('{"x":{},"x":{}}')
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                load_registry(path)

    def test_registry_rejects_paths_formats_bounds_and_projection(self):
        base = load_registry()["blackmatrix-github"]
        for change in [{"path": "../secret"}, {"branch": "main?x=y"}, {"repository": "https://example.com"}, {"format": "unknown"}, {"min_entries": 0}, {"omit_types": ["AND"]}]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "registry.json"
                path.write_text(json.dumps({"source": {**base, **change}}))
                with self.assertRaises(ValueError):
                    load_registry(path)

    def test_live_snapshot_keeps_originals_licenses_and_matches_conversion(self):
        manifest = ROOT / ".cache/upstream-manifest.json"
        if not manifest.is_file():
            self.skipTest("Build-time snapshot not available in this offline checkout")
        snapshot = json.loads(manifest.read_text())
        records = {item["name"]: item for item in snapshot["sources"]}
        for name, descriptor in load_registry().items():
            record = records[name]
            original = (ROOT / record["original"]).read_bytes()
            self.assertEqual(hashlib.sha256(original).hexdigest(), record["sha256"])
            converted, audit = parse_text(original, descriptor)
            self.assertEqual(converted, json.loads((ROOT / "sources" / (name + ".json")).read_text()))
            self.assertEqual(audit["unique_entries"], record["unique_entries"])
        self.assertEqual(len(snapshot["licenses"]), 4)
        for item in snapshot["licenses"]:
            self.assertEqual(hashlib.sha256((ROOT / item["file"]).read_bytes()).hexdigest(), item["sha256"])


if __name__ == "__main__":
    unittest.main()
