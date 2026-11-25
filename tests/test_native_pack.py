import hashlib
from pathlib import Path
import tempfile
import sys
import json
import os
import unittest

NATIVE = Path(__file__).resolve().parents[1] / "native"
sys.path.insert(0, str(NATIVE))
from build import fetch, parse_exact, write_changed
from catalog import build_catalog, optimize


class RuleTests(unittest.TestCase):
    def test_dns_normalization_and_sentinels(self):
        self.assertEqual(parse_exact(b"# test\nZ.example.\na.test\nz.EXAMPLE\n"),
                         (["a.test", "z.example"], 3))
        for bad in [b"*.test", b"a..test", b"foo\x00.bar", b"x.-test", b"GITHUB.COM.", b"# empty"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_exact(bad)

    def test_group_distinct_syntax_and_singletons(self):
        source = [
            {"version": 1, "rules": [{"domain_suffix": ".test", "domain_regex": "^a\\.x$"}]},
            {"version": 2, "rules": [{"domain": ["x", "x"], "domain_suffix": [".test", "test"]}]},
        ]
        sets, before, after = optimize(source)
        self.assertEqual((before, after), (6, 5))
        self.assertEqual(sets[0]["rules"][0]["domain_regex"], ["^a\\.x$"])
        self.assertEqual(sets[1]["rules"][0]["domain_suffix"], [".test", "test"])
        self.assertEqual(sets[1]["rules"][0]["domain"], ["x"])

    def test_ip_union_preserves_exact_address_membership(self):
        v = {"version": 2, "rules": [{"ip_cidr": ["192.0.2.0/25", "192.0.2.128/25", "::1/128"]}]}
        out, _, count = optimize([v])
        self.assertEqual(out[0]["rules"][0]["ip_cidr"], ["192.0.2.0/24", "::1/128"])
        self.assertEqual(count, 2)
        for unknown in [{"invert": True, "domain": ["test"]}, {"source_ip_cidr": ["192.0.2.0/24"]}]:
            with self.subTest(unknown=unknown), self.assertRaises(ValueError):
                optimize([{"version": 2, "rules": [unknown]}])

    def test_changed_objects_and_digest_verification(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            write_changed(path, {"a": b"a", "b": b"b"})
            old = (path / "a").stat()
            write_changed(path, {"a": b"a", "b": b"c"})
            self.assertEqual((path / "a").stat().st_ino, old.st_ino)
            self.assertEqual((path / "a").stat().st_mtime_ns, old.st_mtime_ns)
            self.assertEqual((path / "b").read_bytes(), b"c")
            pin = {"url": "example", "sha256": hashlib.sha256(b"a").hexdigest()}
            self.assertEqual(fetch(pin, path / "a"), b"a")
            with self.assertRaises(ValueError):
                fetch(pin, path / "b")


class PinnedReleaseTests(unittest.TestCase):
    def test_publication_input_and_native_pack(self):
        lock = json.loads((NATIVE / "sources.lock.json").read_text())
        local = os.environ.get("MAGICBOX_PINNED_INPUTS")
        def read(key, filename):
            return fetch(lock[key], Path(local) / filename if local else None)

        archive = read("archive", "source.tar.gz")
        self.assertIn(b"GNU GENERAL PUBLIC LICENSE", read("license", "gpl.txt"))
        names, entries = parse_exact(read("light", "light.txt"))
        self.assertEqual(entries, 85887)
        block = ("magicbox-exact-v1\n" + "\n".join(names) + "\n").encode("ascii")
        self.assertEqual(hashlib.sha256(block).hexdigest(),
                         "1a5d69de6356a48015d319f4dfa305ab068ad6f56d3ced9c0438684a76a20969")
        files, report = build_catalog(archive, names)
        self.assertEqual(report["updated_feed"], {"previous_entries": 93230, "added": 3469, "removed": 10812})
        self.assertEqual((report["logical_sets"], report["unique_objects"]), (113, 92))
        self.assertEqual((report["input_entries"], report["output_entries"]), (1586625, 1301169))
        index = json.loads(files["catalog/index.json"])
        self.assertEqual(len(index["binary_only_upstream"]), 3)
        for item in index["sets"].values():
            data = files["catalog/objects/" + item["sha256"] + ".json.gz"]
            self.assertEqual(item["bytes"], len(data))
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
