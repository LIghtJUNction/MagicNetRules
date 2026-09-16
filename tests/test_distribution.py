import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_upstream as fetcher
import package_release as packaging


class FetchTests(unittest.TestCase):
    def test_all_configured_sources_have_mapping(self):
        config = json.loads((ROOT / "config/rulesets.json").read_text())
        names, binaries = fetcher.inventory(config)
        self.assertGreater(len(names), 50)
        self.assertEqual(len(binaries), 3)

    def test_mapping_preserves_service_and_karing_names(self):
        self.assertEqual(fetcher.source_location("metacubex-service-google-play")[2], "geo/geosite/google-play.srs")
        self.assertEqual(fetcher.source_location("karing-acl4ssr-china-ip")[2], "ACL4SSR/ChinaIp.srs")
        self.assertEqual(fetcher.source_location("metacubex-service-bing@cn")[2], "geo/geosite/bing@cn.srs")
        for name in ("../../etc/passwd", "", "..", "unknown", "https://evil"):
            with self.assertRaises(ValueError):
                fetcher.source_location(name)

    def test_https_only(self):
        with self.assertRaises(ValueError):
            fetcher.download("http://example.test/rules.srs")

    def test_empty_rules_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.json"
            path.write_text('{"version":2,"rules":[]}')
            with self.assertRaises(ValueError):
                fetcher.validate_json(path)

    def test_binary_input_is_not_accepted_as_html(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(fetcher, "download", return_value=b"<html>error</html>"):
                with self.assertRaisesRegex(ValueError, "Invalid SRS"):
                    fetcher.fetch_one("geoip-cn", False,
                        {("lyc8503/sing-box-rules", "rule-set-geoip"): "a" * 40}, Path(temporary), "/unused")

    def test_failed_snapshot_install_restores_all_old_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            (root / ".cache").mkdir()
            for name in ("sources", "sources_binary"):
                (root / name).mkdir()
                (root / name / "old").write_text("old")
                (stage / name).mkdir()
                (stage / name / "new").write_text("new")
            (stage / "upstream-manifest.json").write_text("new")
            (root / ".cache/upstream-manifest.json").write_text("old")
            original = Path.rename
            def fail_second(source, destination):
                if source == stage / "sources_binary":
                    raise OSError("simulated publish failure")
                return original(source, destination)
            with patch.object(Path, "rename", fail_second):
                with self.assertRaises(OSError):
                    fetcher.install_snapshot(stage, root)
            for name in ("sources", "sources_binary"):
                self.assertEqual((root / name / "old").read_text(), "old")
                self.assertFalse((root / name / "new").exists())
            self.assertEqual((root / ".cache/upstream-manifest.json").read_text(), "old")


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        dist = self.root / "dist"
        dist.mkdir()
        data = b"SRS\x02fixture"
        (dist / "example.srs").write_bytes(data)
        self.metadata = {"version": 1, "rulesets": {"example": {
            "sha256_srs": hashlib.sha256(data).hexdigest(), "srs_size": len(data)}}}
        (dist / "manifest.json").write_text(json.dumps(self.metadata))

    def test_runtime_archive_is_reproducible_and_contains_no_json_rules(self):
        files = packaging.runtime_files(self.root)
        (self.root / "dist/example.json").write_text("audit data")
        first, second = self.root / "first.gz", self.root / "second.gz"
        packaging.archive(first, files)
        os.utime(self.root / "dist/example.srs", (1000, 1000))
        packaging.archive(second, files)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as tar:
            self.assertEqual(tar.getnames(), ["example.srs", "manifest.json"])
            self.assertTrue(all(item.uid == 0 and item.mtime == 0 for item in tar))

    def test_tampering_is_rejected(self):
        (self.root / "dist/example.srs").write_bytes(b"SRS\x02tampered")
        with self.assertRaises(ValueError):
            packaging.runtime_files(self.root)

    def test_extra_rule_is_rejected(self):
        (self.root / "dist/stale.srs").write_bytes(b"SRS\x02")
        with self.assertRaises(ValueError):
            packaging.runtime_files(self.root)

    def test_symlink_is_rejected(self):
        target = self.root / "dist/example.srs"
        target.rename(self.root / "other")
        target.symlink_to(self.root / "other")
        with self.assertRaises(ValueError):
            packaging.runtime_files(self.root)


class HistoryTests(unittest.TestCase):
    def test_real_git_history_cleanup_and_lease_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            def git(*args, cwd=work):
                return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.STDOUT, text=True).strip()
            git("init", "--bare", str(root / "remote.git"), cwd=root)
            git("init", "-b", "main", str(work), cwd=root)
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (work / "README.md").write_text("keep this code")
            for directory in ("dist", "sources", "sources_binary"):
                (work / directory).mkdir()
                (work / directory / "generated").write_text("generated")
            git("add", ".")
            git("commit", "-m", "initial")
            git("branch", "old-branch")
            git("tag", "old-tag")
            git("rm", "-r", "dist", "sources", "sources_binary")
            (work / "script.py").write_text("print('preserve')")
            git("add", ".")
            git("commit", "-m", "source only tip")
            git("remote", "add", "origin", str(root / "remote.git"))
            git("push", "origin", "main", "old-branch", "old-tag")
            old = git("rev-parse", "HEAD")
            env = dict(os.environ, EXPECTED_MAIN="0" * 40, GITHUB_ACTIONS="false")
            result = subprocess.run(["bash", str(ROOT / "scripts/clean-history.sh")], cwd=work,
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(old, git("ls-remote", "origin", "refs/heads/main"))
            env["EXPECTED_MAIN"] = old
            result = subprocess.run(["bash", str(ROOT / "scripts/clean-history.sh")], cwd=work,
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)
            remote = root / "remote.git"
            for ref in ("refs/heads/main", "refs/heads/old-branch", "refs/tags/old-tag"):
                objects = git("rev-list", "--objects", ref, cwd=remote)
                for name in ("dist", "sources", "sources_binary"):
                    self.assertNotRegex(objects, rf" {name}(/|$)")
            self.assertEqual(git("show", "main:README.md", cwd=remote), "keep this code")
            self.assertEqual(git("show", "main:script.py", cwd=remote), "print('preserve')")


if __name__ == "__main__":
    unittest.main()
