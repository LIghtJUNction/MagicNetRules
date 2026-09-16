import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import download_release as consumer


def bundle(unsafe=False):
    raw = b"SRS\x02fixture"
    manifest = {"version": 1, "rulesets": {"example": {
        "sha256_srs": hashlib.sha256(raw).hexdigest(), "srs_size": len(raw)}}}
    contents = [("example.srs", raw), ("manifest.json", json.dumps(manifest).encode())]
    if unsafe:
        contents.append(("../escape.srs", raw))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in contents:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


class ReleaseConsumerTests(unittest.TestCase):
    def test_valid_bundle_and_manifest(self):
        data = bundle()
        with tempfile.TemporaryDirectory() as temporary:
            consumer.extract_verified(data, hashlib.sha256(data).hexdigest(), Path(temporary))
            self.assertTrue((Path(temporary) / "dist/example.srs").is_file())

    def test_checksum_failure_does_not_extract(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            with self.assertRaises(ValueError):
                consumer.extract_verified(bundle(), "0" * 64, stage)
            self.assertFalse((stage / "dist").exists())

    def test_path_traversal_is_rejected_even_with_valid_archive_checksum(self):
        data = bundle(True)
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            with self.assertRaises(ValueError):
                consumer.extract_verified(data, hashlib.sha256(data).hexdigest(), stage)
            self.assertFalse((stage / "escape.srs").exists())

    def test_duplicate_checksum_is_rejected(self):
        line = "a" * 64 + "  magicnet-rules.tar.gz\n"
        with self.assertRaises(ValueError):
            consumer.checksum(line * 2)

    def test_failed_download_preserves_previous_output(self):
        data = bundle()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "dist"
            output.mkdir()
            (output / "old.srs").write_bytes(b"previous")
            checksums = ("0" * 64 + "  magicnet-rules.tar.gz\n").encode()
            with patch.object(consumer, "fetch", side_effect=[checksums, data]):
                with self.assertRaises(ValueError):
                    consumer.download_release(output, "rules-test")
            self.assertEqual((output / "old.srs").read_bytes(), b"previous")

    def test_latest_is_resolved_once_and_assets_share_immutable_tag(self):
        data = bundle()
        checksum = (hashlib.sha256(data).hexdigest() + "  magicnet-rules.tar.gz\n").encode()
        metadata = json.dumps({"tag_name": "rules-test", "draft": False, "prerelease": False}).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(consumer, "fetch", side_effect=[metadata, checksum, data]) as get:
                consumer.download_release(Path(temporary) / "dist")
            urls = [call.args[0] for call in get.call_args_list]
            self.assertTrue(urls[0].endswith("/releases/latest"))
            self.assertIn("/download/rules-test/", urls[1])
            self.assertIn("/download/rules-test/", urls[2])


if __name__ == "__main__":
    unittest.main()
