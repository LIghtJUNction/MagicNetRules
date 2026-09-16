import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_upstream as fetcher


class BinarySourceTests(unittest.TestCase):
    def test_binary_sources_are_loaded_not_decompiled(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            (stage / "sources_binary").mkdir()
            (stage / "raw").mkdir()
            data = b"SRS\x02binary-matcher"
            response = subprocess.CompletedProcess([], 0, "", "")
            with patch.object(fetcher, "download", return_value=data):
                with patch.object(fetcher.subprocess, "run", return_value=response) as run:
                    fetcher.fetch_one("hagezi-light", True,
                        {("razaxq/dns-blocklists-sing-box", "rule-set"): "b" * 40}, stage, "sing-box")
            self.assertEqual(run.call_args.args[0][1:3], ["check", "-c"])
            self.assertEqual((stage / "sources_binary/hagezi-light.srs").read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
