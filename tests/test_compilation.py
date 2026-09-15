"""Compilation verification tests."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"


class CompilationTests(unittest.TestCase):
    def test_all_json_have_compiled_srs(self):
        """Ensure every rule-set JSON in dist/ has a non-empty compiled .srs counterpart."""
        json_files = [f for f in DIST_DIR.glob("*.json") if f.name != "manifest.json"]
        self.assertGreater(len(json_files), 0)

        for jf in json_files:
            srs_file = DIST_DIR / f"{jf.stem}.srs"
            with self.subTest(file=jf.name):
                self.assertTrue(srs_file.is_file(), f"Missing compiled binary: {srs_file.name}")
                self.assertGreater(srs_file.stat().st_size, 0, f"Compiled binary is empty: {srs_file.name}")

    def test_binary_sources_present(self):
        """Ensure non-decompileable binary assets (like HaGeZi AdGuard lists) are present in dist/."""
        binary_sources = (ROOT / "sources_binary").glob("*.srs")
        for bf in binary_sources:
            dest = DIST_DIR / bf.name
            with self.subTest(file=bf.name):
                self.assertTrue(dest.is_file(), f"Missing binary asset: {dest.name}")
                self.assertGreater(dest.stat().st_size, 0, f"Binary asset is empty: {dest.name}")


if __name__ == "__main__":
    unittest.main()
