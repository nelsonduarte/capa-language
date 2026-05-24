"""Smoke tests for evaluation/cve/.

The downloader has two contracts the rest of the pipeline depends
on, and these tests guard them:

- MANIFEST.sha256 round-trips through _parse_manifest /
  _format_manifest without losing entries or duplicating lines.
- _sha256 reports the same digest as a hashlib reference.

Network fetches are NOT exercised here -- those depend on the
NVD CDN and would make CI flaky. The download path is left to
the manual workflow on a developer machine + the integrity
check that runs whenever the cache exists.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from evaluation.cve import download_nvd


class TestNvdDownloaderHelpers(unittest.TestCase):
    def test_sha256_matches_hashlib(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"capa-evaluation-test\n" * 1024)
            path = Path(f.name)
        try:
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            actual = download_nvd._sha256(path)
            self.assertEqual(expected, actual)
        finally:
            path.unlink(missing_ok=True)

    def test_manifest_has_one_entry_per_year(self):
        preamble, entries = download_nvd._parse_manifest()
        for year in download_nvd.YEARS:
            filename = f"nvdcve-2.0-{year}.json.gz"
            self.assertIn(filename, entries, f"missing {filename}")

    def test_manifest_roundtrip_stable(self):
        # Parsing then re-formatting must not change the file
        # (besides whitespace normalisation in the data block).
        # Pinned sha256s are preserved; preamble comments survive.
        preamble, entries = download_nvd._parse_manifest()
        rendered = download_nvd._format_manifest(preamble, entries)
        # Re-parse the rendered output.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sha256", delete=False, encoding="utf-8",
        ) as f:
            f.write(rendered)
            tmp_manifest = Path(f.name)
        try:
            saved = download_nvd.MANIFEST_PATH
            download_nvd.MANIFEST_PATH = tmp_manifest
            try:
                _, reparsed = download_nvd._parse_manifest()
            finally:
                download_nvd.MANIFEST_PATH = saved
        finally:
            tmp_manifest.unlink(missing_ok=True)
        # Same set of filenames + same sha256s round-trip.
        self.assertEqual(set(entries), set(reparsed))
        for name in entries:
            self.assertEqual(entries[name].sha256, reparsed[name].sha256)
            self.assertEqual(entries[name].url, reparsed[name].url)


if __name__ == "__main__":
    unittest.main()
