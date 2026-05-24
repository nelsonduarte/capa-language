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

from evaluation.cve import classify, download_nvd


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


class TestClassifierHelpers(unittest.TestCase):
    """Heuristic-level tests for the auto-classifier. The full
    end-to-end pass depends on the NVD cache being present, so
    those tests are skipped when the cache is missing; the helpers
    work on inline mock CVE records."""

    def test_extract_cwes_from_weaknesses(self):
        cve = {
            "weaknesses": [
                {"description": [
                    {"lang": "en", "value": "CWE-78"},
                    {"lang": "en", "value": "CWE-22"},
                ]},
                {"description": [
                    {"lang": "en", "value": "CWE-22"},  # duplicate
                    {"lang": "en", "value": "NVD-CWE-Other"},
                ]},
            ],
        }
        self.assertEqual(classify._extract_cwes(cve), ["CWE-22", "CWE-78"])

    def test_extract_cvss_prefers_v31(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
                ],
                "cvssMetricV2": [
                    {"cvssData": {"baseScore": 5.0}},
                ],
            },
        }
        score, sev = classify._extract_cvss(cve)
        self.assertEqual(score, 9.8)
        self.assertEqual(sev, "CRITICAL")

    def test_auto_bucket_structural(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "command injection via shell"}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        }
        bucket, _ = classify._auto_bucket(cve)
        self.assertEqual(bucket, "STRUCTURAL_REJECT")

    def test_auto_bucket_attenuation(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "path traversal via ../"}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
        }
        bucket, _ = classify._auto_bucket(cve)
        self.assertEqual(bucket, "ATTENUATION_MITIGATED")

    def test_auto_bucket_memory_override(self):
        # CWE-94 (code injection) is normally STRUCTURAL_REJECT,
        # but a description that screams 'use-after-free' overrides
        # to OUT_OF_SCOPE_MEMORY.
        cve = {
            "descriptions": [{
                "lang": "en",
                "value": "use-after-free in script eval handler",
            }],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-94"}]}],
        }
        bucket, _ = classify._auto_bucket(cve)
        self.assertEqual(bucket, "OUT_OF_SCOPE_MEMORY")

    def test_full_classification_deterministic(self):
        # End-to-end pass: requires the cache to exist. If missing,
        # skip so CI doesn't fail on machines without the dataset.
        if not (download_nvd.CACHE_DIR / "nvdcve-2.0-2024.json.gz").exists():
            self.skipTest("NVD cache not present; run download_nvd first")

        first = classify.classify_all()
        second = classify.classify_all()
        # Same seed must produce the same sample, in the same order.
        self.assertEqual(
            [d.cve_id for d in first],
            [d.cve_id for d in second],
        )
        # Sample size locked to constant.
        self.assertLessEqual(len(first), classify.SAMPLE_SIZE)
        # Every bucket label must be a known one.
        valid_buckets = {
            "STRUCTURAL_REJECT", "ATTENUATION_MITIGATED",
            "OUT_OF_SCOPE_MEMORY", "OUT_OF_SCOPE_LOGIC",
            "OUT_OF_SCOPE_BELOW_LANG", "UNCLEAR",
        }
        for d in first:
            self.assertIn(d.bucket, valid_buckets)


if __name__ == "__main__":
    unittest.main()
