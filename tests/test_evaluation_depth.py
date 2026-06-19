"""Smoke tests for evaluation/empirical_study/depth/.

The depth extractor reads the two committed Capa manifests under
``depth/manifests/`` and reports per-program metrics (pure fraction,
per-axis reach, authority concentration, sound-exclusion fact counts,
IFC / constant-time / typestate dimensions). These tests pin the
headline numbers cited in ``depth/README.md`` so a manifest refresh
cannot drift the prose silently, and they confirm the extractor is
deterministic.

They read only the committed JSON, so they run in CI without the
downstream repos or a Capa toolchain, matching the other
``test_evaluation_*`` smoke tests.
"""

import json
import unittest

from evaluation.empirical_study.depth import extract


def _metrics():
    out = {}
    for name, fname in extract.PROGRAMS:
        out[name] = extract.extract(extract.load(extract.MANIFEST_DIR / fname))
    return out


class TestDepthExtractor(unittest.TestCase):
    def test_manifests_present_and_v152(self):
        m = _metrics()
        self.assertEqual(set(m), {"capa_paymentguard", "capa_claimdesk"})
        for prog in m.values():
            self.assertEqual(prog["capa_version"], "1.5.2")
            self.assertEqual(prog["entrypoint"], "main.capa")

    def test_deterministic(self):
        a = json.dumps(_metrics(), sort_keys=True)
        b = json.dumps(_metrics(), sort_keys=True)
        self.assertEqual(a, b)

    def test_paymentguard_headline(self):
        m = _metrics()["capa_paymentguard"]
        self.assertEqual(m["total_functions"], 70)
        self.assertEqual(m["pure_functions"], 66)
        self.assertEqual(m["pure_pct"], 94.3)
        self.assertEqual(m["provably_excluded_facts"], 625)
        self.assertEqual(m["declassification_sites"], 6)
        self.assertEqual(m["constant_time_functions"], 7)
        self.assertEqual(m["unsafe_functions"], 0)
        self.assertEqual(m["sensitive_concentration"]["Fs"]["functions"], 3)
        for axis in ("Net", "Db", "Proc", "Unsafe"):
            self.assertEqual(
                m["sensitive_concentration"][axis]["functions"], 0
            )

    def test_claimdesk_headline(self):
        m = _metrics()["capa_claimdesk"]
        self.assertEqual(m["total_functions"], 213)
        self.assertEqual(m["pure_functions"], 187)
        self.assertEqual(m["pure_pct"], 87.8)
        self.assertEqual(m["provably_excluded_facts"], 2295)
        self.assertEqual(m["declassification_sites"], 3)
        self.assertEqual(m["constant_time_functions"], 8)
        self.assertEqual(m["unsafe_functions"], 0)
        self.assertEqual(
            m["user_defined_capabilities"], ["Notifier", "Logger"]
        )
        self.assertEqual(len(m["typestates"]), 1)
        self.assertEqual(m["typestates"][0]["name"], "Claim")
        self.assertEqual(len(m["typestates"][0]["states"]), 6)
        self.assertEqual(m["sensitive_concentration"]["Db"]["functions"], 5)
        self.assertEqual(m["sensitive_concentration"]["Net"]["functions"], 2)

    def test_concentration_ceiling_is_measured(self):
        # The most-held sensitive axis across both programs is
        # paymentguard's Fs at 4.3 %. Pin a 5 % ceiling drawn from the
        # data, not a target chosen in advance.
        m = _metrics()
        for prog in m.values():
            for axis in extract.SENSITIVE_AXES:
                self.assertLessEqual(
                    prog["sensitive_concentration"][axis]["pct"], 5.0
                )


if __name__ == "__main__":
    unittest.main()
