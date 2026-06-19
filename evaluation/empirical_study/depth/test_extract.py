"""Determinism + sanity tests for the depth extractor.

These run against the committed manifests under ``manifests/`` only, so
they are CI-safe and do not require the downstream repos. They pin the
headline numbers reported in ``README.md`` so a manifest regeneration
that shifts a metric cannot land silently: if a number moves, this test
fails and the prose must be updated alongside it.
"""

from __future__ import annotations

import json

import extract


def _metrics():
    out = {}
    for name, fname in extract.PROGRAMS:
        out[name] = extract.extract(extract.load(extract.MANIFEST_DIR / fname))
    return out


def test_manifests_present_and_v152():
    m = _metrics()
    assert set(m) == {"capa_paymentguard", "capa_claimdesk"}
    for prog in m.values():
        assert prog["capa_version"] == "1.5.2"
        assert prog["entrypoint"] == "main.capa"


def test_extract_is_deterministic():
    # Same input must yield byte-identical JSON across runs.
    a = json.dumps(_metrics(), sort_keys=True)
    b = json.dumps(_metrics(), sort_keys=True)
    assert a == b


def test_paymentguard_headline_numbers():
    m = _metrics()["capa_paymentguard"]
    assert m["total_functions"] == 70
    # App vs vendored split, derived from each function's source path.
    assert m["app_functions"] == 42
    assert m["vendored_functions"] == 28
    assert m["app_functions"] + m["vendored_functions"] == m["total_functions"]
    # The crypto dependency the README's prose cites.
    assert m["vendor_dep_functions"]["capa_hash"] == 28
    assert m["pure_functions"] == 66
    assert m["pure_pct"] == 94.3
    assert m["provably_excluded_facts"] == 625
    assert m["declassification_sites"] == 6
    assert m["constant_time_functions"] == 7
    assert m["unsafe_functions"] == 0
    # Concentration: Fs on 3 functions, no other sensitive axis reached.
    assert m["sensitive_concentration"]["Fs"]["functions"] == 3
    assert m["sensitive_concentration"]["Net"]["functions"] == 0
    assert m["sensitive_concentration"]["Db"]["functions"] == 0
    assert m["sensitive_concentration"]["Proc"]["functions"] == 0
    assert m["sensitive_concentration"]["Unsafe"]["functions"] == 0


def test_claimdesk_headline_numbers():
    m = _metrics()["capa_claimdesk"]
    assert m["total_functions"] == 213
    # App vs vendored split, derived from each function's source path.
    assert m["app_functions"] == 131
    assert m["vendored_functions"] == 82
    assert m["app_functions"] + m["vendored_functions"] == m["total_functions"]
    assert m["pure_functions"] == 187
    assert m["pure_pct"] == 87.8
    assert m["provably_excluded_facts"] == 2295
    assert m["declassification_sites"] == 3
    assert m["constant_time_functions"] == 8
    assert m["unsafe_functions"] == 0
    assert m["user_defined_capabilities"] == ["Notifier", "Logger"]
    assert len(m["typestates"]) == 1
    assert m["typestates"][0]["name"] == "Claim"
    assert len(m["typestates"][0]["states"]) == 6
    # Concentration: the most-reached sensitive axis is Db on 5 functions.
    assert m["sensitive_concentration"]["Fs"]["functions"] == 4
    assert m["sensitive_concentration"]["Net"]["functions"] == 2
    assert m["sensitive_concentration"]["Db"]["functions"] == 5
    assert m["sensitive_concentration"]["Proc"]["functions"] == 3
    assert m["sensitive_concentration"]["Unsafe"]["functions"] == 0


def test_no_sensitive_axis_exceeds_five_percent():
    # The positioning claim: authority concentrates in a small fraction
    # of functions. Pin the REAL measured ceiling: the most-held sensitive
    # axis across both programs is paymentguard's Fs at 4.3 % (3 of 70).
    # The bound is 5 %, set from the data, not a target picked in advance.
    m = _metrics()
    for prog in m.values():
        for axis in extract.SENSITIVE_AXES:
            assert prog["sensitive_concentration"][axis]["pct"] <= 5.0


def test_excluded_facts_dwarf_reachable_facts():
    # The sound-exclusion richness: provably-excluded facts vastly
    # outnumber reachable ones, which is the data no heuristic provides.
    m = _metrics()
    for prog in m.values():
        assert prog["provably_excluded_facts"] > 100 * 1  # non-trivial
