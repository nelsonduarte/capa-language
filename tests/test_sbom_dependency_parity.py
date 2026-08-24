"""Cross-emitter dependency-purl agreement (the anti-drift invariant).

The whole point of routing every dependency purl through the ONE producer
(:func:`capa.manifest._compose._construct_purl`, via
:func:`resolve_dependency_identities`) is that the CycloneDX and the SPDX
emitters render the SAME purl for the SAME dependency, with zero duplicated
knowledge. This guard proves it end-to-end from a SINGLE resolve walk:

- it BUILDS both documents from one ``resolve_dependency_identities(root)``;
- for every dependency with a purl it reads the BUILT CycloneDX component's
  ``purl`` and the BUILT SPDX package's ``externalRefs[0].referenceLocator``
  and asserts both equal ``record.purl``.

It reads the BUILT artifacts (not ``record.purl`` compared to itself), so it
is mutation-tested to BITE: hand-edit either emitter to render a wrong purl
and this test goes red.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.manifest import (
    build_cyclonedx,
    build_spdx,
    resolve_dependency_identities,
)


_WORKED_URL = "https://github.com/acme/widget.git"
_WORKED_COMMIT = "ef1c0ffee1234567890abcdef1234567890abcd"


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestCrossEmitterPurlAgreement(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_sbom_parity_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _project(self) -> Path:
        # A github git dep (purl), a non-github git dep (generic purl), a
        # path dep (no purl), and an unresolved git dep (purl, no version):
        # every purl-bearing branch is exercised in one document.
        root = self.tmp / "proj"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n\n'
            '[dependencies.gitlabdep]\n'
            'git = "https://git.example.org/acme/gitlabdep.git"\n'
            'tag = "v3.0.0"\n\n'
            '[dependencies.localdep]\npath = "../localdep"\n\n'
            '[dependencies.missing]\n'
            'git = "https://github.com/acme/missing.git"\nrev = "abc123"\n'
        ))
        _write(root, "main.capa", "pub fun main()\n    return\n")
        _write(root, "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/widget/w.capa", "pub fun w()\n    return\n")
        _write(root, "vendor/gitlabdep/capa.toml",
               '[package]\nname = "gitlabdep"\nversion = "3.0.0"\n')
        _write(root, "vendor/gitlabdep/g.capa", "pub fun g()\n    return\n")
        _write(self.tmp / "localdep", "capa.toml",
               '[package]\nname = "localdep"\nversion = "9.9.9"\n')
        _write(self.tmp / "localdep", "l.capa", "pub fun l()\n    return\n")
        _write(root, "capa.lock", (
            "[[dependencies]]\n"
            'name = "widget"\n'
            f'git = "{_WORKED_URL}"\n'
            'pin = "v1.2.3"\npin_kind = "tag"\n'
            f'commit = "{_WORKED_COMMIT}"\n'
        ))
        return root

    def _build_both(self, root: Path):
        filename = str(root / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        module = Parser(Lexer(source).lex(), source=source).parse_module()
        self.assertTrue(analyze(module, source=source).ok)
        # ONE resolve walk feeds BOTH emitters.
        ids, graph = resolve_dependency_identities(root)
        cdx = build_cyclonedx(
            module, filename=filename, source=source,
            timestamp="2020-01-01T00:00:00Z",
            dependency_components=ids, dependency_graph=graph,
        )
        spdx = build_spdx(
            module, filename=filename, source=source,
            timestamp="2020-01-01T00:00:00Z",
            dependency_components=ids, dependency_graph=graph,
        )
        return ids, cdx, spdx

    def test_built_purls_agree_across_emitters(self):
        ids, cdx, spdx = self._build_both(self._project())

        # BUILT CycloneDX component purls, keyed by bom-ref.
        cdx_purl_by_ref = {
            c["bom-ref"]: c["purl"]
            for c in cdx["components"] if "purl" in c
        }
        # BUILT SPDX externalRef locators, one list per referenceLocator.
        spdx_locators = [
            ref["referenceLocator"]
            for p in spdx["packages"]
            for ref in p.get("externalRefs", [])
            if ref["referenceType"] == "purl"
        ]

        purl_records = [r for r in ids if r.purl]
        self.assertGreater(len(purl_records), 0, "fixture must have purls")
        for record in purl_records:
            # The BUILT CycloneDX component agrees with the record.
            self.assertEqual(
                cdx_purl_by_ref.get(record.bom_ref), record.purl,
                f"CycloneDX purl for {record.name!r} disagrees with record",
            )
            # Exactly one BUILT SPDX externalRef carries this purl.
            self.assertEqual(
                spdx_locators.count(record.purl), 1,
                f"SPDX externalRef for {record.name!r} missing/duplicated",
            )
        # And, at the set level, the three purl views are identical: no
        # emitter dropped, added, or altered a purl.
        self.assertEqual(
            set(cdx_purl_by_ref.values()),
            set(spdx_locators),
        )
        self.assertEqual(
            set(spdx_locators),
            {r.purl for r in purl_records},
        )


if __name__ == "__main__":
    unittest.main()
