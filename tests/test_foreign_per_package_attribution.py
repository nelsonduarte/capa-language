"""Feature #4 (F2a) precision + CLI posture fixes surfaced by dogfooding
the ``capa_ci_pipeline`` demo.

F-1 (precision): a package's ``foreign_declared_caps`` must be the union
of the declared capability sets of ONLY the foreign components ITS OWN
functions invoke -- not the module-wide union across every declared
boundary. A package that calls only a NO-CAP parser must compose with no
foreign capabilities, while a package calling a ``Net`` fetcher gets
``{Net}``. The soundness fallback (the module-wide union) still fires for
an unresolvable / dynamic / pre-F1 foreign call so a real foreign cap is
never dropped.

F-2 (posture): ``--check-capabilities`` threads the ``--wasm`` enforcement
posture into the composed SBOM, so a per-package ``[capabilities]`` ceiling
on a foreign-calling package is checked against the BOUNDED (host-enforced)
authority under ``--wasm`` instead of failing closed at authority-unknown
TOP.

These are pure-Python compose/policy/CLI tests -- no Wasm tooling.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import analyze
from capa.cli import main
from capa.loader import ModuleLoader
from capa.manifest import (
    build_composed_sbom, build_manifest, evaluate_policies,
    find_policy_file, read_policy_file,
)


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original)


def _link(root_dir: Path, root_file: str):
    root_dir = root_dir.resolve()
    search = [root_dir]
    for vendor in root_dir.rglob("vendor"):
        if vendor.is_dir():
            search.append(vendor)
    filename = str(root_dir / root_file)
    source = Path(filename).read_text(encoding="utf-8")
    loader = ModuleLoader(search_paths=search)
    linked = loader.load_root(source, filename)
    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources, module_privates=linked.module_privates,
    )
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    manifest = build_manifest(
        linked.module, filename=filename, expr_labels=result.expr_labels,
    )
    return linked.module, manifest


def _pkg(composed, name):
    for p in composed["packages"]:
        if p["name"] == name:
            return p
    names = [p["name"] for p in composed["packages"]]
    raise AssertionError(f"no package {name!r} in {names}")


# A product whose three LEAF dependencies each invoke a DIFFERENT foreign
# component: fetcher -> Fetch(Net), parser -> Parse(no caps),
# builder -> Build(Fs). The root itself declares no boundary; it just calls
# each leaf, so each leaf's foreign attribution is isolated to that package.
def _build_product(root: Path) -> None:
    _write(root, "capa.toml", (
        '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
        '[dependencies.fetcher]\ngit = "https://x/fetcher"\ntag = "v1"\n\n'
        '[dependencies.parser]\ngit = "https://x/parser"\ntag = "v1"\n\n'
        '[dependencies.builder]\ngit = "https://x/builder"\ntag = "v1"\n'
    ))
    _write(root, "main.capa", (
        "import fetcher.fetch_lib\n"
        "import parser.parse_lib\n"
        "import builder.build_lib\n"
        "\n"
        "fun main(net: Net, fs: Fs) -> Int\n"
        "    let a = fetch(net, 1)\n"
        "    let b = parse(a)\n"
        "    return build(fs, b)\n"
    ))
    _write(root, "vendor/fetcher/capa.toml",
           '[package]\nname = "fetcher"\nversion = "0.1.0"\n')
    _write(root, "vendor/fetcher/fetch_lib.capa", (
        'extern component Fetch from "fetch.wasm"\n'
        "    fun get(net: Net, x: Int) -> Int\n"
        "\n"
        "pub fun fetch(net: Net, x: Int) -> Int\n"
        "    return Fetch.get(net, x)\n"
    ))
    _write(root, "vendor/parser/capa.toml",
           '[package]\nname = "parser"\nversion = "0.1.0"\n')
    _write(root, "vendor/parser/parse_lib.capa", (
        'extern component Parse from "parse.wasm"\n'
        "    fun run(x: Int) -> Int\n"
        "\n"
        "pub fun parse(x: Int) -> Int\n"
        "    return Parse.run(x)\n"
    ))
    _write(root, "vendor/builder/capa.toml",
           '[package]\nname = "builder"\nversion = "0.1.0"\n')
    _write(root, "vendor/builder/build_lib.capa", (
        'extern component Build from "build.wasm"\n'
        "    fun make(fs: Fs, x: Int) -> Int\n"
        "\n"
        "pub fun build(fs: Fs, x: Int) -> Int\n"
        "    return Build.make(fs, x)\n"
    ))


class _TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_fpp_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))


class TestPerPackageForeignAttribution(_TmpTree):
    """F-1: each package composes ONLY the caps of the foreign components
    its own functions invoke; the product still aggregates all of them."""

    def test_precise_per_package_under_wasm_sandbox(self):
        root = self.tmp / "prod"
        _build_product(root)
        module, manifest = _link(root, "main.capa")
        composed = build_composed_sbom(
            module, manifest, root.resolve(), enforcement="wasm-sandbox",
        )

        # The no-cap parser package composes with NO foreign capabilities.
        parser = _pkg(composed, "parser")
        self.assertEqual(parser["composed_capabilities"], [])
        self.assertFalse(parser["composed_authority_unknown"])

        # The Net fetcher gets exactly {Net}; the Fs builder exactly {Fs}.
        fetcher = _pkg(composed, "fetcher")
        self.assertEqual(fetcher["composed_capabilities"], ["Net"])
        self.assertFalse(fetcher["composed_authority_unknown"])
        builder = _pkg(composed, "builder")
        self.assertEqual(builder["composed_capabilities"], ["Fs"])
        self.assertFalse(builder["composed_authority_unknown"])

        # The PRODUCT composed set still aggregates every package.
        self.assertEqual(
            composed["composed"]["capabilities"], ["Fs", "Net"],
        )
        self.assertFalse(composed["composed"]["authority_unknown"])

    def test_forbid_capability_on_parse_package_now_passes(self):
        # The exact gate the demo hit: "the parse package must not hold
        # Net". With precise attribution the parser composes without Net,
        # so the policy PASSES under the wasm-sandbox posture (it was
        # blocked by the module-wide over-attribution before).
        root = self.tmp / "prod"
        _build_product(root)
        _write(root, "capa-policy.toml", (
            '[[policy]]\nid = "parse-no-net"\nkind = "forbid-capability"\n'
            'capability = "Net"\npackage = "parser"\n'
        ))
        module, manifest = _link(root, "main.capa")
        composed = build_composed_sbom(
            module, manifest, root.resolve(), enforcement="wasm-sandbox",
        )
        policies = read_policy_file(find_policy_file(root.resolve()))
        report = evaluate_policies(composed, policies)
        result = next(
            r for r in report["results"] if r["policy"] == "parse-no-net"
        )
        self.assertTrue(result["pass"], report)

        # A forbid-capability on the fetcher (which DOES hold Net) still
        # fires -- the fix does not blunt the rule where it should bite.
        _write(root, "capa-policy.toml", (
            '[[policy]]\nid = "fetch-no-net"\nkind = "forbid-capability"\n'
            'capability = "Net"\npackage = "fetcher"\n'
        ))
        policies = read_policy_file(find_policy_file(root.resolve()))
        report = evaluate_policies(composed, policies)
        result = next(
            r for r in report["results"] if r["policy"] == "fetch-no-net"
        )
        self.assertFalse(result["pass"], report)

    def test_unresolvable_foreign_call_falls_back_to_union(self):
        # SOUNDNESS GUARD: a foreign call that cannot be resolved to a
        # specific declared boundary (here simulated by renaming the
        # parser's call target to a component that is not declared) must
        # fall back to the module-wide union rather than under-attribute,
        # so a real foreign cap is never dropped.
        root = self.tmp / "prod"
        _build_product(root)
        module, manifest = _link(root, "main.capa")
        for rec in manifest["functions"]:
            if rec.get("foreign_component_calls") == ["Parse.run"]:
                rec["foreign_component_calls"] = ["Ghost.run"]
        composed = build_composed_sbom(
            module, manifest, root.resolve(), enforcement="wasm-sandbox",
        )
        parser = _pkg(composed, "parser")
        # Falls back to the union across every declared boundary {Net, Fs}
        # -- an over-approximation (sound), never the empty precise set.
        self.assertEqual(parser["composed_capabilities"], ["Fs", "Net"])
        self.assertFalse(parser["composed_authority_unknown"])

    def test_missing_call_list_falls_back_to_union(self):
        # A manifest serialised before ``foreign_component_calls`` existed
        # (the key absent while ``calls_foreign_component`` is True) must
        # also fall back to the module-wide union.
        root = self.tmp / "prod"
        _build_product(root)
        module, manifest = _link(root, "main.capa")
        for rec in manifest["functions"]:
            if rec.get("foreign_component_calls") == ["Parse.run"]:
                del rec["foreign_component_calls"]
        composed = build_composed_sbom(
            module, manifest, root.resolve(), enforcement="wasm-sandbox",
        )
        parser = _pkg(composed, "parser")
        self.assertEqual(parser["composed_capabilities"], ["Fs", "Net"])


class TestCheckCapabilitiesPosture(_TmpTree):
    """F-2: --check-capabilities threads the --wasm posture, so a ceiling on
    a foreign-calling package is checked against BOUNDED authority under
    --wasm and stays fail-closed TOP without it."""

    def _product_with_ceiling(self) -> Path:
        # A single-package product whose function calls a Net foreign
        # boundary and declares a [capabilities] ceiling that INCLUDES Net.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net"]\n'
        ))
        _write(root, "main.capa", (
            'extern component Fetch from "fetch.wasm"\n'
            "    fun get(net: Net, x: Int) -> Int\n"
            "\n"
            "fun main(net: Net) -> Int\n"
            "    return Fetch.get(net, 1)\n"
        ))
        return root

    def test_wasm_ceiling_within_bound_passes(self):
        root = self._product_with_ceiling()
        rc, _out, err = _run_cli(
            ["--wasm", "--check-capabilities", str(root / "main.capa")],
            cwd=root,
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("OK", err)

    def test_without_wasm_ceiling_fails_closed(self):
        root = self._product_with_ceiling()
        rc, _out, err = _run_cli(
            ["--check-capabilities", str(root / "main.capa")],
            cwd=root,
        )
        # No enforcing posture: the foreign call composes as TOP, so the
        # ceiling cannot be proven and the gate honestly fails closed.
        self.assertEqual(rc, 1, err)


if __name__ == "__main__":
    unittest.main()
