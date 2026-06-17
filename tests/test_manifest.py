"""Focused tests for the capability manifest builder.

The bulk of manifest behaviour (attribute parsing, per-function
record content, ineligibility proofs, downstream SBOM / VEX /
SLSA wrappers) lives in
[`tests/test_attributes.py`](tests/test_attributes.py), which
grew from attribute-system tests into the de facto manifest
test file. The 2026-05-25 audit (item #9) noted that
``capa/manifest/`` had no test file named after itself even
though the builder is the oracle the property test
``test_runtime_classes_subset_of_manifest_classes`` relies on.

This file complements (does not duplicate) ``test_attributes.py``
by exercising the manifest's *structural* surface:

- the ``SCHEMA_VERSION`` constant and its propagation;
- the empty-module corner;
- ``capa_version`` override;
- ``filename`` propagation;
- determinism + idempotence of ``build_manifest``;
- the multi-implementor sort guarantee;
- the top-level dict shape.

Attribute-driven cases stay in ``test_attributes.py``.
"""

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from capa import Lexer, Parser, analyze
from capa.manifest import (
    SCHEMA_VERSION,
    build_cyclonedx,
    build_manifest,
    build_provenance,
    build_spdx,
)
from capa.loader import ModuleLoader


def _analysed(source: str):
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version_is_one(self):
        self.assertEqual(SCHEMA_VERSION, 1)

    def test_schema_version_in_manifest(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)


class TestEmptyModule(unittest.TestCase):
    def test_empty_module_returns_well_formed_manifest(self):
        m = build_manifest(_analysed(""))
        self.assertEqual(m["functions"], [])
        self.assertEqual(m["user_defined_capabilities"], [])
        self.assertEqual(m["summary"], {
            "total_functions": 0,
            "functions_with_capabilities": 0,
            "functions_with_attributes": 0,
            "functions_crossing_unsafe": 0,
            "declassification_sites": 0,
            "protocol_states": 0,
        })

    def test_empty_module_still_carries_schema_version(self):
        m = build_manifest(_analysed(""))
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertIn("capa_version", m)
        self.assertIsInstance(m["capa_version"], str)


class TestCapaVersionOverride(unittest.TestCase):
    def test_default_capa_version_matches_package(self):
        from capa import __version__
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["capa_version"], __version__)

    def test_explicit_capa_version_overrides_default(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            capa_version="9.9.9-test",
        )
        self.assertEqual(m["capa_version"], "9.9.9-test")


class TestFilenamePropagation(unittest.TestCase):
    def test_filename_appears_at_top_level(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            filename="my-program.capa",
        )
        self.assertEqual(m["filename"], "my-program.capa")

    def test_filename_appears_in_function_pos(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            filename="my-program.capa",
        )
        self.assertTrue(m["functions"][0]["pos"].startswith("my-program.capa:"))

    def test_default_filename_is_placeholder(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["filename"], "<input>")


class TestTopLevelShape(unittest.TestCase):
    """Contract: every manifest carries the documented keys.
    Consumers that rely on the shape (capa-language.com/manifest.html,
    the docgen renderer, the property test oracle) break silently
    if the top-level keys drift."""

    _REQUIRED_KEYS = {
        "capa_version",
        "schema_version",
        "filename",
        "user_defined_capabilities",
        "typestates",
        "functions",
        "summary",
    }

    _SUMMARY_KEYS = {
        "total_functions",
        "functions_with_capabilities",
        "functions_with_attributes",
        "functions_crossing_unsafe",
        "declassification_sites",
        "protocol_states",
    }

    def test_required_top_level_keys_present(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(set(m.keys()), self._REQUIRED_KEYS)

    def test_summary_keys_complete(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(set(m["summary"].keys()), self._SUMMARY_KEYS)

    def test_function_record_required_keys(self):
        m = build_manifest(
            _analysed("fun f(stdio: Stdio)\n    stdio.println(\"hi\")\n"),
        )
        fn = m["functions"][0]
        required = {
            "name", "container", "pos", "is_pub", "doc",
            "params", "return_type",
            "declared_capabilities",
            "transitively_reachable_capabilities",
            "provably_excluded_capabilities",
            "linear_obligations",
            "has_unsafe", "attributes", "calls",
            # Roadmap S4: constant-time guarantee flag.
            "constant_time",
            # Roadmap S2.5: the auditable @secret -> @public bridges.
            "declassifications",
            # Source-level identifiers + import-module disclosure for
            # SBOM emission. ``name`` and ``container`` stay as the
            # loader-time (possibly mangled) identifiers so internal
            # call resolution + bom-ref keying remain stable; the
            # ``source_*`` fields are what the regulator-facing SBOM
            # displays.
            "source_name", "source_container", "source_module_index",
        }
        self.assertEqual(set(fn.keys()), required)


class TestLinearObligations(unittest.TestCase):
    """Roadmap S1: the manifest surfaces must-consume (linear-type)
    obligations -- ``consumes`` lists linear params the function takes
    ownership of, ``produces_linear`` flags a function that hands a
    linear value back to its caller. Per-param ``is_linear`` marks the
    slot."""

    _SRC = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun main(_s: Stdio)\n"
        "    let h = open()\n"
        "    close(h)\n"
    )

    def _fn(self, name: str):
        m = build_manifest(_analysed(self._SRC))
        return next(f for f in m["functions"] if f["source_name"] == name)

    def test_producer_flags_produces_linear(self):
        op = self._fn("open")
        self.assertTrue(op["linear_obligations"]["produces_linear"])
        self.assertEqual(op["linear_obligations"]["consumes"], [])

    def test_consumer_lists_consumed_param(self):
        cl = self._fn("close")
        self.assertEqual(cl["linear_obligations"]["consumes"], ["h"])
        self.assertFalse(cl["linear_obligations"]["produces_linear"])

    def test_consumed_param_is_flagged_linear(self):
        cl = self._fn("close")
        hp = next(p for p in cl["params"] if p["name"] == "h")
        self.assertTrue(hp["is_linear"])
        self.assertTrue(hp["consuming"])

    def test_plain_function_has_empty_obligations(self):
        mn = self._fn("main")
        self.assertEqual(mn["linear_obligations"]["consumes"], [])
        self.assertFalse(mn["linear_obligations"]["produces_linear"])


class TestDeclassificationSites(unittest.TestCase):
    """``declassification_sites`` counts only genuine ``@secret ->
    @public`` bridges. A no-op declassify of an already-public value
    (which the analyzer warns about) must NOT inflate the count, since
    the field is defined as "every point where secret crosses to
    public". The count is precise only when the manifest is built with
    the analysis's ``expr_labels``; without it, the historical
    syntactic count stands."""

    def _build(self, src: str):
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, [e.format() for e in result.errors])
        return module, result

    def test_secret_declassify_is_counted(self):
        src = (
            "fun leak(s: @secret String, stdio: Stdio)\n"
            "    stdio.println(declassify(s, reason: \"audited\"))\n"
        )
        module, result = self._build(src)
        m = build_manifest(module, expr_labels=result.expr_labels)
        self.assertEqual(m["summary"]["declassification_sites"], 1)

    def test_noop_declassify_of_public_is_not_counted(self):
        src = (
            "fun noop(x: Int, stdio: Stdio)\n"
            "    let y = declassify(x, reason: \"no-op\")\n"
            "    stdio.println(\"${y}\")\n"
        )
        module, result = self._build(src)
        m = build_manifest(module, expr_labels=result.expr_labels)
        self.assertEqual(m["summary"]["declassification_sites"], 0)

    def test_mixed_counts_only_the_real_one(self):
        src = (
            "fun leak(s: @secret String, x: Int, stdio: Stdio)\n"
            "    stdio.println(declassify(s, reason: \"real\"))\n"
            "    let y = declassify(x, reason: \"noop\")\n"
            "    stdio.println(\"${y}\")\n"
        )
        module, result = self._build(src)
        m = build_manifest(module, expr_labels=result.expr_labels)
        self.assertEqual(m["summary"]["declassification_sites"], 1)
        # The single recorded entry is the real (secret) one.
        fn = m["functions"][0]
        self.assertEqual(len(fn["declassifications"]), 1)
        self.assertEqual(fn["declassifications"][0]["reason"], "real")

    def test_without_labels_falls_back_to_syntactic(self):
        # A manifest built WITHOUT expr_labels keeps the historical
        # syntactic count (every declassify), so manifest-only callers
        # are unaffected.
        src = (
            "fun noop(x: Int, stdio: Stdio)\n"
            "    let y = declassify(x, reason: \"no-op\")\n"
            "    stdio.println(\"${y}\")\n"
        )
        module, _ = self._build(src)
        m = build_manifest(module)  # no expr_labels
        self.assertEqual(m["summary"]["declassification_sites"], 1)


class TestSourceNameDemangle(unittest.TestCase):
    """The loader prefixes non-pub items imported from another module
    with ``_capa_m{N}__`` for collision-avoidance. The manifest must
    surface the source-level name (so a regulator-facing SBOM reads
    as the user wrote it) while still preserving the loader-time
    name on ``name`` / ``container`` so internal call-resolution and
    bom-ref keying stay collision-stable.

    Two of the three cases drive the real loader through tmpdir
    source files: this is the same harness ``tests/test_loader.py``
    uses, and it exercises the full
    ``ModuleLoader._mangle_private_items`` -> ``_demangle`` pipeline
    end-to-end. The single-module no-mangle case stays inline because
    no loader work is needed.
    """

    _MANGLE_RE = re.compile(r"^_capa_m(\d+)__(.+)$")

    def _link_and_build(self, root: Path):
        from capa.loader import ModuleLoader
        loader = ModuleLoader()
        linked = loader.load_root(
            root.read_text(encoding="utf-8"), str(root),
        )
        result = analyze(
            linked.module,
            source=root.read_text(encoding="utf-8"),
        )
        if not result.ok:
            raise AssertionError(
                f"analyser errors: {[e.format() for e in result.errors]}"
            )
        return build_manifest(linked.module, filename=str(root))

    def _tmpdir(self) -> Path:
        d = Path(tempfile.mkdtemp(prefix="capa_demangle_test_"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _write(self, root: Path, name: str, body: str) -> Path:
        p = root / name
        p.write_text(body, encoding="utf-8")
        return p

    def _find_fn(self, manifest: dict, source_name: str) -> dict:
        for fn in manifest["functions"]:
            if fn["source_name"] == source_name:
                return fn
        raise AssertionError(
            f"no function with source_name={source_name!r}; "
            f"present: {[f['source_name'] for f in manifest['functions']]}"
        )

    def test_root_module_function_has_no_demangle(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        fn = m["functions"][0]
        self.assertEqual(fn["name"], "f")
        self.assertEqual(fn["source_name"], "f")
        self.assertIsNone(fn["source_module_index"])
        self.assertIsNone(fn["container"])
        self.assertIsNone(fn["source_container"])

    def test_imported_non_pub_function_gets_demangled(self):
        d = self._tmpdir()
        self._write(
            d, "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
            "pub fun via_helper(n: Int) -> Int\n"
            "    return helper(n)\n",
        )
        root = self._write(
            d, "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        m = self._link_and_build(root)
        # The loader assigns the mangle counter sequentially; rather
        # than hard-coding it, parse the index out of the mangled
        # name itself with the same regex the source uses.
        candidates = [
            fn for fn in m["functions"]
            if fn["source_name"] == "helper"
        ]
        self.assertEqual(len(candidates), 1, candidates)
        fn = candidates[0]
        match = self._MANGLE_RE.match(fn["name"])
        self.assertIsNotNone(
            match,
            f"expected mangled name on imported non-pub helper; got {fn['name']!r}",
        )
        expected_index = int(match.group(1))
        self.assertEqual(match.group(2), "helper")
        self.assertEqual(fn["source_name"], "helper")
        self.assertEqual(fn["source_module_index"], expected_index)

    def test_imported_function_pos_carries_its_own_file(self):
        # Regression (migrate slice 3 groundwork): an imported
        # function's manifest ``pos`` used to stamp the ROOT file's
        # name onto the imported file's line/col, i.e. a position in
        # the wrong file. It must carry the declaring file instead --
        # in root-relative form, so the manifest never embeds the
        # builder machine's absolute directory layout.
        d = self._tmpdir()
        self._write(
            d, "util.capa",
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n",
        )
        root = self._write(
            d, "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        m = self._link_and_build(root)
        helper = self._find_fn(m, "helper")
        self.assertTrue(
            helper["pos"].startswith("util.capa:"), helper["pos"],
        )
        main = self._find_fn(m, "main")
        self.assertTrue(
            main["pos"].startswith("root.capa:"), main["pos"],
        )

    def test_subdirectory_import_pos_is_relative_posix(self):
        # A module imported from a subdirectory (the vendored-deps
        # shape) records a root-relative path with '/' separators on
        # every OS, so the same project produces byte-identical
        # manifests on Windows and Linux and across machines. The raw
        # loader path is absolute (and machine-specific); none of that
        # may leak into the manifest.
        d = self._tmpdir()
        (d / "vendor").mkdir()
        self._write(
            d / "vendor", "lib.capa",
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n",
        )
        root = self._write(
            d, "root.capa",
            "import vendor.lib\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        m = self._link_and_build(root)
        helper = self._find_fn(m, "helper")
        self.assertTrue(
            helper["pos"].startswith("vendor/lib.capa:"), helper["pos"],
        )
        self.assertNotIn("\\", helper["pos"])
        self.assertNotIn(str(d), helper["pos"])

    def test_module_outside_root_tree_keeps_its_path(self):
        # A module resolved from OUTSIDE the root file's directory
        # (e.g. via a CAPA_PATH search root) has no stable base to
        # relativise against; its path stays exactly as the loader
        # lexed it, which also tells the auditor the code came from
        # outside the project tree.
        from capa.loader import ModuleLoader
        d = self._tmpdir()
        lib_dir = d / "elsewhere"
        lib_dir.mkdir()
        self._write(
            lib_dir, "ext.capa",
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n",
        )
        proj = d / "proj"
        proj.mkdir()
        root = self._write(
            proj, "root.capa",
            "import ext\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        loader = ModuleLoader(search_paths=[lib_dir])
        linked = loader.load_root(
            root.read_text(encoding="utf-8"), str(root),
        )
        result = analyze(
            linked.module, source=root.read_text(encoding="utf-8"),
        )
        self.assertTrue(result.ok, result.errors)
        m = build_manifest(linked.module, filename=str(root))
        helper = self._find_fn(m, "helper")
        expected = str((lib_dir / "ext.capa").resolve())
        self.assertTrue(
            helper["pos"].startswith(expected + ":"), helper["pos"],
        )

    def test_imported_pub_function_is_not_mangled(self):
        d = self._tmpdir()
        self._write(
            d, "util.capa",
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n",
        )
        root = self._write(
            d, "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    let n = helper(3)\n"
            "    stdio.println(\"hi\")\n",
        )
        m = self._link_and_build(root)
        fn = self._find_fn(m, "helper")
        self.assertEqual(fn["name"], "helper")
        self.assertEqual(fn["source_name"], "helper")
        self.assertIsNone(fn["source_module_index"])

    def test_imported_non_pub_capability_is_demangled_in_user_surfaces(self):
        """Audit slice 20 (2026-05-29) regression: a non-pub capability
        defined in an imported module used to leak its loader prefix
        (``_capa_m{N}__LocalCap``) into ``user_defined_capabilities``,
        the per-param ``type`` field, ``declared_capabilities``,
        ``provably_excluded_capabilities``, and the implementor list -
        every regulator-facing surface. The fix demangles all of these
        while keeping ``name`` / ``container`` mangled for stable
        internal bom-ref keying."""
        d = self._tmpdir()
        self._write(
            d, "mod_cap.capa",
            "capability LocalCap\n"
            "    fun describe(self) -> String\n"
            "\n"
            "type LocalImpl {\n"
            "    label: String\n"
            "}\n"
            "\n"
            "impl LocalCap for LocalImpl\n"
            "    fun describe(self) -> String\n"
            "        return self.label\n"
            "\n"
            "pub fun use_it(c: LocalCap) -> String\n"
            "    return c.describe()\n",
        )
        root = self._write(
            d, "root.capa",
            "import mod_cap\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        m = self._link_and_build(root)
        rendered = json.dumps(m)
        # The user-facing capability list must read as the user wrote
        # it, with no loader prefix anywhere in the cap record.
        caps = [c for c in m["user_defined_capabilities"] if c["name"] == "LocalCap"]
        self.assertEqual(len(caps), 1, m["user_defined_capabilities"])
        cap = caps[0]
        self.assertNotIn("_capa_m", cap["name"])
        for impl in cap["implementors"]:
            self.assertNotIn("_capa_m", impl)
        self.assertIn("LocalImpl", cap["implementors"])

        fn = self._find_fn(m, "use_it")
        # Parameter type, declared cap list, and the (empty here)
        # exclusion list must all be in the source-level namespace.
        self.assertEqual(fn["params"][0]["type"], "LocalCap")
        self.assertIn("LocalCap", fn["declared_capabilities"])
        for excluded in fn["provably_excluded_capabilities"]:
            self.assertNotIn("_capa_m", excluded)
        self.assertNotIn("LocalCap", fn["provably_excluded_capabilities"])
        # Catch-all guard: no regulator-facing field anywhere on this
        # function record carries the prefix.
        leak_re = re.compile(r"_capa_m\d+__LocalCap")
        for field in (
            "source_name", "source_container",
            "return_type",
            *(p["type"] for p in fn["params"]),
            *fn["declared_capabilities"],
            *fn["provably_excluded_capabilities"],
        ):
            self.assertIsNone(
                leak_re.search(str(field)),
                f"unexpected mangled cap name leaked: {field!r}",
            )


class TestPerImplReachability(unittest.TestCase):
    """Audit slice 21 closure (2026-05-29): the
    ``provably_excluded_capabilities`` field is computed against
    the per-impl reachability closure, not the signature alone.
    Before the closure a function ``use_logger(lg: FileLogger)``
    where ``FileLogger { out: Stdio }`` and the impl method
    ``log(self, msg) { self.out.println(msg) }`` falsely claimed
    Stdio was provably excluded; running the function in fact
    printed via Stdio. The fix walks every in-scope impl of each
    user-cap and every cap-bearing struct's field types, unions
    the built-in caps reachable through them, and surfaces the
    union as ``transitively_reachable_capabilities``."""

    def _build(self, src: str) -> dict[str, Any]:
        return build_manifest(_analysed(src))

    def _find(self, m: dict[str, Any], name: str) -> dict[str, Any]:
        for fn in m["functions"]:
            if fn["source_name"] == name:
                return fn
        raise AssertionError(
            f"no function {name!r}; present: "
            f"{[f['source_name'] for f in m['functions']]}"
        )

    def test_struct_param_reaches_wrapped_builtin_cap(self):
        m = self._build(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type FileLogger { out: Stdio }\n"
            "impl Logger for FileLogger\n"
            "    fun log(self, msg: String)\n"
            "        self.out.println(msg)\n"
            "fun new_logger(s: Stdio) -> FileLogger\n"
            "    return FileLogger { out: s }\n"
            "fun use_logger(lg: FileLogger)\n"
            "    lg.log(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    use_logger(new_logger(stdio))\n"
        )
        use = self._find(m, "use_logger")
        # Signature declares nothing (FileLogger isn't a cap).
        self.assertEqual(use["declared_capabilities"], [])
        # Transitive reachable includes Stdio via the impl chain.
        self.assertIn("Stdio", use["transitively_reachable_capabilities"])
        # Exclusion must NOT claim Stdio is unreachable.
        self.assertNotIn(
            "Stdio", use["provably_excluded_capabilities"]
        )

    def test_user_cap_param_reaches_wrapped_builtin_cap(self):
        # Same shape via the user-cap trait param. Logger's only
        # impl in scope is FileLogger which holds Stdio; passing
        # any Logger to use_logger therefore reaches Stdio.
        m = self._build(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type FileLogger { out: Stdio }\n"
            "impl Logger for FileLogger\n"
            "    fun log(self, msg: String)\n"
            "        self.out.println(msg)\n"
            "fun new_logger(s: Stdio) -> FileLogger\n"
            "    return FileLogger { out: s }\n"
            "fun use_logger(lg: Logger)\n"
            "    lg.log(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    use_logger(new_logger(stdio))\n"
        )
        use = self._find(m, "use_logger")
        self.assertIn("Logger", use["declared_capabilities"])
        self.assertIn("Stdio", use["transitively_reachable_capabilities"])
        self.assertNotIn(
            "Stdio", use["provably_excluded_capabilities"]
        )

    def test_unsafe_in_cap_bearing_struct_is_rejected(self):
        # Audit 2026-06-17 C5(a): the cap-bearing relaxation lets a
        # struct that implements a user-cap encapsulate the
        # ATTENUABLE built-in caps in its fields, but Unsafe never
        # benefits from it (it is the FFI escape hatch, not an
        # attenuable cap). A struct field of type Unsafe is rejected
        # at analysis even when the struct implements a user-cap, so
        # the manifest can never be built for such a program.
        tokens = Lexer(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { u: Unsafe }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
            "fun use_it(c: Client) -> Int\n"
            "    return c.do_it()\n"
        ).lex()
        module = Parser(tokens).parse_module()
        result = analyze(module)
        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                "Unsafe" in e.message
                and "capability-bearing struct" in e.message
                for e in result.errors
            ),
            result.errors,
        )

    def test_no_impl_means_no_extras(self):
        # A user-cap with no in-scope impls reaches no caps;
        # functions taking it claim a strong exclusion.
        m = self._build(
            "capability Empty\n"
            "    fun ping(self)\n"
            "fun take(e: Empty)\n"
            "    e.ping()\n"
        )
        take = self._find(m, "take")
        self.assertEqual(
            take["transitively_reachable_capabilities"], ["Empty"],
        )
        # All built-in caps remain provably excluded.
        for cap in ("Stdio", "Fs", "Net", "Unsafe", "Clock"):
            self.assertIn(
                cap, take["provably_excluded_capabilities"],
            )

    def test_impl_method_self_carries_wrapped_caps(self):
        # An impl method on a cap-bearing struct sees its
        # wrapped caps through ``self``. The method itself
        # cannot claim Stdio is excluded.
        m = self._build(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type FileLogger { out: Stdio }\n"
            "impl Logger for FileLogger\n"
            "    fun log(self, msg: String)\n"
            "        self.out.println(msg)\n"
        )
        log = self._find(m, "log")
        self.assertIn("Stdio", log["transitively_reachable_capabilities"])
        self.assertNotIn(
            "Stdio", log["provably_excluded_capabilities"],
        )

    def test_user_cap_via_struct_is_reachable_not_excluded(self):
        # Audit 2026-06-17 C6: a holder of a cap-bearing struct ``S``
        # can exercise the user-cap ``C`` that ``S`` implements (by
        # calling a method of ``C`` on the value), so ``C`` is in the
        # transitive reachable set and NOT provably excluded. The
        # claim is derived from the SIGNATURE, so it cannot depend on
        # whether the body happens to call the method - a body that
        # does call it would emit the same record, and only the
        # conservative answer (cap reachable) is sound.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "fun process(m: SmtpMailer) -> Bool\n"
            "    return m.send(\"a@b\")\n"
        )
        proc = self._find(m, "process")
        self.assertIn(
            "SendEmail", proc["transitively_reachable_capabilities"],
        )
        self.assertNotIn(
            "SendEmail", proc["provably_excluded_capabilities"],
        )
        # The wrapped built-in cap (Net) is reachable too, and no
        # user-cap that is exercised ever lands in the exclusion set.
        self.assertIn("Net", proc["transitively_reachable_capabilities"])

    def test_user_cap_inert_body_still_reachable(self):
        # Same struct, but the body never calls ``send`` (returns a
        # constant). The conservative bound still reports SendEmail
        # reachable - the signature alone determines it, so a quiet
        # body cannot be used to falsely claim exclusion.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "fun greeting(mailer: SmtpMailer) -> Int\n"
            "    return 1\n"
        )
        g = self._find(m, "greeting")
        self.assertIn(
            "SendEmail", g["transitively_reachable_capabilities"],
        )
        self.assertNotIn(
            "SendEmail", g["provably_excluded_capabilities"],
        )

    def test_plain_struct_nesting_cap_bearing_struct_propagates(self):
        # Audit 2026-06-17: a PLAIN data struct ``Outer { mailer:
        # SmtpMailer }`` that merely nests a cap-bearing struct must
        # propagate the nested caps. ``process(o: Outer)`` calling
        # ``o.mailer.send(...)`` exercises both the user-cap SendEmail
        # and the built-in Net wrapped inside SmtpMailer; pre-fix the
        # manifest falsely provably-excluded both because Outer (not
        # being cap-bearing) had no reachable entry and resolved empty.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "type Outer { mailer: SmtpMailer }\n"
            "fun process(o: Outer) -> Bool\n"
            "    return o.mailer.send(\"a@b\")\n"
        )
        proc = self._find(m, "process")
        self.assertIn(
            "SendEmail", proc["transitively_reachable_capabilities"],
        )
        self.assertIn(
            "Net", proc["transitively_reachable_capabilities"],
        )
        self.assertNotIn(
            "SendEmail", proc["provably_excluded_capabilities"],
        )
        self.assertNotIn(
            "Net", proc["provably_excluded_capabilities"],
        )

    def test_two_level_struct_nesting_propagates(self):
        # A deeper chain: Outer -> Middle -> SmtpMailer. Both plain
        # data structs must carry the nested caps up so a function
        # touching the outermost struct still reports Net + SendEmail.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "type Middle { mailer: SmtpMailer }\n"
            "type Outer { mid: Middle }\n"
            "fun process(o: Outer) -> Bool\n"
            "    return o.mid.mailer.send(\"a@b\")\n"
        )
        proc = self._find(m, "process")
        self.assertIn(
            "SendEmail", proc["transitively_reachable_capabilities"],
        )
        self.assertIn(
            "Net", proc["transitively_reachable_capabilities"],
        )
        self.assertNotIn(
            "SendEmail", proc["provably_excluded_capabilities"],
        )
        self.assertNotIn(
            "Net", proc["provably_excluded_capabilities"],
        )

    def test_plain_struct_not_nesting_cap_keeps_strong_exclusion(self):
        # Guard against over-propagation: a plain data struct with no
        # cap-bearing field reaches nothing, so a function taking it
        # still provably-excludes every built-in cap.
        m = self._build(
            "type Plain { n: Int }\n"
            "fun touch(p: Plain) -> Int\n"
            "    return p.n\n"
        )
        fn = self._find(m, "touch")
        self.assertEqual(fn["transitively_reachable_capabilities"], [])
        for cap in ("Stdio", "Fs", "Net", "Unsafe", "Clock"):
            self.assertIn(cap, fn["provably_excluded_capabilities"])

    def test_sum_variant_payload_carries_cap_bearing_struct(self):
        # Audit 2026-06-17: a cap reachable ONLY through a sum-variant
        # payload. ``Wrap = Carry(SmtpMailer) | Nope`` with
        # ``process(w: Wrap)`` doing ``match w { Carry(m) -> m.send }``
        # exercises both the user-cap SendEmail and the built-in Net
        # wrapped inside SmtpMailer; pre-fix the sum had no reachable
        # entry so both were falsely provably-excluded.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "type Wrap =\n"
            "    Carry(SmtpMailer)\n"
            "    Nope\n"
            "fun process(w: Wrap) -> Bool\n"
            "    match w\n"
            "        Carry(m) -> return m.send(\"a@b\")\n"
            "        Nope -> return false\n"
        )
        proc = self._find(m, "process")
        self.assertIn("SendEmail", proc["transitively_reachable_capabilities"])
        self.assertIn("Net", proc["transitively_reachable_capabilities"])
        self.assertNotIn("SendEmail", proc["provably_excluded_capabilities"])
        self.assertNotIn("Net", proc["provably_excluded_capabilities"])

    def test_sum_in_struct_field_propagates_variant_caps(self):
        # The sum is nested inside a plain struct field: Outer { w: Wrap }.
        # Both the struct's reachable entry and the sum's must compose so
        # ``handle(o: Outer)`` still reports Net + SendEmail.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "type Wrap =\n"
            "    Carry(SmtpMailer)\n"
            "    Nope\n"
            "type Outer { w: Wrap }\n"
            "fun handle(o: Outer) -> Bool\n"
            "    match o.w\n"
            "        Carry(m) -> return m.send(\"a@b\")\n"
            "        Nope -> return false\n"
        )
        fn = self._find(m, "handle")
        self.assertIn("SendEmail", fn["transitively_reachable_capabilities"])
        self.assertIn("Net", fn["transitively_reachable_capabilities"])
        self.assertNotIn("SendEmail", fn["provably_excluded_capabilities"])
        self.assertNotIn("Net", fn["provably_excluded_capabilities"])

    def test_sum_carrying_struct_that_nests_cap_chain_propagates(self):
        # Chain through a sum: Wrap = Hold(Middle) where Middle nests a
        # cap-bearing SmtpMailer. The sum's reachable set must pick up the
        # transitively-closed reachable set of the struct it carries.
        m = self._build(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "type Middle { mailer: SmtpMailer }\n"
            "type Wrap =\n"
            "    Hold(Middle)\n"
            "    Nope\n"
            "fun process(w: Wrap) -> Bool\n"
            "    match w\n"
            "        Hold(mid) -> return mid.mailer.send(\"a@b\")\n"
            "        Nope -> return false\n"
        )
        proc = self._find(m, "process")
        self.assertIn("SendEmail", proc["transitively_reachable_capabilities"])
        self.assertIn("Net", proc["transitively_reachable_capabilities"])
        self.assertNotIn("SendEmail", proc["provably_excluded_capabilities"])
        self.assertNotIn("Net", proc["provably_excluded_capabilities"])

    def test_pure_data_sum_still_excludes_everything(self):
        # Guard against over-declaration: a sum whose variants carry only
        # plain data reaches no cap, so a function taking it still
        # provably-excludes every built-in cap.
        m = self._build(
            "type Color =\n"
            "    Red\n"
            "    Named(String)\n"
            "fun describe(c: Color) -> Int\n"
            "    match c\n"
            "        Red -> return 0\n"
            "        Named(s) -> return 1\n"
        )
        fn = self._find(m, "describe")
        self.assertEqual(fn["transitively_reachable_capabilities"], [])
        for cap in ("Stdio", "Fs", "Net", "Unsafe", "Clock"):
            self.assertIn(cap, fn["provably_excluded_capabilities"])


class TestSourceNameInSboms(unittest.TestCase):
    """The CycloneDX / SPDX wrappers must display the source-level
    name on each function component (so the SBOM reads as a
    regulator expects) while keeping the loader-time name on the
    bom-ref / SPDXID so cross-module references still resolve.

    To keep these tests independent of any specific loader-counter
    allocation we build a single-module AST programmatically and
    hand-set a function's ``.name`` to a simulated mangle
    (``_capa_m3__as_object_or_err``). The de-mangle helper lives on
    the manifest builder and is unaware of how the mangle arrived,
    so this is faithful to the real pipeline; the alternative
    (driving a real multi-module program) would only add I/O without
    exercising any extra code under test.
    """

    _MANGLED = "_capa_m3__as_object_or_err"
    _SOURCE = "as_object_or_err"
    _INDEX = 3

    def _module_with_mangled_fn(self):
        # Round-trip a tiny program through the parser, then
        # rename the FunDecl in place to simulate what the loader's
        # ``_mangle_private_items`` would have produced for a non-pub
        # imported helper.
        src = "fun as_object_or_err() -> Int\n    return 0\n"
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        if not result.ok:
            raise AssertionError(
                f"analyser errors: {[e.format() for e in result.errors]}"
            )
        for item in module.items:
            if getattr(item, "name", None) == self._SOURCE:
                item.name = self._MANGLED
                break
        else:
            raise AssertionError("test setup: target function not found")
        return module

    def test_cyclonedx_shows_source_name_with_source_module_index_property(self):
        module = self._module_with_mangled_fn()
        doc = build_cyclonedx(
            module,
            filename="program.capa",
            timestamp="2026-01-01T00:00:00Z",
        )
        # Round-trip through JSON to mirror the wire shape consumers
        # will see; catches any non-serialisable value sneaking in.
        doc = json.loads(json.dumps(doc))

        targets = [
            c for c in doc["components"]
            if c.get("bom-ref", "").endswith(self._MANGLED)
        ]
        self.assertEqual(len(targets), 1, targets)
        comp = targets[0]
        self.assertEqual(
            comp["name"], self._SOURCE,
            "displayed component name must be the source-level identifier",
        )
        self.assertIn(
            self._MANGLED, comp["bom-ref"],
            "bom-ref must keep the loader-time name so cross-module"
            " references still resolve",
        )
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(
            props.get("capa:source_module_index"), str(self._INDEX),
        )
        # Sanity: no still-mangled name leaked into the displayed
        # component-name surface anywhere in the document.
        self.assertFalse(
            any(
                c.get("name", "").startswith("_capa_m")
                for c in doc["components"]
            ),
            "no component should display a still-mangled name",
        )

    def test_spdx_shows_source_name_with_source_module_index_annotation(self):
        module = self._module_with_mangled_fn()
        doc = build_spdx(
            module,
            filename="program.capa",
            timestamp="2026-01-01T00:00:00Z",
        )
        doc = json.loads(json.dumps(doc))

        # SPDXIDs sanitise non-conforming characters (the allowed
        # alphabet is [a-zA-Z0-9.-]; underscores become dashes via
        # ``_spdx_id``). Match by source-name and then assert the
        # sanitised mangle survives, which is what cross-module
        # references rely on inside SPDX-land.
        sanitised_mangle = "capa-m3--as-object-or-err"
        targets = [
            p for p in doc["packages"]
            if p.get("name") == self._SOURCE
        ]
        self.assertEqual(len(targets), 1, targets)
        pkg = targets[0]
        self.assertIn(
            sanitised_mangle, pkg["SPDXID"],
            "SPDXID must keep the (sanitised) loader-time name so"
            " cross-module references still resolve",
        )
        annot_comments = [
            a["comment"] for a in pkg.get("annotations", [])
        ]
        self.assertIn(
            f"capa:source_module_index={self._INDEX}",
            annot_comments,
        )
        # Sanity: no still-mangled name leaked into any package name.
        self.assertFalse(
            any(
                p.get("name", "").startswith("_capa_m")
                for p in doc["packages"]
            ),
            "no package should display a still-mangled name",
        )


class TestDeterminism(unittest.TestCase):
    """Same source, two runs -> identical manifest dicts. The
    property test ``test_runtime_classes_subset_of_manifest_classes``
    in ``test_properties.py`` depends on this: it generates a
    program, lowers it, and compares the manifest against the
    runtime trace. Non-determinism would surface as flakes."""

    def test_repeated_build_is_byte_equal(self):
        src = (
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"ok\")\n"
        )
        m1 = build_manifest(_analysed(src))
        m2 = build_manifest(_analysed(src))
        self.assertEqual(m1, m2)


class TestBuildTimestampResolution(unittest.TestCase):
    """The SOURCE_DATE_EPOCH resolver: valid -> formatted UTC string,
    absent -> None (wall-clock fallback), invalid -> hard error."""

    def test_absent_returns_none(self):
        from capa.manifest import resolve_build_timestamp
        self.assertIsNone(resolve_build_timestamp(environ={}))

    def test_valid_epoch_formats_utc(self):
        from capa.manifest import resolve_build_timestamp
        ts = resolve_build_timestamp(
            environ={"SOURCE_DATE_EPOCH": "1609459200"}
        )
        self.assertEqual(ts, "2021-01-01T00:00:00Z")

    def test_surrounding_whitespace_tolerated(self):
        from capa.manifest import resolve_build_timestamp
        self.assertEqual(
            resolve_build_timestamp(environ={"SOURCE_DATE_EPOCH": " 1609459200 "}),
            "2021-01-01T00:00:00Z",
        )

    def test_garbage_raises(self):
        from capa.manifest import resolve_build_timestamp, SourceDateEpochError
        with self.assertRaises(SourceDateEpochError):
            resolve_build_timestamp(environ={"SOURCE_DATE_EPOCH": "xyz"})

    def test_negative_raises(self):
        from capa.manifest import resolve_build_timestamp, SourceDateEpochError
        with self.assertRaises(SourceDateEpochError):
            resolve_build_timestamp(environ={"SOURCE_DATE_EPOCH": "-5"})

    def test_huge_value_raises_controlled_not_traceback(self):
        # Out of any time_t / datetime range. ``fromtimestamp`` would
        # raise OverflowError; the resolver must convert it into the
        # same controlled SourceDateEpochError, never a raw traceback.
        from capa.manifest import resolve_build_timestamp, SourceDateEpochError
        with self.assertRaises(SourceDateEpochError):
            resolve_build_timestamp(
                environ={"SOURCE_DATE_EPOCH": "99999999999999999999"}
            )

    def test_year_10000_raises_controlled(self):
        # 253402300800 is 10000-01-01T00:00:00Z, one second past
        # datetime.MAXYEAR; ``fromtimestamp`` raises ValueError/OSError
        # depending on the platform. Must be a controlled error.
        from capa.manifest import resolve_build_timestamp, SourceDateEpochError
        with self.assertRaises(SourceDateEpochError):
            resolve_build_timestamp(
                environ={"SOURCE_DATE_EPOCH": "253402300800"}
            )

    def test_far_future_but_representable_passes(self):
        # A distant-but-valid epoch (32503680000 == 3000-01-01Z, well
        # inside year 9999) must format cleanly, not be over-rejected
        # by an off-by-one upper bound.
        from capa.manifest import resolve_build_timestamp
        self.assertEqual(
            resolve_build_timestamp(
                environ={"SOURCE_DATE_EPOCH": "32503680000"}
            ),
            "3000-01-01T00:00:00Z",
        )

    def test_zero_epoch_is_unix_origin(self):
        from capa.manifest import resolve_build_timestamp
        self.assertEqual(
            resolve_build_timestamp(environ={"SOURCE_DATE_EPOCH": "0"}),
            "1970-01-01T00:00:00Z",
        )

    def test_strict_decimal_rejects_non_canonical_forms(self):
        # reproducible-builds.org mandates a plain decimal integer.
        # ``int()`` is laxer than that; these forms must all be
        # rejected so two toolchains agree on what is valid.
        from capa.manifest import resolve_build_timestamp, SourceDateEpochError
        for bad in ("+1", "1_000", "08", "0x10", "123.0", "", "  "):
            with self.subTest(value=bad):
                with self.assertRaises(SourceDateEpochError):
                    resolve_build_timestamp(
                        environ={"SOURCE_DATE_EPOCH": bad}
                    )


class TestInvocationStyleReproducibility(unittest.TestCase):
    """Artefact-level byte-reproducibility across invocation styles.

    The same project, built with the root path passed absolute,
    relative from inside the project directory, or relative from a
    different cwd, must produce byte-identical manifest / CycloneDX /
    SPDX / provenance output modulo timestamps (pinned here so the
    comparison is exact). Pre-fix, the top-level ``filename`` field
    echoed the raw CLI argument and the deterministic uuid5 seeds
    (CycloneDX ``serialNumber``, SPDX ``documentNamespace``,
    provenance ``invocationId``) derived from it, so the artefacts
    varied with the invocation style and across machines even though
    every per-function ``pos`` was already root-relative.
    """

    _TS = "2026-01-01T00:00:00Z"

    def setUp(self):
        import os
        self.addCleanup(os.chdir, os.getcwd())
        d = Path(tempfile.mkdtemp(prefix="capa_repro_test_")).resolve()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "vendor").mkdir()
        (d / "vendor" / "lib.capa").write_text(
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n",
            encoding="utf-8",
        )
        self.root = d / "root.capa"
        self.root.write_text(
            "import vendor.lib\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
            encoding="utf-8",
        )
        self.project_dir = d

    def _artefacts(self, filename: str) -> dict[str, str]:
        """Build all four artefacts for the project under the given
        root-path spelling, timestamps pinned, serialised to the same
        JSON shape the CLI prints."""
        from capa.loader import ModuleLoader
        from capa.manifest import build_provenance
        source = self.root.read_text(encoding="utf-8")
        linked = ModuleLoader().load_root(source, filename)
        result = analyze(linked.module, source=source)
        self.assertTrue(result.ok, result.errors)
        return {
            "manifest": json.dumps(
                build_manifest(linked.module, filename=filename),
                indent=2,
            ),
            "cyclonedx": json.dumps(
                build_cyclonedx(
                    linked.module, filename=filename, timestamp=self._TS,
                    source=source,
                ),
                indent=2,
            ),
            "spdx": json.dumps(
                build_spdx(
                    linked.module, filename=filename, timestamp=self._TS,
                    source=source,
                ),
                indent=2,
            ),
            "provenance": json.dumps(
                build_provenance(
                    source, filename=filename,
                    started_on=self._TS, finished_on=self._TS,
                ),
                indent=2,
            ),
        }

    def test_invocation_styles_produce_byte_identical_artefacts(self):
        import os
        absolute = self._artefacts(str(self.root))
        os.chdir(self.project_dir)
        relative = self._artefacts("root.capa")
        os.chdir(self.project_dir.parent)
        from_other_cwd = self._artefacts(
            str(Path(self.project_dir.name) / "root.capa"),
        )
        for kind in ("manifest", "cyclonedx", "spdx", "provenance"):
            self.assertEqual(absolute[kind], relative[kind], kind)
            self.assertEqual(absolute[kind], from_other_cwd[kind], kind)

    def test_no_artefact_embeds_the_project_directory(self):
        # The builder machine's directory layout (and username) must
        # never appear anywhere in any artefact, even when the CLI is
        # handed the absolute path. Compare against the JSON-escaped
        # spelling so Windows backslashes are matched as serialised.
        arts = self._artefacts(str(self.root))
        leak = json.dumps(str(self.project_dir))[1:-1]
        for kind, text in arts.items():
            self.assertNotIn(leak, text, kind)

    def test_top_level_filename_is_display_form(self):
        m = json.loads(self._artefacts(str(self.root))["manifest"])
        self.assertEqual(m["filename"], "root.capa")


class TestBasenameCollisionResistance(unittest.TestCase):
    """Two unrelated projects whose root files share a basename
    (every project called ``main.capa``) must NOT collide on the
    deterministic identifiers. Seeding from the display form alone
    would collide; the source digest in the seed (the shape the
    provenance ``invocationId`` always had) keeps them apart while
    the display form keeps the same project byte-identical across
    invocation styles (covered by
    :class:`TestInvocationStyleReproducibility`)."""

    _TS = "2026-01-01T00:00:00Z"

    def _project(self, body: str):
        d = Path(tempfile.mkdtemp(prefix="capa_collide_test_")).resolve()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        root = d / "main.capa"
        root.write_text(body, encoding="utf-8")
        source = root.read_text(encoding="utf-8")
        from capa.loader import ModuleLoader
        linked = ModuleLoader().load_root(source, str(root))
        result = analyze(linked.module, source=source)
        self.assertTrue(result.ok, result.errors)
        return linked.module, source, str(root)

    def setUp(self):
        self.mod_a, self.src_a, self.file_a = self._project(
            "fun main(stdio: Stdio)\n    stdio.println(\"project a\")\n"
        )
        self.mod_b, self.src_b, self.file_b = self._project(
            "fun main(stdio: Stdio)\n    stdio.println(\"project b\")\n"
        )

    def test_cyclonedx_serial_numbers_differ(self):
        a = build_cyclonedx(
            self.mod_a, filename=self.file_a, source=self.src_a,
            timestamp=self._TS,
        )
        b = build_cyclonedx(
            self.mod_b, filename=self.file_b, source=self.src_b,
            timestamp=self._TS,
        )
        self.assertNotEqual(a["serialNumber"], b["serialNumber"])

    def test_spdx_document_namespaces_differ(self):
        a = build_spdx(
            self.mod_a, filename=self.file_a, source=self.src_a,
            timestamp=self._TS,
        )
        b = build_spdx(
            self.mod_b, filename=self.file_b, source=self.src_b,
            timestamp=self._TS,
        )
        self.assertNotEqual(a["documentNamespace"], b["documentNamespace"])

    def test_provenance_invocation_ids_differ(self):
        from capa.manifest import build_provenance
        a = build_provenance(
            self.src_a, filename=self.file_a,
            started_on=self._TS, finished_on=self._TS,
        )
        b = build_provenance(
            self.src_b, filename=self.file_b,
            started_on=self._TS, finished_on=self._TS,
        )
        self.assertNotEqual(
            a["predicate"]["runDetails"]["metadata"]["invocationId"],
            b["predicate"]["runDetails"]["metadata"]["invocationId"],
        )

    def test_same_project_same_identifiers_across_invocation_styles(self):
        # The digest must not reintroduce invocation-style variance:
        # absolute vs relative spelling of the same root still agree.
        import os
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(Path(self.file_a).parent)
        absolute = build_cyclonedx(
            self.mod_a, filename=self.file_a, source=self.src_a,
            timestamp=self._TS,
        )
        relative = build_cyclonedx(
            self.mod_a, filename="main.capa", source=self.src_a,
            timestamp=self._TS,
        )
        self.assertEqual(absolute["serialNumber"], relative["serialNumber"])


class TestInMemoryPlaceholderSeeds(unittest.TestCase):
    """The lexer's synthetic in-memory placeholder (``<input>``) must
    pass through the display relativisation unchanged, on every OS
    and from any cwd. Pinned to literal uuid5 values so any drift in
    the seed input (e.g. the placeholder accidentally being resolved
    against the cwd) fails loudly."""

    _SRC = "fun f()\n    return\n"

    def test_manifest_filename_stays_placeholder(self):
        m = build_manifest(_analysed(self._SRC))
        self.assertEqual(m["filename"], "<input>")

    def test_cyclonedx_serial_number_pinned(self):
        sbom = build_cyclonedx(
            _analysed(self._SRC), timestamp="2026-01-01T00:00:00Z",
        )
        self.assertEqual(
            sbom["serialNumber"],
            "urn:uuid:44ab6878-887a-5ddc-ae18-523dcab90daa",
        )

    def test_spdx_document_namespace_pinned(self):
        spdx = build_spdx(
            _analysed(self._SRC), timestamp="2026-01-01T00:00:00Z",
        )
        self.assertEqual(
            spdx["documentNamespace"],
            "https://capa-language.com/spdx/"
            "aa90f747-81b3-5561-9c4c-85d02c079a81",
        )

    def test_provenance_invocation_id_pinned(self):
        from capa.manifest import build_provenance
        att = build_provenance(
            self._SRC,
            started_on="2026-01-01T00:00:00Z",
            finished_on="2026-01-01T00:00:00Z",
        )
        self.assertEqual(
            att["predicate"]["runDetails"]["metadata"]["invocationId"],
            "a0497d00-9e75-5a80-bad6-69e19c60947c",
        )
        self.assertEqual(att["subject"][0]["name"], "<input>")


class TestMultiImplementor(unittest.TestCase):
    """When multiple structs implement one user-defined capability,
    the manifest must list all of them in sorted order so two runs
    on the same module agree byte-for-byte."""

    def test_implementors_sorted(self):
        # Declare three implementors out of alphabetical order in
        # source; manifest must sort them.
        src = (
            "capability Logger\n"
            "    fun log(self, msg: String) -> Bool\n"
            "type ZSink { stdio: Stdio }\n"
            "type ASink { stdio: Stdio }\n"
            "type MSink { stdio: Stdio }\n"
            "impl Logger for ZSink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
            "impl Logger for ASink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
            "impl Logger for MSink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
        )
        m = build_manifest(_analysed(src))
        ucs = m["user_defined_capabilities"]
        self.assertEqual(len(ucs), 1)
        self.assertEqual(ucs[0]["implementors"], ["ASink", "MSink", "ZSink"])

    def test_multiple_user_caps_each_with_implementors(self):
        src = (
            "capability Logger\n"
            "    fun log(self, m: String) -> Bool\n"
            "capability Mailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SinkA { stdio: Stdio }\n"
            "type SinkB { stdio: Stdio }\n"
            "type MailerX { net: Net }\n"
            "impl Logger for SinkA\n"
            "    fun log(self, m: String) -> Bool\n"
            "        return true\n"
            "impl Logger for SinkB\n"
            "    fun log(self, m: String) -> Bool\n"
            "        return true\n"
            "impl Mailer for MailerX\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
        )
        m = build_manifest(_analysed(src))
        ucs = {uc["name"]: uc for uc in m["user_defined_capabilities"]}
        self.assertEqual(set(ucs.keys()), {"Logger", "Mailer"})
        self.assertEqual(ucs["Logger"]["implementors"], ["SinkA", "SinkB"])
        self.assertEqual(ucs["Mailer"]["implementors"], ["MailerX"])


class TestFunctionRecordFields(unittest.TestCase):
    """Fields not exercised by test_attributes.py: is_pub, doc."""

    def test_is_pub_default_false(self):
        m = build_manifest(_analysed("fun private_fn()\n    return\n"))
        self.assertFalse(m["functions"][0]["is_pub"])

    def test_pub_keyword_sets_is_pub_true(self):
        m = build_manifest(_analysed("pub fun exposed()\n    return\n"))
        self.assertTrue(m["functions"][0]["is_pub"])

    def test_doc_comment_captured(self):
        m = build_manifest(
            _analysed(
                "/// A function that does nothing.\n"
                "fun documented()\n"
                "    return\n"
            ),
        )
        doc = m["functions"][0]["doc"]
        self.assertIsNotNone(doc)
        self.assertIn("does nothing", doc)


class TestExports(unittest.TestCase):
    """The ``capa.manifest`` __init__ surface; consumers import
    these names directly."""

    def test_public_surface_resolves(self):
        from capa.manifest import (
            SCHEMA_VERSION, CYCLONEDX_SPEC_VERSION, SPDX_SPEC_VERSION,
            CAPA_BUILD_TYPE, CAPA_BUILDER_ID, SLSA_PREDICATE_TYPE,
            build_manifest, build_cyclonedx, build_spdx,
            build_vex_document, build_vex_entries, build_provenance,
        )
        for c in (
            SCHEMA_VERSION, CYCLONEDX_SPEC_VERSION, SPDX_SPEC_VERSION,
            CAPA_BUILD_TYPE, CAPA_BUILDER_ID, SLSA_PREDICATE_TYPE,
        ):
            self.assertIsNotNone(c)
        for fn in (
            build_manifest, build_cyclonedx, build_spdx,
            build_vex_document, build_vex_entries, build_provenance,
        ):
            self.assertTrue(callable(fn))


from capa import capa_ast as A
from capa.manifest._strings import (
    _quote_string,
    _root_type_name,
    _stringify_expr,
    _stringify_expr_full,
    _ty_text,
)
from capa.tokens import Pos


_P = Pos(line=1, col=1, offset=0)


def _ident(name: str) -> A.Ident:
    return A.Ident(pos=_P, name=name)


def _int(n: int) -> A.IntLit:
    return A.IntLit(pos=_P, value=n)


class TestManifestStringHelpers(unittest.TestCase):
    """Direct unit coverage of the small AST-to-string helpers in
    ``capa.manifest._strings``. One method per Expr/TypeExpr branch,
    so coverage tracks every isinstance check in the cascade."""

    # -- _stringify_expr (the truncating wrapper) ----------------

    def test_stringify_expr_short_passes_through(self):
        self.assertEqual(_stringify_expr(_ident("abc")), "abc")

    def test_stringify_expr_long_is_truncated_with_ellipsis(self):
        long_name = "x" * 200
        out = _stringify_expr(_ident(long_name))
        self.assertEqual(len(out), 80)
        self.assertTrue(out.endswith("..."))
        self.assertEqual(out, "x" * 77 + "...")

    # -- _stringify_expr_full per node shape ---------------------

    def test_full_none_returns_empty(self):
        self.assertEqual(_stringify_expr_full(None), "")

    def test_full_ident(self):
        self.assertEqual(_stringify_expr_full(_ident("foo")), "foo")

    def test_full_int_lit(self):
        self.assertEqual(_stringify_expr_full(_int(42)), "42")

    def test_full_float_lit(self):
        self.assertEqual(
            _stringify_expr_full(A.FloatLit(pos=_P, value=1.5)),
            repr(1.5),
        )

    def test_full_string_lit_quoted(self):
        self.assertEqual(
            _stringify_expr_full(A.StringLit(pos=_P, value="hi")),
            '"hi"',
        )

    def test_full_interpolated_string(self):
        # parts: literal "a", expr Ident("x"), literal "b"
        node = A.InterpolatedString(pos=_P, parts=["a", _ident("x"), "b"])
        self.assertEqual(_stringify_expr_full(node), '"a${...}b"')

    def test_full_char_lit(self):
        self.assertEqual(
            _stringify_expr_full(A.CharLit(pos=_P, value="z")),
            "'z'",
        )

    def test_full_bool_lit_true(self):
        self.assertEqual(
            _stringify_expr_full(A.BoolLit(pos=_P, value=True)),
            "true",
        )

    def test_full_bool_lit_false(self):
        self.assertEqual(
            _stringify_expr_full(A.BoolLit(pos=_P, value=False)),
            "false",
        )

    def test_full_unit_lit(self):
        self.assertEqual(_stringify_expr_full(A.UnitLit(pos=_P)), "()")

    def test_full_binop(self):
        node = A.BinOp(pos=_P, op="+", left=_int(1), right=_int(2))
        self.assertEqual(_stringify_expr_full(node), "1 + 2")

    def test_full_unary_op_symbolic_no_space(self):
        node = A.UnaryOp(pos=_P, op="-", operand=_int(3))
        self.assertEqual(_stringify_expr_full(node), "-3")

    def test_full_unary_op_alpha_inserts_space(self):
        node = A.UnaryOp(pos=_P, op="not", operand=A.BoolLit(pos=_P, value=True))
        self.assertEqual(_stringify_expr_full(node), "not true")

    def test_full_call(self):
        node = A.Call(pos=_P, callee=_ident("f"), args=[_int(1), _int(2)])
        self.assertEqual(_stringify_expr_full(node), "f(1, 2)")

    def test_full_method_call(self):
        node = A.MethodCall(
            pos=_P, receiver=_ident("x"), method="bar", args=[_int(7)]
        )
        self.assertEqual(_stringify_expr_full(node), "x.bar(7)")

    def test_full_field_access(self):
        node = A.FieldAccess(pos=_P, receiver=_ident("rec"), field_name="f")
        self.assertEqual(_stringify_expr_full(node), "rec.f")

    def test_full_index(self):
        node = A.Index(pos=_P, receiver=_ident("a"), index=_int(0))
        self.assertEqual(_stringify_expr_full(node), "a[0]")

    def test_full_try(self):
        node = A.Try(pos=_P, expr=_ident("res"))
        self.assertEqual(_stringify_expr_full(node), "res?")

    def test_full_list_lit(self):
        node = A.ListLit(pos=_P, elements=[_int(1), _int(2), _int(3)])
        self.assertEqual(_stringify_expr_full(node), "[1, 2, 3]")

    def test_full_tuple_lit(self):
        node = A.TupleLit(pos=_P, elements=[_int(1), _ident("x")])
        self.assertEqual(_stringify_expr_full(node), "(1, x)")

    def test_full_struct_lit(self):
        node = A.StructLit(
            pos=_P,
            type_name="Point",
            fields=[("x", _int(1)), ("y", _int(2))],
        )
        self.assertEqual(
            _stringify_expr_full(node),
            "Point { x: 1, y: 2 }",
        )

    def test_full_range_expr_exclusive(self):
        node = A.RangeExpr(pos=_P, start=_int(0), end=_int(10), inclusive=False)
        self.assertEqual(_stringify_expr_full(node), "0..10")

    def test_full_range_expr_inclusive(self):
        node = A.RangeExpr(pos=_P, start=_int(0), end=_int(10), inclusive=True)
        self.assertEqual(_stringify_expr_full(node), "0..=10")

    def test_full_lambda_expr(self):
        node = A.LambdaExpr(pos=_P, params=[], body=_int(1))
        self.assertEqual(_stringify_expr_full(node), "fun(...) => ...")

    def test_full_if_expr(self):
        node = A.IfExpr(
            pos=_P,
            cond=A.BoolLit(pos=_P, value=True),
            then_expr=_int(1),
            else_expr=_int(2),
        )
        self.assertEqual(
            _stringify_expr_full(node),
            "if true then ... else ...",
        )

    def test_full_match_expr(self):
        node = A.MatchExpr(pos=_P, scrutinee=_ident("v"), arms=[])
        self.assertEqual(_stringify_expr_full(node), "match v { ... }")

    def test_full_unknown_node_falls_back_to_class_name(self):
        # AssignStmt is a Stmt, not an Expr; the cascade should miss
        # every isinstance check and hit the final fallback.
        stmt = A.AssignStmt(
            pos=_P, target=_ident("x"), op="=", value=_int(1),
        )
        self.assertEqual(_stringify_expr_full(stmt), "<AssignStmt>")

    # -- _quote_string -------------------------------------------

    def test_quote_string_empty(self):
        self.assertEqual(_quote_string(""), '""')

    def test_quote_string_simple_ascii(self):
        self.assertEqual(_quote_string("hello"), '"hello"')

    def test_quote_string_escapes_double_quote(self):
        self.assertEqual(_quote_string('say "hi"'), '"say \\"hi\\""')

    def test_quote_string_escapes_backslash(self):
        self.assertEqual(_quote_string("a\\b"), '"a\\\\b"')

    def test_quote_string_escapes_newline(self):
        self.assertEqual(_quote_string("a\nb"), '"a\\nb"')

    def test_quote_string_escapes_tab(self):
        self.assertEqual(_quote_string("a\tb"), '"a\\tb"')

    def test_quote_string_other_control_char_passes_through(self):
        # The function only special-cases \\, ", \n, \t. Other control
        # characters are kept verbatim inside the literal.
        self.assertEqual(_quote_string("a\x01b"), '"a\x01b"')

    def test_quote_string_backslash_n_literal_not_double_escaped(self):
        # Input is the two-char sequence backslash + 'n'. The backslash
        # is escaped first, so the result is \\n (four chars). The 'n'
        # is not interpreted as the newline-escape replacement.
        self.assertEqual(_quote_string("\\n"), '"\\\\n"')

    # -- _ty_text -------------------------------------------------

    def test_ty_text_none_is_unit_string(self):
        self.assertEqual(_ty_text(None), "()")

    def test_ty_text_bare_type_name(self):
        self.assertEqual(_ty_text(A.TypeName(pos=_P, name="Int")), "Int")

    def test_ty_text_generic_type_name(self):
        node = A.TypeName(
            pos=_P, name="List", args=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertEqual(_ty_text(node), "List<Int>")

    def test_ty_text_generic_type_name_two_args(self):
        node = A.TypeName(
            pos=_P,
            name="Result",
            args=[
                A.TypeName(pos=_P, name="Int"),
                A.TypeName(pos=_P, name="String"),
            ],
        )
        self.assertEqual(_ty_text(node), "Result<Int, String>")

    def test_ty_text_fun_type(self):
        node = A.FunType(
            pos=_P,
            param_types=[A.TypeName(pos=_P, name="Int")],
            return_type=A.TypeName(pos=_P, name="String"),
        )
        self.assertEqual(_ty_text(node), "Fun(Int) -> String")

    def test_ty_text_fun_type_no_params(self):
        node = A.FunType(
            pos=_P,
            param_types=[],
            return_type=A.UnitType(pos=_P),
        )
        self.assertEqual(_ty_text(node), "Fun() -> ()")

    def test_ty_text_tuple_type(self):
        node = A.TupleType(
            pos=_P,
            elements=[
                A.TypeName(pos=_P, name="Int"),
                A.TypeName(pos=_P, name="String"),
            ],
        )
        self.assertEqual(_ty_text(node), "(Int, String)")

    def test_ty_text_unit_type(self):
        self.assertEqual(_ty_text(A.UnitType(pos=_P)), "()")

    def test_ty_text_unknown_falls_back_to_class_name(self):
        # Pass a TypeExpr subclass the cascade does not handle. We do
        # not have one in the codebase today, so we synthesize a minimal
        # subclass to hit the final fallback line.
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class _Mystery(A.TypeExpr):
            pass

        self.assertEqual(_ty_text(_Mystery(pos=_P)), "<_Mystery>")

    # -- _root_type_name -----------------------------------------

    def test_root_type_name_none(self):
        self.assertIsNone(_root_type_name(None))

    def test_root_type_name_bare(self):
        self.assertEqual(
            _root_type_name(A.TypeName(pos=_P, name="Int")),
            "Int",
        )

    def test_root_type_name_generic_keeps_head(self):
        node = A.TypeName(
            pos=_P, name="List", args=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertEqual(_root_type_name(node), "List")

    def test_root_type_name_non_type_name_returns_none(self):
        self.assertIsNone(_root_type_name(A.UnitType(pos=_P)))
        tup = A.TupleType(
            pos=_P,
            elements=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertIsNone(_root_type_name(tup))


class TestMultiFileSourceDigest(unittest.TestCase):
    """Audit 2026-06-17: the provenance subject and the CDX
    ``serialNumber`` / SPDX ``documentNamespace`` seeds must cover
    EVERY linked module, not only the root. Pre-fix an attacker could
    rewrite an imported module (changing its capability surface) while
    the root stayed byte-identical and the attestation subject digest,
    CDX serial, and SPDX namespace stayed UNCHANGED -- a verifier
    accepted a program whose imports had been swapped."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_sbom_digest_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name: str, body: str) -> Path:
        p = self._tmp / name
        p.write_text(body, encoding="utf-8")
        return p

    _ROOT = (
        "import util\n"
        "fun main(stdio: Stdio)\n"
        '    stdio.println("hi")\n'
    )

    def _link(self, util_body: str):
        self._write("util.capa", util_body)
        root = self._write("root.capa", self._ROOT)
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        return root, linked

    def _artifacts(self, util_body: str):
        root, linked = self._link(util_body)
        source = root.read_text()
        fn = str(root)
        prov = build_provenance(
            source, filename=fn, sources=linked.sources,
            started_on="2020-01-01T00:00:00Z",
            finished_on="2020-01-01T00:00:00Z",
        )
        cdx = build_cyclonedx(
            linked.module, filename=fn, source=source,
            sources=linked.sources, timestamp="2020-01-01T00:00:00Z",
        )
        spdx = build_spdx(
            linked.module, filename=fn, source=source,
            sources=linked.sources, timestamp="2020-01-01T00:00:00Z",
        )
        return prov, cdx, spdx

    def test_rewriting_imported_module_changes_every_digest(self):
        # Two programs with a BYTE-IDENTICAL root but a differing
        # imported module. Every source-derived identifier must differ.
        prov_a, cdx_a, spdx_a = self._artifacts(
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        prov_b, cdx_b, spdx_b = self._artifacts(
            "pub fun helper(net: Net) -> Int\n"
            "    return 0\n"
        )
        self.assertNotEqual(
            prov_a["subject"], prov_b["subject"],
            "rewriting the import left the provenance subject unchanged",
        )
        self.assertNotEqual(
            prov_a["predicate"]["runDetails"]["metadata"]["invocationId"],
            prov_b["predicate"]["runDetails"]["metadata"]["invocationId"],
        )
        self.assertNotEqual(cdx_a["serialNumber"], cdx_b["serialNumber"])
        self.assertNotEqual(
            spdx_a["documentNamespace"], spdx_b["documentNamespace"],
        )

    def test_provenance_carries_one_subject_per_module(self):
        prov, _, _ = self._artifacts(
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        names = sorted(s["name"] for s in prov["subject"])
        self.assertEqual(names, ["root.capa", "util.capa"])
        for s in prov["subject"]:
            self.assertEqual(len(s["digest"]["sha256"]), 64)

    def test_multi_file_build_is_reproducible(self):
        # Two builds of the SAME multi-file input must be byte-identical
        # (deterministic ordering; no machine state leaks).
        util = (
            "pub fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        prov_a, cdx_a, spdx_a = self._artifacts(util)
        prov_b, cdx_b, spdx_b = self._artifacts(util)
        self.assertEqual(prov_a, prov_b)
        self.assertEqual(cdx_a["serialNumber"], cdx_b["serialNumber"])
        self.assertEqual(
            spdx_a["documentNamespace"], spdx_b["documentNamespace"],
        )

    def test_single_file_still_one_subject_and_works(self):
        # No sources map: the historical single-subject provenance and
        # single-source seed are preserved exactly.
        src = "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        prov = build_provenance(
            src, filename="main.capa",
            started_on="2020-01-01T00:00:00Z",
            finished_on="2020-01-01T00:00:00Z",
        )
        self.assertEqual(len(prov["subject"]), 1)
        self.assertEqual(prov["subject"][0]["name"], "main.capa")

    def test_single_file_cli_path_keeps_historical_identifiers(self):
        # Audit 2026-06-17: the CLI ALWAYS forwards ``linked.sources``.
        # For an import-free program that map has one entry (the root),
        # which must NOT trip the multi-file ``<display>\n<sha256>`` join:
        # doing so changed the serialNumber / documentNamespace /
        # invocationId of every already-signed single-file program. The
        # historical seed is ``<display>:sha256(source)``; verify the
        # one-entry-root path reproduces it byte-for-byte and matches the
        # no-sources fallback. The existing single-subject test missed
        # this because it called build_provenance WITHOUT ``sources``.
        import hashlib
        root = self._write(
            "solo.capa",
            "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n",
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        # An import-free program links exactly itself.
        self.assertEqual(len(linked.sources), 1)
        source = root.read_text()
        fn = str(root)

        # CLI path: sources = one-entry root map.
        prov_cli = build_provenance(
            source, filename=fn, sources=linked.sources,
            started_on="2020-01-01T00:00:00Z",
            finished_on="2020-01-01T00:00:00Z",
        )
        cdx_cli = build_cyclonedx(
            linked.module, filename=fn, source=source,
            sources=linked.sources, timestamp="2020-01-01T00:00:00Z",
        )
        spdx_cli = build_spdx(
            linked.module, filename=fn, source=source,
            sources=linked.sources, timestamp="2020-01-01T00:00:00Z",
        )

        # Historical path: no sources map at all.
        prov_hist = build_provenance(
            source, filename=fn,
            started_on="2020-01-01T00:00:00Z",
            finished_on="2020-01-01T00:00:00Z",
        )
        cdx_hist = build_cyclonedx(
            linked.module, filename=fn, source=source,
            timestamp="2020-01-01T00:00:00Z",
        )
        spdx_hist = build_spdx(
            linked.module, filename=fn, source=source,
            timestamp="2020-01-01T00:00:00Z",
        )

        # Single subject, digested as the bare sha256 of the source -
        # exactly the pre-2026-06-17 value.
        self.assertEqual(len(prov_cli["subject"]), 1)
        bare = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self.assertEqual(prov_cli["subject"][0]["digest"]["sha256"], bare)

        # CLI path identifiers are IDENTICAL to the historical ones.
        self.assertEqual(
            prov_cli["predicate"]["runDetails"]["metadata"]["invocationId"],
            prov_hist["predicate"]["runDetails"]["metadata"]["invocationId"],
        )
        self.assertEqual(prov_cli["subject"], prov_hist["subject"])
        self.assertEqual(cdx_cli["serialNumber"], cdx_hist["serialNumber"])
        self.assertEqual(
            spdx_cli["documentNamespace"], spdx_hist["documentNamespace"],
        )


class TestSelImportDemangle(unittest.TestCase):
    """Audit 2026-06-17: a pub capability NOT selected by a selective
    import ``import foo (X)`` is renamed ``_capa_m{N}__sel__<Name>`` by
    the loader. The manifest demangle must strip the ``sel__`` infix too
    so the SBOM shows the source-level ``Name`` (not ``sel__Name``)."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_sel_demangle_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name: str, body: str) -> Path:
        p = self._tmp / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_unselected_cap_demangles_without_sel_prefix(self):
        self._write(
            "caps.capa",
            "pub capability Logger\n"
            "    fun log(self, msg: String)\n"
            "pub capability Pinger\n"
            "    fun ping(self)\n",
        )
        # Select only Pinger; Logger becomes _capa_m{N}__sel__Logger.
        root = self._write(
            "root.capa",
            "import caps (Pinger)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n',
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        m = build_manifest(linked.module, filename=str(root))
        cap_names = {uc["name"] for uc in m["user_defined_capabilities"]}
        self.assertIn("Logger", cap_names)
        self.assertNotIn("sel__Logger", cap_names)
        leak = re.compile(r"sel__")
        for uc in m["user_defined_capabilities"]:
            self.assertIsNone(leak.search(uc["name"]))


if __name__ == "__main__":
    unittest.main()
