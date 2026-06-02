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
from capa.manifest import SCHEMA_VERSION, build_cyclonedx, build_manifest, build_spdx


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
        "functions",
        "summary",
    }

    _SUMMARY_KEYS = {
        "total_functions",
        "functions_with_capabilities",
        "functions_with_attributes",
        "functions_crossing_unsafe",
        "declassification_sites",
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

    def test_user_cap_unsafe_in_impl_propagates_has_unsafe(self):
        # A user-cap whose impl holds Unsafe makes any function
        # taking the user-cap reach Unsafe; ``has_unsafe`` flips
        # to True and exclusion is empty (Unsafe is the
        # universal escape hatch).
        m = self._build(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { u: Unsafe }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
            "fun use_it(c: Client) -> Int\n"
            "    return c.do_it()\n"
        )
        use = self._find(m, "use_it")
        self.assertIn("Unsafe", use["transitively_reachable_capabilities"])
        self.assertTrue(use["has_unsafe"])
        self.assertEqual(use["provably_excluded_capabilities"], [])

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


if __name__ == "__main__":
    unittest.main()
