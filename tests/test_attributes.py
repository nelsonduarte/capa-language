"""Tests for function attributes and the --manifest builder.

Three blocks:

  - parsing: ``@name(key: "value", ...)`` syntax accepted on top-level
    funs and on impl methods, rejected on other items.
  - semantic validation: the analyzer accepts the v1 catalogue of
    attribute names (security, deprecated, audited) and rejects
    unknown names, unknown keys, and duplicate attributes.
  - manifest emission: ``build_manifest`` produces the expected
    JSON-serialisable shape for a representative sample of programs.
"""

import unittest

from capa import Lexer, Parser, ParserError, analyze
from capa import ast as A
from capa.manifest import build_manifest, build_cyclonedx, build_spdx


def parse(source: str) -> A.Module:
    tokens = Lexer(source).lex()
    return Parser(tokens, source=source).parse_module()


def check_errors(source: str) -> list[str]:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return [e.message for e in analyze(module, source=source).errors]


def manifest_of(source: str, filename: str = "<test>") -> dict:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    # We do not require analysis to pass for the manifest tests, the
    # builder is robust to ASTs that have only been parsed, and we
    # want to inspect manifests for programs that the discipline
    # legitimately rejects (e.g., unused capability params).
    return build_manifest(module, filename=filename)


def cyclonedx_of(source: str, filename: str = "test.capa", **kw) -> dict:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return build_cyclonedx(
        module,
        filename=filename,
        timestamp="2026-05-12T00:00:00Z",
        **kw,
    )


def props_dict(props: list[dict]) -> dict:
    """Flatten a properties list into a name -> [values] mapping."""
    out: dict[str, list[str]] = {}
    for p in props:
        out.setdefault(p["name"], []).append(p["value"])
    return out


# =============================================================
# Parsing
# =============================================================

class TestAttributeParsing(unittest.TestCase):
    def test_single_attribute(self):
        m = parse(
            '@security(cve: "CVE-2024-1")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        fn = m.items[0]
        self.assertIsInstance(fn, A.FunDecl)
        self.assertEqual(len(fn.attributes), 1)
        self.assertEqual(fn.attributes[0].name, "security")
        self.assertEqual(fn.attributes[0].args, [("cve", "CVE-2024-1")])

    def test_stacked_attributes(self):
        m = parse(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        fn = m.items[0]
        self.assertEqual(len(fn.attributes), 2)
        self.assertEqual(fn.attributes[0].name, "security")
        self.assertEqual(fn.attributes[1].name, "audited")
        self.assertEqual(
            dict(fn.attributes[0].args),
            {"cve": "CVE-2024-1", "severity": "high"},
        )

    def test_trailing_comma_accepted(self):
        m = parse(
            '@security(cve: "X", severity: "low",)\n'
            'fun f()\n    return\n'
        )
        fn = m.items[0]
        self.assertEqual(len(fn.attributes[0].args), 2)

    def test_empty_args_accepted_by_parser(self):
        # Parser is permissive, analyzer may still complain about
        # certain attributes that conceptually need arguments.
        m = parse('@security()\nfun f()\n    return\n')
        fn = m.items[0]
        self.assertEqual(fn.attributes[0].args, [])

    def test_attribute_on_impl_method(self):
        m = parse(
            'type Foo {}\n'
            'impl Foo\n'
            '    @audited(date: "2026-05-11")\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        impl = m.items[1]
        self.assertIsInstance(impl, A.ImplBlock)
        method = impl.methods[0]
        self.assertEqual(len(method.attributes), 1)
        self.assertEqual(method.attributes[0].name, "audited")

    def test_attribute_on_const_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: "X")\n'
                'const PI: Float = 3.14\n'
            )
        self.assertIn("const", cm.exception.message)

    def test_attribute_on_type_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: "X")\n'
                'type Foo {}\n'
            )
        self.assertIn("type", cm.exception.message)

    def test_at_without_name_rejected(self):
        with self.assertRaises(ParserError):
            parse('@\nfun f()\n    return\n')

    def test_non_string_value_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: 42)\n'
                'fun f()\n    return\n'
            )
        self.assertIn("string", cm.exception.message)


# =============================================================
# Analyzer validation
# =============================================================

class TestAttributeAnalysis(unittest.TestCase):
    def test_known_attributes_accepted(self):
        errs = check_errors(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@deprecated(reason: "x", since: "0.3.0")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        self.assertEqual(errs, [], f"unexpected analyzer errors: {errs}")

    def test_unknown_attribute_rejected(self):
        errs = check_errors(
            '@bogus(x: "y")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(any("unknown attribute" in e for e in errs), errs)
        self.assertTrue(any("bogus" in e for e in errs), errs)

    def test_unknown_key_rejected(self):
        errs = check_errors(
            '@security(no_such_key: "x")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(any("unknown key" in e for e in errs), errs)
        self.assertTrue(any("no_such_key" in e for e in errs), errs)

    def test_duplicate_attribute_rejected(self):
        errs = check_errors(
            '@security(cve: "A")\n'
            '@security(cve: "B")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(
            any("appears more than once" in e for e in errs),
            errs,
        )

    def test_duplicate_key_within_attribute_rejected(self):
        errs = check_errors(
            '@security(cve: "A", cve: "B")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(
            any("appears more than once" in e for e in errs),
            errs,
        )

    def test_attribute_on_method_validated(self):
        errs = check_errors(
            'type Foo {}\n'
            'impl Foo\n'
            '    @nonsense(x: "y")\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        self.assertTrue(
            any("unknown attribute" in e and "nonsense" in e for e in errs),
            errs,
        )


# =============================================================
# Manifest emission
# =============================================================

class TestManifest(unittest.TestCase):
    def test_hello_world(self):
        m = manifest_of(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        self.assertEqual(m["schema_version"], 1)
        self.assertEqual(m["summary"]["total_functions"], 1)
        self.assertEqual(m["summary"]["functions_with_capabilities"], 1)
        self.assertEqual(m["summary"]["functions_with_attributes"], 0)
        self.assertEqual(m["summary"]["functions_crossing_unsafe"], 0)

        fn = m["functions"][0]
        self.assertEqual(fn["name"], "main")
        self.assertEqual(fn["declared_capabilities"], ["Stdio"])
        self.assertFalse(fn["has_unsafe"])

        param = fn["params"][0]
        self.assertEqual(param["name"], "stdio")
        self.assertEqual(param["type"], "Stdio")
        self.assertTrue(param["is_capability"])

    def test_unsafe_boundary_detected(self):
        m = manifest_of(
            'fun crosses(u: Unsafe)\n'
            '    return\n'
        )
        fn = m["functions"][0]
        self.assertTrue(fn["has_unsafe"])
        self.assertIn("Unsafe", fn["declared_capabilities"])
        self.assertEqual(m["summary"]["functions_crossing_unsafe"], 1)

    def test_user_defined_capability_with_implementor(self):
        m = manifest_of(
            'capability SendEmail\n'
            '    fun send(self, to: String) -> Bool\n'
            'type SmtpMailer { net: Net }\n'
            'impl SendEmail for SmtpMailer\n'
            '    fun send(self, to: String) -> Bool\n'
            '        return true\n'
        )
        ucs = m["user_defined_capabilities"]
        self.assertEqual(len(ucs), 1)
        self.assertEqual(ucs[0]["name"], "SendEmail")
        self.assertEqual(ucs[0]["methods"], ["send"])
        self.assertEqual(ucs[0]["implementors"], ["SmtpMailer"])

    def test_impl_method_has_container(self):
        m = manifest_of(
            'type Foo {}\n'
            'impl Foo\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        method = m["functions"][0]
        self.assertEqual(method["name"], "bar")
        self.assertEqual(method["container"], "Foo")

    def test_attributes_in_manifest(self):
        m = manifest_of(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun verify(stdio: Stdio) -> Bool\n'
            '    return true\n'
        )
        fn = m["functions"][0]
        attrs = fn["attributes"]
        names = [a["name"] for a in attrs]
        self.assertEqual(sorted(names), ["audited", "security"])
        sec = next(a for a in attrs if a["name"] == "security")
        self.assertEqual(sec["args"]["cve"], "CVE-2024-1")
        self.assertEqual(sec["args"]["severity"], "high")
        self.assertEqual(m["summary"]["functions_with_attributes"], 1)

    def test_pure_function_no_caps(self):
        m = manifest_of(
            'fun pure_fn(x: Int) -> Int\n'
            '    return x * 2\n'
        )
        fn = m["functions"][0]
        self.assertEqual(fn["declared_capabilities"], [])
        self.assertFalse(fn["has_unsafe"])
        self.assertEqual(m["summary"]["functions_with_capabilities"], 0)


# =============================================================
# CycloneDX 1.5 wrapper
# =============================================================

class TestCycloneDX(unittest.TestCase):
    def test_top_level_envelope(self):
        sbom = cyclonedx_of(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(sbom["version"], 1)
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(sbom["metadata"]["timestamp"], "2026-05-12T00:00:00Z")

    def test_tool_metadata_records_capa(self):
        sbom = cyclonedx_of('fun f()\n    return\n')
        tools = sbom["metadata"]["tools"]["components"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "capa")

    def test_program_component_present(self):
        sbom = cyclonedx_of('fun f()\n    return\n', filename="demo.capa")
        program = sbom["metadata"]["component"]
        self.assertEqual(program["name"], "demo.capa")
        self.assertEqual(program["type"], "application")
        self.assertEqual(program["bom-ref"], "capa:program:demo.capa")

    def test_function_becomes_component(self):
        sbom = cyclonedx_of(
            'fun fetch_user(net: Net) -> Bool\n'
            '    return net.allows("api.example.com")\n',
            filename="api.capa",
        )
        # 1 function component, 0 user caps
        components = sbom["components"]
        self.assertEqual(len(components), 1)
        fn = components[0]
        self.assertEqual(fn["name"], "fetch_user")
        self.assertEqual(fn["type"], "library")
        self.assertEqual(fn["bom-ref"], "capa:fn:api.capa:fetch_user")

    def test_function_properties_include_capabilities(self):
        sbom = cyclonedx_of(
            'fun fetch_user(net: Net) -> Bool\n'
            '    return net.allows("api.example.com")\n',
        )
        fn = sbom["components"][0]
        props = props_dict(fn["properties"])
        self.assertEqual(props["capa:kind"], ["function"])
        self.assertEqual(props["capa:has_unsafe"], ["false"])
        self.assertEqual(props["capa:declared_capability"], ["Net"])

    def test_security_attribute_flattened(self):
        sbom = cyclonedx_of(
            '@security(cve: "CVE-2024-99", severity: "high")\n'
            'fun verify(token: String) -> Bool\n'
            '    return true\n'
        )
        fn = sbom["components"][0]
        props = props_dict(fn["properties"])
        self.assertEqual(props["capa:attribute:security:cve"], ["CVE-2024-99"])
        self.assertEqual(props["capa:attribute:security:severity"], ["high"])

    def test_user_defined_capability_becomes_component(self):
        sbom = cyclonedx_of(
            'capability SendEmail\n'
            '    fun send(self, to: String) -> Bool\n'
            'type SmtpMailer { net: Net }\n'
            'impl SendEmail for SmtpMailer\n'
            '    fun send(self, to: String) -> Bool\n'
            '        return true\n'
        )
        # The user-cap shows up as its own component, plus the impl method.
        names = [c["name"] for c in sbom["components"]]
        self.assertIn("SendEmail", names)
        # The impl method has the qualified container::method name.
        self.assertIn("SmtpMailer::send", names)

        send_email = next(
            c for c in sbom["components"] if c["name"] == "SendEmail"
        )
        props = props_dict(send_email["properties"])
        self.assertEqual(props["capa:kind"], ["capability"])
        self.assertEqual(props["capa:capability:method"], ["send"])
        self.assertEqual(props["capa:capability:implementor"], ["SmtpMailer"])

    def test_function_depending_on_user_cap_has_dependency_edge(self):
        sbom = cyclonedx_of(
            'capability SendEmail\n'
            '    fun send(self, to: String) -> Bool\n'
            'fun welcome(mailer: SendEmail, to: String) -> Bool\n'
            '    return mailer.send(to)\n',
            filename="email.capa",
        )
        # Find the dependency edge for the welcome function.
        welcome_ref = "capa:fn:email.capa:welcome"
        deps = [d for d in sbom["dependencies"] if d["ref"] == welcome_ref]
        self.assertEqual(len(deps), 1)
        cap_ref = "capa:cap:email.capa:SendEmail"
        self.assertIn(cap_ref, deps[0]["dependsOn"])

    def test_unsafe_boundary_property(self):
        sbom = cyclonedx_of(
            'fun crosses(_u: Unsafe)\n    return\n',
        )
        fn = sbom["components"][0]
        props = props_dict(fn["properties"])
        self.assertEqual(props["capa:has_unsafe"], ["true"])

    def test_summary_in_metadata(self):
        sbom = cyclonedx_of(
            'fun a(net: Net)\n    let _x = net.allows("x")\n'
            'fun b()\n    return\n'
        )
        props = props_dict(sbom["metadata"]["properties"])
        self.assertEqual(props["capa:summary:total_functions"], ["2"])
        self.assertEqual(props["capa:summary:functions_with_capabilities"], ["1"])

    def test_serial_number_is_deterministic_for_same_filename(self):
        a = cyclonedx_of('fun a()\n    return\n', filename="same.capa")
        b = cyclonedx_of('fun b()\n    return\n', filename="same.capa")
        # Different sources, same filename -> same UUID (intentional;
        # for SBOM diffability across releases).
        self.assertEqual(a["serialNumber"], b["serialNumber"])

    def test_serial_number_differs_across_filenames(self):
        a = cyclonedx_of('fun a()\n    return\n', filename="one.capa")
        b = cyclonedx_of('fun a()\n    return\n', filename="two.capa")
        self.assertNotEqual(a["serialNumber"], b["serialNumber"])

    def test_function_to_function_call_becomes_dependency_edge(self):
        sbom = cyclonedx_of(
            'fun helper(x: Int) -> Int\n'
            '    return x * 2\n'
            'fun main()\n'
            '    let n = helper(21)\n',
            filename="demo.capa",
        )
        # main depends on helper because it calls it
        main_dep = next(
            (d for d in sbom["dependencies"]
             if d["ref"] == "capa:fn:demo.capa:main"),
            None,
        )
        self.assertIsNotNone(main_dep, "expected a dependsOn entry for main")
        self.assertIn("capa:fn:demo.capa:helper", main_dep["dependsOn"])

    def test_method_calls_do_not_create_dependency_edge_v1(self):
        # Method calls are not resolved to specific impls in v1; the
        # manifest records them in calls[] but does not produce a
        # CycloneDX edge for them. This is a deliberate v1 limit;
        # data-flow tracking will close it later.
        sbom = cyclonedx_of(
            'type Foo {}\n'
            'impl Foo\n'
            '    fun bar(self) -> Int\n'
            '        return 1\n'
            'fun caller(f: Foo)\n'
            '    let n = f.bar()\n'
        )
        caller_dep = next(
            (d for d in sbom["dependencies"]
             if d["ref"].endswith(":caller")),
            None,
        )
        # caller should have no dependsOn (no declared user-caps,
        # method call is not edge-promoted in v1).
        self.assertIsNone(caller_dep)


# =============================================================
# Call-site extraction in the manifest
# =============================================================

class TestCallExtraction(unittest.TestCase):
    def _calls_of(self, source: str, fn_name: str = "main") -> list:
        m = manifest_of(source)
        fn = next(f for f in m["functions"] if f["name"] == fn_name)
        return fn["calls"]

    def test_plain_function_call_recorded(self):
        calls = self._calls_of(
            'fun add(a: Int, b: Int) -> Int\n'
            '    return a + b\n'
            'fun main()\n'
            '    let n = add(1, 2)\n'
        )
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertEqual(c["kind"], "fn")
        self.assertEqual(c["callee"], "add")
        self.assertEqual(c["args"], ["1", "2"])

    def test_method_call_recorded_with_receiver_method_callee(self):
        calls = self._calls_of(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertEqual(c["kind"], "method")
        self.assertEqual(c["callee"], "stdio.println")
        self.assertEqual(c["args"], ['"hi"'])

    def test_attenuation_visible_in_call_record(self):
        # The whole point of this feature: an auditor reading the
        # manifest sees the actual restrict_to call before the
        # downstream function gets the cap.
        calls = self._calls_of(
            'fun fetch_user(net: Net) -> Bool\n'
            '    return net.allows("x")\n'
            'fun main(net: Net)\n'
            '    let api = net.restrict_to("api.example.com")\n'
            '    let ok = fetch_user(api)\n'
        )
        callees = [c["callee"] for c in calls]
        self.assertIn("net.restrict_to", callees)
        self.assertIn("fetch_user", callees)
        restrict_call = next(c for c in calls if c["callee"] == "net.restrict_to")
        self.assertEqual(restrict_call["args"], ['"api.example.com"'])

    def test_nested_calls_recorded(self):
        # f(g(x)), both f and g show up in the call list.
        calls = self._calls_of(
            'fun g(x: Int) -> Int\n    return x + 1\n'
            'fun f(x: Int) -> Int\n    return x * 2\n'
            'fun main()\n    let n = f(g(3))\n'
        )
        callees = [c["callee"] for c in calls]
        self.assertIn("f", callees)
        self.assertIn("g", callees)

    def test_position_recorded(self):
        calls = self._calls_of(
            'fun main(stdio: Stdio)\n'
            '    let x = 1\n'
            '    stdio.println("hi")\n'
        )
        c = calls[0]
        # Line 3, columns are 1-indexed and point at the receiver.
        line = int(c["pos"].split(":")[0])
        self.assertEqual(line, 3)

    def test_call_inside_branch_captured(self):
        calls = self._calls_of(
            'fun helper()\n    return\n'
            'fun main()\n'
            '    if true\n'
            '        helper()\n'
        )
        callees = [c["callee"] for c in calls]
        self.assertIn("helper", callees)

    def test_call_inside_match_arm_captured(self):
        calls = self._calls_of(
            'fun ok_branch()\n    return\n'
            'fun err_branch()\n    return\n'
            'fun main()\n'
            '    let x: Option<Int> = Some(1)\n'
            '    match x\n'
            '        Some(_) -> ok_branch()\n'
            '        None    -> err_branch()\n'
        )
        callees = [c["callee"] for c in calls]
        self.assertIn("ok_branch", callees)
        self.assertIn("err_branch", callees)

    def test_pure_function_has_empty_calls(self):
        calls = self._calls_of(
            'fun main(x: Int) -> Int\n'
            '    return x * 2\n'
        )
        self.assertEqual(calls, [])

    def test_long_arg_truncated_with_ellipsis(self):
        # An argument longer than the max-arg-repr ceiling is
        # truncated in the manifest so the JSON stays readable.
        long_str = "x" * 200
        calls = self._calls_of(
            f'fun main(stdio: Stdio)\n'
            f'    stdio.println("{long_str}")\n'
        )
        arg = calls[0]["args"][0]
        self.assertTrue(arg.endswith("..."), f"arg was: {arg!r}")


# =============================================================
# SPDX 2.3 wrapper
# =============================================================

def spdx_of(source: str, filename: str = "test.capa", **kw) -> dict:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return build_spdx(
        module,
        filename=filename,
        timestamp="2026-05-12T00:00:00Z",
        **kw,
    )


def _annot_comments(pkg: dict) -> list[str]:
    return [a["comment"] for a in pkg.get("annotations", [])]


def _pkg_by_name(spdx: dict, name: str) -> dict:
    for pkg in spdx["packages"]:
        if pkg["name"] == name:
            return pkg
    raise AssertionError(f"no SPDX package named {name!r}")


class TestSPDX(unittest.TestCase):
    def test_top_level_envelope(self):
        spdx = spdx_of(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx["dataLicense"], "CC0-1.0")
        self.assertEqual(spdx["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertEqual(spdx["creationInfo"]["created"], "2026-05-12T00:00:00Z")
        self.assertTrue(
            spdx["documentNamespace"].startswith("https://capa-lang.org/spdx/"),
            spdx["documentNamespace"],
        )

    def test_creator_records_capa_tool(self):
        spdx = spdx_of('fun f()\n    return\n')
        creators = spdx["creationInfo"]["creators"]
        self.assertEqual(len(creators), 1)
        self.assertTrue(creators[0].startswith("Tool: capa-"), creators[0])

    def test_program_package_described(self):
        spdx = spdx_of('fun f()\n    return\n', filename="demo.capa")
        pkg = _pkg_by_name(spdx, "demo.capa")
        self.assertEqual(pkg["downloadLocation"], "NOASSERTION")
        self.assertFalse(pkg["filesAnalyzed"])
        describes = next(
            r for r in spdx["relationships"]
            if r["relationshipType"] == "DESCRIBES"
        )
        self.assertEqual(describes["relatedSpdxElement"], pkg["SPDXID"])

    def test_function_becomes_package(self):
        spdx = spdx_of(
            'fun fetch_user(net: Net) -> Bool\n'
            '    return net.allows("api.example.com")\n',
            filename="api.capa",
        )
        pkg = _pkg_by_name(spdx, "fetch_user")
        self.assertEqual(pkg["downloadLocation"], "NOASSERTION")
        self.assertFalse(pkg["filesAnalyzed"])
        self.assertTrue(pkg["SPDXID"].startswith("SPDXRef-Fn-"), pkg["SPDXID"])

    def test_function_annotations_include_capabilities(self):
        spdx = spdx_of(
            'fun fetch_user(net: Net) -> Bool\n'
            '    return net.allows("api.example.com")\n',
        )
        pkg = _pkg_by_name(spdx, "fetch_user")
        comments = _annot_comments(pkg)
        self.assertIn("capa:kind=function", comments)
        self.assertIn("capa:declared_capability=Net", comments)
        self.assertIn("capa:has_unsafe=false", comments)

    def test_program_contains_function_relationship(self):
        spdx = spdx_of(
            'fun helper()\n    return\n',
            filename="demo.capa",
        )
        helper_pkg = _pkg_by_name(spdx, "helper")
        program_pkg = _pkg_by_name(spdx, "demo.capa")
        edge = next(
            (r for r in spdx["relationships"]
             if r["spdxElementId"] == program_pkg["SPDXID"]
             and r["relationshipType"] == "CONTAINS"
             and r["relatedSpdxElement"] == helper_pkg["SPDXID"]),
            None,
        )
        self.assertIsNotNone(edge, "expected CONTAINS edge from program to helper")

    def test_function_to_function_call_becomes_depends_on(self):
        spdx = spdx_of(
            'fun helper(x: Int) -> Int\n'
            '    return x * 2\n'
            'fun main()\n'
            '    let n = helper(21)\n',
        )
        main_pkg = _pkg_by_name(spdx, "main")
        helper_pkg = _pkg_by_name(spdx, "helper")
        edge = next(
            (r for r in spdx["relationships"]
             if r["spdxElementId"] == main_pkg["SPDXID"]
             and r["relationshipType"] == "DEPENDS_ON"
             and r["relatedSpdxElement"] == helper_pkg["SPDXID"]),
            None,
        )
        self.assertIsNotNone(edge, "expected DEPENDS_ON edge from main to helper")

    def test_namespace_deterministic_per_filename(self):
        # Same filename -> same documentNamespace across runs, which is
        # what the SPDX-diff workflow depends on.
        a = spdx_of('fun f()\n    return\n', filename="x.capa")
        b = spdx_of('fun g()\n    return\n', filename="x.capa")
        self.assertEqual(a["documentNamespace"], b["documentNamespace"])

    def test_namespace_differs_per_filename(self):
        a = spdx_of('fun f()\n    return\n', filename="one.capa")
        b = spdx_of('fun f()\n    return\n', filename="two.capa")
        self.assertNotEqual(a["documentNamespace"], b["documentNamespace"])

    def test_spdxids_are_syntactically_valid(self):
        # SPDXRef-[a-zA-Z0-9.-]+ per the spec. Function names with
        # colons or slashes must be sanitised; this test enforces it.
        import re
        spdx = spdx_of(
            'type Foo {}\n'
            'impl Foo\n'
            '    fun bar(self) -> Int\n'
            '        return 1\n',
            filename="weird::name.capa",
        )
        pattern = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")
        for pkg in spdx["packages"]:
            self.assertTrue(
                pattern.match(pkg["SPDXID"]),
                f"invalid SPDXID: {pkg['SPDXID']!r}",
            )

    def test_user_defined_capability_becomes_package(self):
        spdx = spdx_of(
            'capability SendEmail\n'
            '    fun send(self, to: String) -> Bool\n'
            'type SmtpMailer {}\n'
            'impl SendEmail for SmtpMailer\n'
            '    fun send(self, to: String) -> Bool\n'
            '        return true\n',
            filename="mailer.capa",
        )
        pkg = _pkg_by_name(spdx, "SendEmail")
        comments = _annot_comments(pkg)
        self.assertIn("capa:kind=capability", comments)
        self.assertIn("capa:capability:method=send", comments)
        self.assertIn("capa:capability:implementor=SmtpMailer", comments)


if __name__ == "__main__":
    unittest.main()
