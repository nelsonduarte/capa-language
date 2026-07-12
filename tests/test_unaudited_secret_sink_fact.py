"""The un-audited secret->sink fact (feature #6, B1).

Capa's secret-to-public-sink information-flow check is WARN-ONLY by
default (a hard error only under ``@strict_ifc``). B1 materializes that
warn-tier "an un-audited @secret value reaches an egress sink" fact as a
first-class per-function record, carried on ``AnalysisResult`` and emitted
per function in the manifest, so ``no-secret-egress`` can gate on it.

These tests pin the RECORDING and EMISSION layers (the policy-level
behavior is covered in ``test_policy_compliance``). They assert only what
is OBSERVED / RECORDED; they do NOT change any warn-or-error decision.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa.manifest import build_manifest


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _sinks(module, result):
    """The manifest's per-function ``unaudited_secret_sinks``, as
    ``{function name: [(capability, pos), ...]}``."""
    man = build_manifest(
        module, expr_labels=result.expr_labels,
        unaudited_secret_sinks=result.unaudited_secret_sinks,
    )
    return {
        f["name"]: [(s["capability"], s["pos"]) for s in f["unaudited_secret_sinks"]]
        for f in man["functions"]
    }


class TestAnalyzerRecords(unittest.TestCase):
    def _one(self, src):
        module = _parse(src)
        result = analyze(module, source=src)
        self.assertTrue(result.ok, [e.message for e in result.errors])
        return module, result

    def test_intra_net_sink_recorded(self):
        module, result = self._one(
            "pub fun exfil(token: @secret String, net: Net) -> Unit\n"
            "    net.post(\"u\", token)\n"
            "    return\n"
        )
        # Exactly one warn-tier flow, recorded under the enclosing function.
        self.assertEqual(len(result.unaudited_secret_sinks), 1)
        caps = [c for c, _pos in _sinks(module, result)["exfil"]]
        self.assertEqual(caps, ["Net"])

    def test_intra_stdio_sink_recorded_with_its_capability(self):
        module, result = self._one(
            "pub fun echo(token: @secret String, stdio: Stdio) -> Unit\n"
            "    stdio.println(token)\n"
            "    return\n"
        )
        self.assertEqual(
            [c for c, _ in _sinks(module, result)["echo"]], ["Stdio"],
        )

    def test_declassified_flow_is_not_recorded(self):
        # A declassified value is public and never trips the warn: no fact.
        module, result = self._one(
            "pub fun send(token: @secret String, stdio: Stdio) -> Unit\n"
            "    stdio.println(declassify(token, reason: \"ok\"))\n"
            "    return\n"
        )
        self.assertEqual(result.unaudited_secret_sinks, {})
        self.assertEqual(_sinks(module, result)["send"], [])

    def test_public_value_to_sink_is_not_recorded(self):
        module, result = self._one(
            "pub fun send(msg: String, net: Net) -> Unit\n"
            "    net.post(\"u\", msg)\n"
            "    return\n"
        )
        self.assertEqual(_sinks(module, result)["send"], [])

    def test_panic_secret_recorded_as_stdio(self):
        # panic writes to stderr, framed by the analyzer as a Stdio-like
        # public sink, so an un-audited secret in panic is tagged Stdio.
        module, result = self._one(
            "pub fun boom(token: @secret String) -> Unit\n"
            "    panic(token)\n"
            "    return\n"
        )
        self.assertEqual(
            [c for c, _ in _sinks(module, result)["boom"]], ["Stdio"],
        )

    def test_cross_function_panic_recorded_against_caller_as_stdio(self):
        # The secret is routed through a helper that only reaches a sink via
        # ``panic``; the fact is recorded against the CALLER, tagged Stdio
        # (panic writes to stderr). This closes a false negative where the
        # panic branch grew the sink-reaching set without attributing a cap,
        # leaving the caller's recorded leak caps empty.
        module, result = self._one(
            "fun h(s: String) -> Unit\n"
            "    panic(s)\n"
            "    return\n"
            "pub fun caller(token: @secret String) -> Unit\n"
            "    h(token)\n"
            "    return\n"
        )
        s = _sinks(module, result)
        self.assertEqual(s["h"], [])   # h's own param is public
        self.assertEqual([c for c, _ in s["caller"]], ["Stdio"])

    def test_transitive_panic_recorded_against_caller_as_stdio(self):
        # Two-hop version (caller -> h -> g -> panic): the Stdio attribution
        # must still reach the outermost caller.
        module, result = self._one(
            "fun g(x: String) -> Unit\n"
            "    panic(x)\n"
            "    return\n"
            "fun h(s: String) -> Unit\n"
            "    g(s)\n"
            "    return\n"
            "pub fun caller(token: @secret String) -> Unit\n"
            "    h(token)\n"
            "    return\n"
        )
        s = _sinks(module, result)
        self.assertEqual([c for c, _ in s["caller"]], ["Stdio"])

    def test_cross_function_panic_of_public_value_not_recorded(self):
        # A cross-function panic of a PUBLIC value records nothing: no
        # over-attribution when there is no secret to leak.
        module, result = self._one(
            "fun h(s: String) -> Unit\n"
            "    panic(s)\n"
            "    return\n"
            "pub fun caller(msg: String) -> Unit\n"
            "    h(msg)\n"
            "    return\n"
        )
        self.assertEqual(_sinks(module, result)["caller"], [])

    def test_cross_function_recorded_against_caller_with_callee_cap(self):
        # The secret is routed through a helper that sinks it to Net; the
        # fact is recorded against the CALLER, tagged with the callee's Net.
        module, result = self._one(
            "fun helper(s: String, net: Net) -> Unit\n"
            "    net.post(\"u\", s)\n"
            "    return\n"
            "pub fun caller(token: @secret String, net: Net) -> Unit\n"
            "    helper(token, net)\n"
            "    return\n"
        )
        s = _sinks(module, result)
        self.assertEqual(s["helper"], [])   # helper's own param is public
        self.assertEqual([c for c, _ in s["caller"]], ["Net"])

    def test_cross_function_per_parameter_cap_precision(self):
        # A callee whose parameters reach DIFFERENT sinks: ``a`` -> Net,
        # ``b`` -> Fs. A secret routed to the Net-param must be tagged ONLY
        # Net, never the sibling Fs-param's capability. This pins the
        # per-parameter attribution (the whole-callable union was a false
        # positive: it fabricated Fs on a secret that only reaches Net).
        module, result = self._one(
            "fun h(a: String, b: String, net: Net, fs: Fs) -> Unit\n"
            "    net.post(\"u\", a)\n"
            "    fs.write(\"p\", b)\n"
            "    return\n"
            "pub fun c(token: @secret String, pub2: String, "
            "net: Net, fs: Fs) -> Unit\n"
            "    h(token, pub2, net, fs)\n"
            "    return\n"
        )
        s = _sinks(module, result)
        self.assertEqual(s["h"], [])   # h's own params are public
        self.assertEqual([c for c, _ in s["c"]], ["Net"])

    def test_cross_function_per_parameter_cap_precision_symmetric(self):
        # Symmetric: routing the secret to the Fs-param of the same
        # two-sink callee tags ONLY Fs, never the Net-param's capability.
        module, result = self._one(
            "fun h(a: String, b: String, net: Net, fs: Fs) -> Unit\n"
            "    net.post(\"u\", a)\n"
            "    fs.write(\"p\", b)\n"
            "    return\n"
            "pub fun c(pub2: String, token: @secret String, "
            "net: Net, fs: Fs) -> Unit\n"
            "    h(pub2, token, net, fs)\n"
            "    return\n"
        )
        s = _sinks(module, result)
        self.assertEqual([c for c, _ in s["c"]], ["Fs"])

    def test_strict_flow_is_error_and_not_recorded(self):
        # Under @strict_ifc the same flow is a hard ERROR (no manifest), so
        # nothing is recorded as a warn-tier fact.
        module = _parse(
            "@strict_ifc()\n"
            "pub fun exfil(token: @secret String, net: Net) -> Unit\n"
            "    net.post(\"u\", token)\n"
            "    return\n"
        )
        result = analyze(module, source="")
        self.assertFalse(result.ok)
        self.assertEqual(result.unaudited_secret_sinks, {})

    def test_manifest_field_deterministic_and_pathless(self):
        module, result = self._one(
            "pub fun exfil(a: @secret String, net: Net) -> Unit\n"
            "    net.post(a, a)\n"
            "    return\n"
        )
        entries = _sinks(module, result)["exfil"]
        # Both sink argument positions of Net.post carry the secret; each is
        # its own evidence entry, sorted by (capability, pos), no path.
        self.assertTrue(all(c == "Net" for c, _ in entries))
        positions = [pos for _c, pos in entries]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue(all(":" in pos and "/" not in pos for pos in positions))


if __name__ == "__main__":
    unittest.main()
