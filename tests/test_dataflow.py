"""Tests for per-call data-flow tracking.

The manifest's call records carry a parallel ``args_flow`` field
where each entry is either ``None`` (no tracking info for that
argument) or ``{"name": str, "attenuations": [...]}`` summarising
the chain of ``.restrict_to*`` calls applied to the binding that
produced the argument.

v1 of the tracker is intentionally syntactic: only top-level
``LetStmt``s with restrict-chain RHSs are recorded, and the walk
does not honour lexical scope (a re-binding inside an ``if`` will
overwrite the outer one in the map). These limitations are
documented in the manifest module and exercised by the tests
below where relevant.
"""

import unittest

from capa import Lexer, Parser
from capa import ast as A
from capa.manifest import build_manifest


def parse(source: str) -> A.Module:
    return Parser(Lexer(source).lex(), source=source).parse_module()


def main_calls(source: str) -> list[dict]:
    m = build_manifest(parse(source), filename="t.capa")
    main = next(f for f in m["functions"] if f["name"] == "main")
    return main["calls"]


# =============================================================
# Basic shape
# =============================================================

class TestArgsFlowShape(unittest.TestCase):
    def test_args_flow_parallel_to_args(self):
        # Even when no flow info exists, every call gets an
        # args_flow list the same length as args.
        calls = main_calls(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = calls[0]
        self.assertEqual(len(c["args_flow"]), len(c["args"]))
        self.assertEqual(c["args_flow"], [None])

    def test_plain_call_has_all_none_flow(self):
        calls = main_calls(
            "fun helper(x: Int) -> Int\n    return x\n"
            "fun main()\n    let n = helper(42)\n"
        )
        c = calls[0]
        self.assertEqual(c["args_flow"], [None])


# =============================================================
# Single restrict chain
# =============================================================

class TestSingleRestriction(unittest.TestCase):
    def test_single_restriction_visible_in_flow(self):
        calls = main_calls(
            "fun fetch_user(net: Net) -> Bool\n"
            "    return net.allows(\"x\")\n"
            "fun main(net: Net)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    let ok = fetch_user(api)\n"
        )
        # Find the fetch_user call.
        fu = next(c for c in calls if c["callee"] == "fetch_user")
        self.assertEqual(len(fu["args_flow"]), 1)
        flow = fu["args_flow"][0]
        self.assertEqual(flow["name"], "api")
        self.assertEqual(len(flow["attenuations"]), 1)
        att = flow["attenuations"][0]
        self.assertEqual(att["method"], "restrict_to")
        self.assertEqual(att["args"], ['"api.example.com"'])

    def test_unbound_arg_has_no_flow(self):
        # The "42" string literal arg gets None, only the bound
        # identifier carries flow info.
        calls = main_calls(
            "fun fetch_user(net: Net, id: String) -> Bool\n"
            "    return net.allows(id)\n"
            "fun main(net: Net)\n"
            "    let api = net.restrict_to(\"x\")\n"
            "    let ok = fetch_user(api, \"42\")\n"
        )
        fu = next(c for c in calls if c["callee"] == "fetch_user")
        self.assertEqual(fu["args_flow"][1], None)


# =============================================================
# Chained restriction (the headline case)
# =============================================================

class TestChainedRestriction(unittest.TestCase):
    def test_chain_of_two_restrictions_propagates(self):
        calls = main_calls(
            "fun fetch_user(net: Net) -> Bool\n"
            "    return net.allows(\"x\")\n"
            "fun main(net: Net)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    let narrower = api.restrict_to(\"v2.api.example.com\")\n"
            "    let ok = fetch_user(narrower)\n"
        )
        fu = next(c for c in calls if c["callee"] == "fetch_user")
        flow = fu["args_flow"][0]
        self.assertEqual(flow["name"], "narrower")
        self.assertEqual(len(flow["attenuations"]), 2)
        first, second = flow["attenuations"]
        self.assertEqual(first["args"], ['"api.example.com"'])
        self.assertEqual(second["args"], ['"v2.api.example.com"'])

    def test_inline_chain_without_intermediate_let(self):
        # let api = net.restrict_to("a").restrict_to("b")
        # Both restrictions should be recorded on api.
        calls = main_calls(
            "fun fetch_user(net: Net) -> Bool\n"
            "    return net.allows(\"x\")\n"
            "fun main(net: Net)\n"
            "    let api = net.restrict_to(\"a\").restrict_to(\"b\")\n"
            "    let ok = fetch_user(api)\n"
        )
        fu = next(c for c in calls if c["callee"] == "fetch_user")
        atts = fu["args_flow"][0]["attenuations"]
        self.assertEqual(len(atts), 2)
        self.assertEqual([a["args"][0] for a in atts], ['"a"', '"b"'])


# =============================================================
# Multiple capability types
# =============================================================

class TestMixedCaps(unittest.TestCase):
    def test_fs_restrict_to_prefix(self):
        calls = main_calls(
            "fun read_app(fs: Fs)\n"
            "    let _ = fs.read(\"/tmp/myapp/data\")\n"
            "fun main(fs: Fs)\n"
            "    let app_fs = fs.restrict_to(\"/tmp/myapp/\")\n"
            "    read_app(app_fs)\n"
        )
        c = next(c for c in calls if c["callee"] == "read_app")
        att = c["args_flow"][0]["attenuations"][0]
        self.assertEqual(att["method"], "restrict_to")
        self.assertEqual(att["args"], ['"/tmp/myapp/"'])

    def test_env_restrict_to_keys(self):
        calls = main_calls(
            "fun read_env(env: Env)\n"
            "    let _ = env.get(\"HOME\")\n"
            "fun main(env: Env)\n"
            "    let limited = env.restrict_to_keys([\"HOME\", \"PATH\"])\n"
            "    read_env(limited)\n"
        )
        c = next(c for c in calls if c["callee"] == "read_env")
        att = c["args_flow"][0]["attenuations"][0]
        self.assertEqual(att["method"], "restrict_to_keys")
        # The list literal stringification is exposed verbatim.
        self.assertIn("HOME", att["args"][0])
        self.assertIn("PATH", att["args"][0])

    def test_clock_restrict_to_after(self):
        calls = main_calls(
            "fun later(clock: Clock)\n"
            "    let _ = clock.allows()\n"
            "fun main(clock: Clock)\n"
            "    let future_only = clock.restrict_to_after(0.0)\n"
            "    later(future_only)\n"
        )
        c = next(c for c in calls if c["callee"] == "later")
        att = c["args_flow"][0]["attenuations"][0]
        self.assertEqual(att["method"], "restrict_to_after")

    def test_random_with_seed(self):
        calls = main_calls(
            "fun do_work(rng: Random)\n"
            "    let _ = rng.int_range(0, 100)\n"
            "fun main(rng: Random)\n"
            "    let det = rng.with_seed(42)\n"
            "    do_work(det)\n"
        )
        c = next(c for c in calls if c["callee"] == "do_work")
        att = c["args_flow"][0]["attenuations"][0]
        self.assertEqual(att["method"], "with_seed")
        self.assertEqual(att["args"], ["42"])


# =============================================================
# Negative cases
# =============================================================

class TestNoFlow(unittest.TestCase):
    def test_non_restrict_method_does_not_record(self):
        # `let users = net.get(url)` is a call, not a restrict chain.
        calls = main_calls(
            "fun helper(s: Result<String, IoError>)\n"
            "    return\n"
            "fun main(net: Net)\n"
            "    let users = net.get(\"https://x\")\n"
            "    helper(users)\n"
        )
        c = next(c for c in calls if c["callee"] == "helper")
        self.assertEqual(c["args_flow"][0], None)

    def test_unrestricted_param_is_not_in_map(self):
        # Bare capability parameters (no restriction chain applied)
        # do not appear in args_flow, even though they are caps.
        calls = main_calls(
            "fun helper(net: Net)\n"
            "    let _ = net.allows(\"x\")\n"
            "fun main(net: Net)\n"
            "    helper(net)\n"
        )
        c = next(c for c in calls if c["callee"] == "helper")
        self.assertEqual(c["args_flow"][0], None)


if __name__ == "__main__":
    unittest.main()
