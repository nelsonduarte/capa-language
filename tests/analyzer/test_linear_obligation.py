"""Analyzer tests: linear must-consume-exactly-once plus move/alias tracking: consume,
use-after-consume, param-reuse, double-free runtime, anonymous drop,
var-reassign, match-partial-consume, move-paths, conditional-alias, and
the carrier-obligation cluster.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from capa import Lexer, Parser, analyze

from tests.analyzer._helpers import check, errors_of


class TestConsume(unittest.TestCase):
    """The `consume` qualifier on a parameter indicates that the call
    transfers ownership of the passed capability. After a consuming
    call, the name cannot be used again.

    In branches (if/else, match), fork/merge is done: snapshot of
    consumed before each branch, conservative union after.
    """

    def test_consume_then_use_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier and cannot be used again" in m for m in msgs)
        )

    def test_consume_then_pass_again_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_does_not_consume(self):
        # Function without `consume` borrows, caller keeps the cap.
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_then_consume_ok(self):
        # Borrows followed by a final consume: typical pattern.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_one_branch_makes_unusable_after(self):
        # If any branch of the if consumes, after the if the cap is considered
        # consumed (conservative rule).
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_both_branches_consume_no_use_after_ok(self):
        # Both branches consume, no use afterward, OK.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_both_branches_consume_use_after_rejected(self):
        # Both branches consume, but using afterward is an error.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_match_arm(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, c: Cor)\n"
            "    match c\n"
            "        Vermelho ->\n"
            "            adoptar(stdio)\n"
            "        Verde ->\n"
            "            stdio.println(\"verde\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_methods_apply(self):
        # `consume` also works on methods.
        msgs = errors_of(
            "type Recurso { id: Int }\n"
            "impl Recurso\n"
            "    fun fechar(self, consume stdio: Stdio)\n"
            "        stdio.println(\"adeus\")\n"
            "fun main(stdio: Stdio)\n"
            "    let r = Recurso { id: 1 }\n"
            "    r.fechar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    # ------- Linearity in loops -------

    def test_consume_in_while_rejected(self):
        # Consuming inside while is an error: on the 2nd iteration it's already consumed.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    while true\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_for_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_in_loop_consume_after_ok(self):
        # Typical pattern: borrow several times in the loop, final consume outside.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio)\n"
            "    var i = 0\n"
            "    while i < 3\n"
            "        emprestar(stdio)\n"
            "        i += 1\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_only_in_loop_ok(self):
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_if_branch_ok(self):
        # If a branch consumes a cap and then diverges (return),
        # the cap is not really consumed past the if: the divergent
        # path never reaches the merge point, so the post-if code
        # can still see the cap as live. Previously the merge was
        # naively conservative and treated the divergent path's
        # consumption as if it flowed forward; this test pins the
        # NLL-style precision fix.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_else_branch_ok(self):
        # Symmetric to the if-then case: the else diverges, the
        # then is a no-op, and the post-if code still has the cap.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        stdio.println(\"keep\")\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_match_arm_ok(self):
        # Same principle applied to match: the Yes arm consumes and
        # returns; the No arm does not consume. The post-match code
        # can only be reached via the No arm, where the cap is
        # still live.
        r = check(
            "type Choice =\n"
            "    Yes\n"
            "    No\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, ch: Choice)\n"
            "    match ch\n"
            "        Yes ->\n"
            "            adoptar(stdio)\n"
            "            return\n"
            "        No -> stdio.println(\"no\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_non_divergent_if_branch_still_rejected(self):
        # Soundness check: the precision fix only excludes branches
        # that diverge. A branch that consumes and then falls
        # through must still propagate the consumption to the
        # merge, otherwise we admit a real use-after-consume.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs), msgs
        )

    def test_consume_in_all_divergent_branches_ok(self):
        # All if branches diverge; the code after is unreachable.
        # The analyzer should not block on a phantom consumption in
        # the unreachable continuation.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    else\n"
            "        return\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestLinearTypes(unittest.TestCase):
    """Roadmap S1: ``linear type`` must-consume discipline. A linear
    value must be consumed (passed to a ``consume`` param / ``consume
    self`` method, or returned) before it leaves scope."""

    _BASE = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        # Drop the unused-cap-param noise so tests assert on the
        # linear messages only.
        return [
            e for e in errors_of(self._BASE + body)
            if "never used" not in e
        ]

    def test_consumed_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_dropped_errors(self):
        errs = self._errs(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    _s.println(\"leak\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_returned_transfers_obligation(self):
        self.assertEqual(
            self._errs(
                "fun make() -> Handle\n"
                "    let h = open()\n"
                "    return h\n"
                "fun main(_s: Stdio)\n"
                "    close(make())\n"
            ),
            [],
        )

    def test_consume_self_method_discharges(self):
        errs = [
            e for e in errors_of(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            )
            if "never used" not in e
        ]
        self.assertEqual(errs, [])

    def test_both_branches_consume_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(c: Bool)\n"
                "    let h = open()\n"
                "    if c\n"
                "        close(h)\n"
                "    else\n"
                "        close(h)\n"
            ),
            [],
        )

    def test_consume_one_branch_only_errors(self):
        errs = self._errs(
            "fun main(c: Bool, _s: Stdio)\n"
            "    let h = open()\n"
            "    if c\n"
            "        close(h)\n"
            "    _s.println(\"x\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_consume_param_terminal_not_re_obligated(self):
        # ``close(consume h)`` is the terminal owner; its own body
        # need not re-consume h. (Regression: an early version seeded
        # consume-params into the live set and flagged close itself.)
        self.assertEqual(self._errs(""), [])

    def test_non_linear_struct_unaffected(self):
        self.assertEqual(
            [
                e for e in errors_of(
                    "type Plain { x: Int }\n"
                    "fun mk() -> Plain\n"
                    "    return Plain { x: 1 }\n"
                    "fun main(_s: Stdio)\n"
                    "    let p = mk()\n"
                )
                if "never used" not in e
            ],
            [],
        )


class TestLinearUseAfterConsume(unittest.TestCase):
    """Soundness: a linear / typestate value consumed *exactly once*
    cannot be used again. Passing it to a ``consume`` parameter, a
    ``consume self`` method, transitioning it with ``become``, or
    returning it consumes it; any later read / pass is a compile error.

    Before this fix a discharge merely cleared the must-consume
    obligation (``_live_linear``) without poisoning the name against
    later use, so a double-consume (settle the same authorization
    twice) type-checked and ran."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_double_consume_linear_param_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_read_field_after_consume_linear_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    let bad = h.id\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_use_after_consume_self_method_rejected(self):
        errs = self._errs(
            "linear type Handle { id: Int }\n"
            "impl Handle\n"
            "    fun shut(consume self) -> Unit\n"
            "        return ()\n"
            "fun open() -> Handle\n"
            "    return Handle { id: 1 }\n"
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    h.shut()\n"
            "    h.shut()\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_double_consume_typestate_after_become_rejected(self):
        # ``become(c, Approved)`` consumes c; a second become of c is
        # a use-after-consume of the old-state value.
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    let b = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(b)\n"
        )
        self.assertTrue(
            any(
                "linear value 'c' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_settle_typestate_twice_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(a)\n"
        )
        self.assertTrue(
            any(
                "linear value 'a' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_single_consume_linear_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_consume_self_once_ok(self):
        self.assertEqual(
            self._errs(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            ),
            [],
        )

    def test_typestate_chain_distinct_names_ok(self):
        # The idiomatic chain: each step binds a fresh name and consumes
        # the previous. Must stay legal after the poison fix.
        self.assertEqual(
            self._errs(
                self._TS
                + "fun main(_s: Stdio)\n"
                "    let c = mk()\n"
                "    let a = become(c, Approved)\n"
                "    settle(a)\n"
            ),
            [],
        )

    def test_return_transfers_obligation_ok(self):
        self.assertEqual(
            self._errs(
                self._TS
                + "fun promote() -> Claim[Approved]\n"
                "    let c = mk()\n"
                "    return become(c, Approved)\n"
                "fun main(_s: Stdio)\n"
                "    settle(promote())\n"
            ),
            [],
        )


class TestLinearConsumeParamReuse(unittest.TestCase):
    """LIN-1: a ``consume`` linear / typestate PARAMETER is OWNED by the
    receiving body, so consuming it a second time -- or using it after a
    consume -- is a use-after-consume, exactly as for a let-bound value.

    Before the fix the consume parameter was seeded into NO tracker (not
    ``_live_linear`` and not ``_borrowed_linear``), so the first discharge
    never poisoned it and every re-use slipped ``--check`` (rc0) and ran a
    real double-free / double-spend. This is the consume analog of the
    borrowed B-F1 hole: the let-bound TWIN of each case below is already
    caught (see ``TestLinearUseAfterConsume``), which is what pins the gap
    to the parameter seeding.

    The whole class shares one root and closes on one seam -- seed the
    consume parameter into the ``_live_linear`` owned tracker (drop-exempt)
    -- so each member is rejected with the single use-after-consume
    message. The negatives pin the class boundary: dropping a consume
    parameter WITHOUT re-consuming stays legal (the terminal-owner
    semantics used by ``discard`` / ``adopt`` and the typestate
    examples)."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun release(consume h: Handle)\n"
        "    return\n"
        "fun forward(consume h: Handle)\n"
        "    release(h)\n"
    )
    _FILE = (
        "linear type File { fd: Int }\n"
        "impl File\n"
        "    fun close(consume self)\n"
        "        return\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun settle(consume c: Claim[Approved])\n"
        "    return\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _assert_reuse_rejected(self, src: str, name: str) -> None:
        errs = self._errs(src)
        self.assertTrue(
            any(
                f"linear value {name!r} was consumed earlier and cannot "
                f"be used again" in e
                for e in errs
            ),
            errs,
        )

    # ---- the six-member class (each rc0 before the fix) ----------

    def test_member1_double_consume_arg_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun choose(consume h: Handle)\n"
            "    release(h)\n"
            "    release(h)\n",
            "h",
        )

    def test_member2_use_after_consume_field_read_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun bad(consume h: Handle) -> Int\n"
            "    release(h)\n"
            "    return h.id\n",
            "h",
        )

    def test_member3_double_free_sink_twice_rejected(self):
        self._assert_reuse_rejected(
            "linear type File { fd: Int }\n"
            "fun sink(consume f: File)\n"
            "    return\n"
            "fun bad(consume f: File)\n"
            "    sink(f)\n"
            "    sink(f)\n",
            "f",
        )

    def test_member4_forward_then_reuse_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun bad(consume h: Handle)\n"
            "    forward(h)\n"
            "    release(h)\n",
            "h",
        )

    def test_member5_pack_after_consume_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "type Box { h: Handle }\n"
            "fun bad(consume h: Handle) -> Box\n"
            "    release(h)\n"
            "    return Box { h: h }\n",
            "h",
        )

    def test_member6_typestate_double_become_rejected(self):
        self._assert_reuse_rejected(
            self._TS
            + "fun bad(consume c: Claim[Draft])\n"
            "    let a = become(c, Approved)\n"
            "    let b = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(b)\n",
            "c",
        )

    def test_member1_double_consume_self_method_rejected(self):
        # The consume-self shape of the double-consume: ``f.close()`` twice.
        self._assert_reuse_rejected(
            self._FILE
            + "fun bad(consume f: File)\n"
            "    f.close()\n"
            "    f.close()\n",
            "f",
        )

    # ---- the class boundary: drop stays legal (negatives) --------

    def test_neg7_terminal_consumer_drop_is_legal(self):
        # A consume parameter received and never re-consumed is the
        # documented terminal owner (``discard`` / ``adopt``): still rc0.
        # This is the case the drop-exemption exists to preserve.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun discard(consume h: Handle)\n"
                "    return\n"
            ),
            [],
        )

    def test_neg8_typestate_examples_stay_accepted(self):
        # The canonical typestate examples end each protocol with a
        # terminal ``discard(consume ...)``; the drop-exemption keeps them
        # rc0. A regression here would reject a shipped example.
        import pathlib
        # This module lives at tests/analyzer/, two levels below the repo
        # root that holds examples/ (it was one level below as the former
        # tests/test_analyzer.py, hence parents[1] there).
        root = pathlib.Path(__file__).resolve().parents[2]
        for rel in (
            "examples/wasm/typestate_door.capa",
            "examples/wasm/typestate_methods.capa",
            "examples/wasm/typestate_socket.capa",
        ):
            src = (root / rel).read_text(encoding="utf-8")
            errs = self._errs(src)
            self.assertEqual(errs, [], f"{rel}: {errs}")

    def test_neg9_valid_single_consume_arg_is_legal(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun closeit(consume h: Handle)\n"
                "    release(h)\n"
            ),
            [],
        )

    def test_neg9_valid_single_consume_self_is_legal(self):
        self.assertEqual(
            self._errs(
                self._FILE
                + "fun closeit(consume f: File)\n"
                "    f.close()\n"
            ),
            [],
        )

    def test_neg9_valid_single_become_and_forward_is_legal(self):
        # Transition a consume typestate parameter once and hand the result
        # to a consumer: a valid single consume, not a re-use.
        self.assertEqual(
            self._errs(
                self._TS
                + "fun approve(consume c: Claim[Draft])\n"
                "    settle(become(c, Approved))\n"
            ),
            [],
        )

    def test_neg10_borrowed_linear_param_consume_still_rejected(self):
        # B-F1 unchanged: a NON-consume linear parameter is BORROWED, so
        # consuming it stays a compile error (the caller retains ownership).
        errs = self._errs(
            self._LIN
            + "fun peek(h: Handle)\n"
            "    release(h)\n"
        )
        self.assertTrue(
            any(
                "borrowed linear/typestate value 'h'" in e for e in errs
            ),
            errs,
        )

    def test_neg10_alias_consume_param_then_consume_alias_is_legal(self):
        # Aliasing the consume parameter MOVES the obligation onto the
        # alias; consuming the alias once is valid (the source is poisoned,
        # not re-consumed). Confirms the let-owned move path is unchanged.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun ok(consume h: Handle)\n"
                "    let h2 = h\n"
                "    release(h2)\n"
            ),
            [],
        )


class TestLinearConsumeParamDoubleFreeRuntime(unittest.TestCase):
    """LIN-1 member 3 (double-free) end to end. ``--check`` now REJECTS a
    consume-parameter double-consume, so a rejected program never reaches
    a backend. To prove that rejection is load-bearing -- that the base
    really would double-free -- we BYPASS the analyzer verdict and drive
    the codegen directly: the value is consumed twice (a double-spend,
    ``PAID 100`` printed twice) IDENTICALLY on all three backends (legacy
    / --ir / --wasm). The types and bindings are fully resolved even when
    the flow check rejects, so the codegen runs; the fix stops the program
    at ``--check`` before it can ever execute this double-spend."""

    # ``settle`` spends the payment; consuming ``p`` twice double-spends.
    _DOUBLE_SPEND = (
        "linear type Payment { amount: Int }\n"
        "impl Payment\n"
        "    fun settle(consume self, stdio: Stdio)\n"
        '        stdio.println("PAID ${self.amount}")\n'
        "fun process(consume p: Payment, stdio: Stdio)\n"
        "    p.settle(stdio)\n"
        "    p.settle(stdio)\n"
        "fun main(stdio: Stdio)\n"
        "    process(Payment { amount: 100 }, stdio)\n"
    )

    @staticmethod
    def _has_wasm() -> bool:
        import shutil
        if shutil.which("wasm-tools") is None:
            return False
        try:
            import wasmtime  # noqa: F401
            return True
        except ImportError:
            return False

    def _run_unchecked(self, backend: str) -> str:
        """Compile + run ``_DOUBLE_SPEND`` on ``backend`` with the analyzer
        verdict IGNORED, capturing stdout."""
        import io
        import sys
        module = Parser(
            Lexer(self._DOUBLE_SPEND).lex(), source=self._DOUBLE_SPEND,
        ).parse_module()
        result = analyze(module, source=self._DOUBLE_SPEND)  # rejects; ignored
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            if backend == "legacy":
                from capa import transpile
                code = transpile(
                    module, types=result.types, bindings=result.bindings,
                )
                exec(compile(code, "<lin1>", "exec"), {"__name__": "__main__"})
            elif backend == "ir":
                from capa.ir import compile_program
                code = compile_program(
                    module, types=result.types, bindings=result.bindings,
                )
                exec(compile(code, "<lin1>", "exec"), {"__name__": "__main__"})
            elif backend == "wasm":
                from capa.ir import compile_wasm
                from capa.runtime._wasm_host import WasmHost
                blob = compile_wasm(module, types=result.types)
                WasmHost().run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_check_rejects_the_double_spend(self):
        errs = [
            e for e in errors_of(self._DOUBLE_SPEND) if "never used" not in e
        ]
        self.assertTrue(
            any(
                "linear value 'p' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_base_double_spends_on_legacy_and_ir_when_unchecked(self):
        # Analysis bypassed: both Python backends consume ``p`` twice.
        self.assertEqual(self._run_unchecked("legacy"), "PAID 100\nPAID 100\n")
        self.assertEqual(self._run_unchecked("ir"), "PAID 100\nPAID 100\n")

    def test_base_double_spends_on_wasm_when_unchecked(self):
        if not self._has_wasm():
            self.skipTest("wasm-tools and/or wasmtime-py not installed")
        self.assertEqual(self._run_unchecked("wasm"), "PAID 100\nPAID 100\n")


class TestLinearAnonymousDrop(unittest.TestCase):
    """Soundness: a linear / typestate value cannot be dropped into an
    anonymous slot -- a wildcard binding ``let _ = open()`` or a bare
    expression statement ``open()`` / ``become(c, S)`` -- any more than
    it can be dropped under a named binding.

    Before this fix the must-consume obligation was keyed only by the
    bound name, so an anonymous drop registered no obligation and the
    value silently vanished unconsumed."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_wildcard_let_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let _ = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_expr_stmt_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_become_stmt_drops_typestate_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_drops_typestate_become_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let _ = become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_moves_linear_reported_once(self):
        # ``let _ = h`` moves the live binding into the void; it must be
        # reported once at the drop site and not again at function exit.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let _ = h\n"
        )
        drops = [e for e in errs if "dropped without being consumed" in e]
        self.assertEqual(len(drops), 1, errs)

    # ---- positives that must keep compiling ----------------------

    def test_bare_consume_call_stmt_ok(self):
        # ``close(h)`` as a bare statement returns Unit (not linear), so
        # it is a legal consume, not a drop.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_wildcard_let_nonlinear_ok(self):
        self.assertEqual(
            self._errs(
                "type Plain { x: Int }\n"
                "fun mk() -> Plain\n"
                "    return Plain { x: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let _ = mk()\n"
            ),
            [],
        )


class TestLinearVarAndReassign(unittest.TestCase):
    """Soundness: a ``var`` binding of a linear / typestate value carries
    the same must-consume obligation a ``let`` does -- ``var`` only makes
    the slot re-assignable, it does not waive use-once. Re-assigning a name
    that still holds a live linear value DROPS that value (a leak), while
    re-assigning a name whose value was already consumed re-arms a fresh
    obligation.

    Before this fix ``_check_var`` never registered the obligation and
    ``_check_assign`` never touched the live set, so a linear value bound
    with ``var`` (or re-assigned) escaped both the leak and the
    double-consume checks."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_var_linear_leak_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    var h = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_var_double_consume_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_reassign_drops_live_linear_rejected(self):
        # ``h = open()`` while h still holds an unconsumed value overwrites
        # (and so drops) the old value -- a leak.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    h = open()\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' is dropped without being consumed; "
                "re-assigning to it overwrites the old value" in e
                for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_var_single_consume_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_reassign_after_consume_ok(self):
        # The old value was consumed before the re-assignment, so the
        # name re-arms a fresh obligation that the final close discharges.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
                "    h = open()\n"
                "    close(h)\n"
            ),
            [],
        )


class TestLinearMatchPartialConsume(unittest.TestCase):
    """Soundness: a linear / typestate value live at the entry of a
    ``match`` must be consumed on EVERY non-diverging arm or on NONE.
    Consuming it in some arms but not others leaks it on the paths that
    did not consume -- the obligation survives the merge (the union of
    each reachable arm's survivors), so the leak surfaces, and a later
    consume after the match is a use-after-consume on the arms that
    already consumed it.

    Before this fix ``_check_match_expr`` merged ``_consumed`` like
    ``_check_if`` but never snapshotted / merged ``_live_linear``, so
    consuming in a single arm removed the obligation permanently and the
    leak on the other arms went unreported."""

    _M = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun pick() -> Option<Int>\n"
        "    return Some(1)\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_match_partial_consume_rejected(self):
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> ()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_match_consume_all_arms_ok(self):
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> close(h)\n"
                "        None -> close(h)\n"
            ),
            [],
        )

    def test_match_consume_none_then_after_ok(self):
        # Consumed in no arm, then consumed once after the match.
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> ()\n"
                "        None -> ()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_match_consume_all_arms_then_after_rejected(self):
        # Consumed in every arm, then used again after the match: a
        # use-after-consume on whichever arm ran.
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )


class TestLinearMovePaths(unittest.TestCase):
    """Struct field move-paths for the linear/typestate discipline.

    Consuming, moving, or projecting a linear/typestate STRUCT FIELD is
    now tracked per path, closing the latent runtime double-free where
    ``close(s.conn)`` on a value carrying a live linear field was a silent
    no-op. The three shapes:

    - HOLE-1: per-field partial-move accounting -- moving one linear field
      leaves the others outstanding; the whole value cannot be consumed
      once a field was moved (partial-move double-free).
    - HOLE-2: aliasing a value whose type transitively owns a linear field
      (even a non-linear carrier) MOVES the base.
    - WARNING-3: overwriting a live linear field drops it (a leak).
    - WARNING-4/5: a borrowed value's field cannot be consumed or laundered
      out through a projection.

    Both facets (``linear type`` and ``typestate``) are exercised.
    Analyzer-only, reject-only; the accepted shapes are run byte-identically
    on all three backends by ``test_ir_wasm_parity``."""

    # A linear struct P carrying two linear fields a, b and a scalar tag.
    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "linear type P { a: Conn, b: Conn, tag: Int }\n"
        "fun mkp() -> P\n"
        "    return P { a: open(), b: open(), tag: 0 }\n"
        "fun sinkp(consume p: P) -> Unit\n"
        "    return ()\n"
    )
    # A NON-linear struct S carrying a linear field conn plus a scalar tag.
    _NL = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
        "fun sink(consume s: S) -> Unit\n"
        "    return ()\n"
    )
    # Typestate facet: a Claim carrying a linear/typestate field inside a
    # non-linear Record carrier.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Record { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Record\n"
        "    return Record { claim: become(mk(), Settled), tag: 0 }\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    # ---- HOLE-1 partial-move accounting ----

    def test_consume_both_linear_fields_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    close(p.b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_one_field_leaks_naming_other(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n"
        )
        self.assertTrue(
            any("'p.b'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_project_field_then_use_rest_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    let c = p.a\n    close(c)\n    close(p.b)\n"
            "    let n = p.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_double_consume_through_path_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    close(p.a)\n    close(p.b)\n"
        )
        self.assertTrue(
            any("'p.a'" in e and "consumed earlier" in e for e in errs),
            errs,
        )

    def test_consume_field_then_whole_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    sinkp(p)\n"
        )
        self.assertTrue(
            any("its field 'p.a' was already consumed" in e for e in errs),
            errs,
        )

    # ---- HOLE-2 alias-move ----

    def test_alias_move_double_free_rejected(self):
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let t = s\n    close(s.conn)\n    close(t.conn)\n"
        )
        self.assertTrue(
            any("'s'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_field_move_out_of_non_linear_carrier_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let c = s.conn\n    close(c)\n    let n = s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_typestate_carrier_field_move_out_ok(self):
        r = check(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let n = rec.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_typestate_carrier_alias_move_double_free_rejected(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let dup = rec\n    archive(rec.claim)\n    archive(dup.claim)\n"
        )
        self.assertTrue(
            any("'rec'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- WARNING-3 field-store drop ----

    def test_field_store_over_live_field_rejected(self):
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    s.conn = open()\n    let c = s.conn\n    close(c)\n"
        )
        self.assertTrue(
            any("'s.conn' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )

    def test_field_store_after_consume_rearms_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    close(s.conn)\n"
            "    let n = s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- WARNING-4/5 borrow facet over paths ----

    def test_read_scalar_field_of_borrowed_carrier_ok(self):
        r = check(
            self._NL + "fun peek(s: S) -> Int\n    return s.conn.id\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_sibling_locals_not_over_rejected_when_param_borrowed(self):
        r = check(
            self._NL + "fun use(s: S) -> Int\n"
            "    let session = mks()\n    close(session.conn)\n"
            "    let s2 = mks()\n    close(s2.conn)\n    return s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_field_of_borrowed_carrier_rejected(self):
        errs = self._errs(
            self._NL + "fun bad(s: S) -> Unit\n    close(s.conn)\n"
        )
        self.assertTrue(
            any("borrowed value the caller still owns" in e
                or "belongs to a borrowed value" in e for e in errs),
            errs,
        )

    def test_project_field_of_borrowed_then_consume_rejected(self):
        errs = self._errs(
            self._NL + "fun bad(s: S) -> Unit\n    let c = s.conn\n    close(c)\n"
        )
        self.assertTrue(
            any("borrowed" in e for e in errs), errs,
        )

    # ---- retained: no linear value into a container ----

    def test_linear_value_into_container_still_rejected(self):
        # A whole linear value may still not enter a container; the field
        # move-paths do not relax that (containers stay deferred). Embedding
        # it never discharges the obligation, so it leaks at scope exit.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    let c = open()\n"
            "    let xs = [c]\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )


class TestLinearConditionalAlias(unittest.TestCase):
    """A linear/typestate value selected through an if/match EXPRESSION.

    The move / consume / return / receiver seams recognised only a bare
    ``Ident`` / ``FieldAccess`` node, so an ``if`` / ``match`` wrapper that
    yields a linear place was invisible to them: binding, consuming, or
    returning the wrapper opened a SECOND obligation on the same runtime
    value, a double-free. A single position-independent bar used to reject
    every such wrapper at one ``_check_expr`` site.

    That bar was replaced by RESOLUTION: the selection's outcome is computed
    once, where the arms have been checked, and read back through
    ``_path_of`` by every position-driven rule. So the reject now comes from
    the rule the program actually violates, and says which value:

    * a selection whose arms hand over the SAME place IS that place, so
      reusing it afterwards is an ordinary use-after-consume naming the
      value, and consuming it exactly ONCE is legal (the bar rejected that
      too -- `test_nested_wrapper_form` below is the case, and it now
      compiles and closes its resource once on all three backends);
    * a selection over a BORROWED value reports the borrow, with the wording
      the direct spelling already used;
    * a selection naming DIFFERENT places, or one arm that cannot be
      resolved, keeps the fail-closed selection reject, because one branch
      would leak -- `test_selection_of_distinct_places_rejected` pins it.

    Both facets (``linear type`` and ``typestate``) are exercised; the reject
    parity across the three backends is pinned by ``test_ir_wasm_parity``."""

    # A bare linear resource with an indexed factory and a consume sink.
    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open(n: Int) -> Conn\n"
        "    return Conn { id: n }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    # A NON-linear carrier S owning a linear field conn plus a scalar tag.
    _NL = _LIN + (
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(1), tag: 0 }\n"
    )
    # Typestate facet: an authorization that must be settled exactly once.
    _TS = (
        "typestate Auth\n    Pending\n    Settled\n"
        "fun mk() -> Auth[Pending]\n"
        "    return Auth[Pending] {}\n"
        "fun settle(consume a: Auth[Pending]) -> Unit\n"
        "    return ()\n"
    )
    _MSG = "cannot be selected through a conditional / match expression"

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _assert_barred(self, body: str) -> None:
        """The fail-closed SELECTION reject, for a selection that cannot be
        resolved to one place."""
        errs = self._errs(body)
        self.assertTrue(any(self._MSG in e for e in errs), errs)

    def _assert_says(self, body: str, needle: str) -> None:
        """Rejected, and the diagnostic names the value or the borrow. The
        message is asserted rather than only the verdict because the whole
        point of resolving the operand is WHICH rule fires: a generic bar
        would still reject these and say nothing useful."""
        errs = self._errs(body)
        self.assertTrue(any(needle in e for e in errs), errs)

    def _assert_reuse_of(self, body: str, name: str) -> None:
        """Rejected as an ordinary use-after-consume NAMING ``name``."""
        self._assert_says(
            body, f"linear value {name!r} was consumed earlier")

    def _assert_borrowed_value(self, body: str, name: str) -> None:
        """Rejected by the shared borrowed-TRANSFER reject."""
        self._assert_says(
            body,
            f"cannot consume or transfer borrowed linear/typestate value "
            f"{name!r}")

    def _assert_borrowed_field(self, body: str, place: str) -> None:
        """Rejected by the borrowed-FIELD reject inside the move seam."""
        self._assert_says(
            body,
            f"cannot consume or move linear/typestate field {place!r}")

    # ---- must REJECT: whole value / field / borrowed / all sites ----
    #
    # Each of these still rejects, and now asserts WHICH rule fires. Before
    # the selection was resolved they all produced the same generic
    # "cannot be selected through a conditional" text, which said nothing
    # about what was wrong with the program.

    def test_1a_whole_value_via_if_bind(self):
        # ``let t = if true then s else s; close(s); close(t)`` double-frees.
        # Both arms hand over ``s``, so ``t`` IS ``s`` and the second close
        # is an ordinary use-after-consume that NAMES the value.
        self._assert_reuse_of(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = if true then s else s\n"
            "    close(s)\n    close(t)\n", "s"
        )

    def test_a3_whole_value_via_match_bind(self):
        self._assert_reuse_of(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = match 0\n        _ -> s\n"
            "    close(s)\n    close(t)\n", "s"
        )

    def test_1b_linear_field_via_if(self):
        # b1: a linear field of a non-linear carrier, selected through if.
        # The selection resolves to the FIELD place, so the reject names it.
        self._assert_reuse_of(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let c = if true then s.conn else s.conn\n"
            "    close(c)\n    close(s.conn)\n", "s.conn"
        )

    def test_1c_borrowed_carrier_field_via_if_return(self):
        # b2: a borrowed carrier's field returned through if bypassed the
        # borrow guard. Resolved, it reaches the borrowed-FIELD reject with
        # the wording the direct spelling ``return s.conn`` already used.
        self._assert_borrowed_field(
            self._NL + "fun bad(s: S) -> Conn\n"
            "    return if true then s.conn else s.conn\n", "s.conn"
        )

    def test_consume_arg_form(self):
        # ``close(if c then s else s)`` -- the wrapper as a consume argument.
        self._assert_reuse_of(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    close(if true then s else s)\n    close(s)\n", "s"
        )

    def test_return_form_on_borrowed_param(self):
        # ``return if c then s else s`` on a borrowed param -- borrow bypass.
        # Reaches the shared borrowed-TRANSFER reject, naming the parameter.
        self._assert_borrowed_value(
            self._LIN + "fun bad(c: Conn) -> Conn\n"
            "    return if true then c else c\n", "c"
        )

    def test_nested_wrapper_form(self):
        # ``if a then s else (if b then s else s)`` -- a place at depth.
        # EVERY arm hands over ``s`` and ``t`` is consumed exactly ONCE, so
        # nothing doubles and nothing leaks: this is a CORRECT program and
        # it must COMPILE. The old position-independent bar rejected it
        # because it could not tell one place from two; a resolved selection
        # can. Verified to run byte-identically on the legacy, ``--ir`` and
        # ``--wasm`` backends, closing its resource exactly once.
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = if true then s else (if false then s else s)\n"
            "    close(t)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_claimdesk_double_disbursement_typestate(self):
        # The claimdesk shape: one authorization settled twice via an alias
        # laundered through a conditional.
        self._assert_reuse_of(
            self._TS + "fun main(_s: Stdio)\n    let authz = mk()\n"
            "    let dup = if true then authz else authz\n"
            "    settle(authz)\n    settle(dup)\n", "authz"
        )

    def test_typestate_whole_value_via_if_bind(self):
        self._assert_reuse_of(
            self._TS + "fun main(_s: Stdio)\n    let a = mk()\n"
            "    let t = if true then a else a\n"
            "    settle(a)\n    settle(t)\n", "a"
        )

    def test_selection_of_distinct_places_rejected(self):
        # Per the design's (2) rule: selecting between two DISTINCT live
        # linear resources is barred (not tracked-through).
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let a = open(1)\n    let b = open(2)\n"
            "    let t = if true then a else b\n"
            "    close(t)\n"
        )

    # ---- must COMPILE: fresh factory + non-linear conditionals ----

    def test_fresh_factory_conditional_ok(self):
        # Arms are CALLS (fresh values), not places, so the bar does not fire.
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let t = if true then open(1) else open(2)\n"
            "    close(t)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_fresh_factory_via_match_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let t = match 0\n        _ -> open(1)\n"
            "    close(t)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_int_conditional_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let n = if true then 1 else 2\n    let _ = n\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_string_conditional_ok(self):
        r = check(
            "fun verdict(live: Bool) -> String\n"
            "    return if live then \"yes\" else \"no\"\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_option_match_ok(self):
        r = check(
            "fun pick(o: Option<Int>) -> Int\n"
            "    return match o\n        Some(x) -> x\n        None -> 0\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_carrier_field_conditional_ok(self):
        # Selecting a NON-linear field (the scalar tag) through a conditional
        # is untouched: the bar keys on the linear/typestate leaf type only.
        r = check(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let n = if true then s.tag else 0\n"
            "    close(s.conn)\n    let _ = n\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


class TestLinearCarrierObligation(unittest.TestCase):
    """Carrier obligation: a struct (or nested struct) that TRANSITIVELY
    OWNS a linear/typestate field is itself a must-consume CARRIER. It must
    be consumed / transitioned / returned, OR its linear field(s) must be
    consumed / moved out, else it leaks -- exactly as a bare linear value
    does. Closes the struct-literal move-tracking double-free: a linear
    value packed into a field and then re-used double-frees.

    Discharge is PER-FIELD: consuming or moving out the carrier's linear
    field(s) satisfies it (the whole value need not itself reach a
    consume). A ``consume``-param carrier is DROP-EXEMPT transitively.

    Analyzer-only; accepted shapes lower unchanged. Both facets
    (``linear type`` and ``typestate``) are exercised."""

    _BASE = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "type Box { h: Handle }\n"
        "fun make_box() -> Box\n"
        "    return Box { h: open() }\n"
        "fun sink(consume b: Box) -> Unit\n"
        "    return ()\n"
    )
    # A carrier W with a single linear field plus a scalar, for the
    # partial-field-consume-across-branches (Connection C) tests.
    _W = (
        "type W { c: Handle, tag: Int }\n"
        "fun mkw() -> W\n"
        "    return W { c: open(), tag: 0 }\n"
    )
    # Typestate facet: a non-linear carrier of a typestate field.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Rec { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Rec\n"
        "    return Rec { claim: become(mk(), Settled), tag: 0 }\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _rejects(self, body: str) -> None:
        self.assertTrue(self._errs(body), "expected a rejection, got none")

    def _compiles(self, body: str) -> None:
        errs = self._errs(body)
        self.assertEqual(errs, [], errs)

    # ---- core struct-pack double-free (both orders) ----

    def test_pack_then_reuse_source_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let h = open()\n"
            "    let b = Box { h: h }\n    close(h)\n    close(b.h)\n"
        )

    def test_pack_then_reuse_field_first_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let h = open()\n"
            "    let b = Box { h: h }\n    close(b.h)\n    close(h)\n"
        )

    # ---- E1 binding-level arming from a factory call ----

    def test_factory_carrier_dropped_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
        )

    def test_factory_carrier_anonymous_drop_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let _ = make_box()\n"
        )

    def test_factory_carrier_bare_stmt_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    make_box()\n"
        )

    def test_nested_carrier_dropped_rejected(self):
        self._rejects(
            self._BASE + "type Inner { h: Handle }\n"
            "type Outer { inner: Inner, tag: Int }\n"
            "fun make_outer() -> Outer\n"
            "    return Outer { inner: Inner { h: open() }, tag: 0 }\n"
            "fun main(_s: Stdio)\n    let o = make_outer()\n"
        )

    # ---- Connection C: partial field-consume across branches ----

    def test_partial_field_consume_across_branches_rejected(self):
        self._rejects(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    if flag\n        close(w.c)\n    else\n        s.println(\"x\")\n"
        )

    def test_field_consume_on_all_paths_ok(self):
        self._compiles(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    if flag\n        close(w.c)\n    else\n        close(w.c)\n"
        )

    def test_partial_field_consume_match_rejected(self):
        self._rejects(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    match flag\n"
            "        true -> close(w.c)\n"
            "        false -> s.println(\"x\")\n"
        )

    # ---- E2: reassign drops the old carrier ----

    def test_reassign_drops_old_carrier_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    var b = make_box()\n"
            "    b = make_box()\n    close(b.h)\n"
        )

    # ---- variant payload BAR (declaration) ----

    def test_variant_bare_linear_payload_rejected(self):
        self._rejects(
            "linear type Handle { id: Int }\n"
            "type Wrap =\n    A(Handle)\n    B(Int)\n"
        )

    def test_variant_bare_typestate_payload_rejected(self):
        self._rejects(
            "typestate Claim\n    Draft\n    Settled\n"
            "type Wrap =\n    A(Claim[Draft])\n    B(Int)\n"
        )

    # ---- STAY ACCEPTED ----

    def test_return_carrier_literal_ok(self):
        self._compiles(
            self._BASE + "fun wrap(consume h: Handle) -> Box\n"
            "    return Box { h: h }\n"
        )

    def test_carrier_consumed_once_ok(self):
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    sink(b)\n"
        )

    def test_carrier_passthrough_ok(self):
        self._compiles(
            self._BASE + "fun passthrough(consume b: Box) -> Box\n"
            "    return b\n"
        )

    def test_borrowed_carrier_forwarded_ok(self):
        self._compiles(
            self._BASE + "fun peek(b: Box) -> Int\n    return b.h.id\n"
            "fun use2(b: Box) -> Int\n    return peek(b)\n"
        )

    def test_consume_carrier_param_dropped_ok(self):
        # Adopting the whole carrier + its contents is legal (drop-exempt
        # transitively), consistent with ``adopt(consume h)``.
        self._compiles(
            self._BASE + "fun adopt_box(consume b: Box) -> Unit\n"
            "    return ()\n"
        )

    def test_field_consumed_then_carrier_dropped_ok(self):
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n"
        )

    def test_typestate_carrier_field_moved_out_ok(self):
        self._compiles(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let n = rec.tag\n"
        )

    def test_arm_local_carrier_field_moved_out_ok(self):
        # A carrier bound AND fully field-moved-out inside a single match arm
        # (the capa_claimdesk ``let result = settle(...); let settled =
        # result.claim; settled.archive()`` shape). Moving out its last
        # linear field discharges the whole carrier, so it must not linger
        # into the arm merge (where the sibling arm would wrongly intersect
        # the field-move away and report a false leak).
        self._compiles(
            self._BASE + "fun main(s: Stdio, flag: Bool)\n"
            "    match flag\n"
            "        true ->\n"
            "            let b = make_box()\n"
            "            let inner = b.h\n"
            "            close(inner)\n"
            "        false ->\n"
            "            s.println(\"x\")\n"
        )

    def test_typestate_carrier_dropped_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
        )

    # ---- HUSK re-consume after ALL linear fields moved out ----
    # A carrier whose linear field(s) are all moved out is a spent husk. It
    # may be DROPPED, but consuming / returning / re-packing the WHOLE husk
    # again re-transfers an already-moved field -- a runtime double-free.

    def test_field_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    sink(b)\n"
        )

    def test_field_projected_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    let x = b.h\n    close(x)\n    sink(b)\n"
        )

    def test_field_moved_then_whole_returned_rejected(self):
        self._rejects(
            self._BASE + "fun leak(consume b: Box) -> Box\n"
            "    close(b.h)\n    return b\n"
        )

    def test_field_moved_then_repacked_rejected(self):
        self._rejects(
            self._BASE + "type Outer2 { inner: Box }\n"
            "fun sink_o2(consume o: Outer2) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let o = Outer2 { inner: b }\n    sink_o2(o)\n"
        )

    def test_two_fields_both_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "type W2 { c: Handle, d: Handle }\n"
            "fun mkw2() -> W2\n    return W2 { c: open(), d: open() }\n"
            "fun sink2(consume w: W2) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let w = mkw2()\n"
            "    close(w.c)\n    close(w.d)\n    sink2(w)\n"
        )

    def test_nested_field_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "type Inner2 { h: Handle }\n"
            "type Outer3 { inner: Inner2 }\n"
            "fun mko3() -> Outer3\n"
            "    return Outer3 { inner: Inner2 { h: open() } }\n"
            "fun sink_o3(consume o: Outer3) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let o = mko3()\n"
            "    close(o.inner.h)\n    sink_o3(o)\n"
        )

    # ---- STAY ACCEPTED: husk dropped / husk non-linear field read ----

    def test_husk_dropped_ok(self):
        # Field moved out, husk merely dropped, never re-consumed: legal (the
        # per-field-discharge semantic that keeps claimdesk compiling).
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n"
        )

    def test_husk_nonlinear_field_read_after_move_ok(self):
        # Reading a husk's NON-linear field after moving out its linear field
        # must stay legal (this is why the husk root is not marked
        # wholesale-consumed).
        self._compiles(
            "linear type Handle { id: Int }\n"
            "fun open() -> Handle\n    return Handle { id: 1 }\n"
            "fun close(consume h: Handle) -> Unit\n    return ()\n"
            "type BoxT { h: Handle, tag: Int }\n"
            "fun make_boxt() -> BoxT\n    return BoxT { h: open(), tag: 0 }\n"
            "fun main(_s: Stdio)\n    let b = make_boxt()\n"
            "    let x = b.h\n    close(x)\n    let n = b.tag\n"
        )

    # ---- HUSK re-consume through an ALIAS / reassignment ----
    # The move seam poisons the SOURCE binding, but an alias / reassignment
    # re-arms the TARGET with a fresh FULL obligation, so without carrying the
    # moved-out sub-path across, re-consuming the whole husk through the alias
    # slips past every use-site scan and lowers to a runtime double-free. The
    # moved sub-path must travel across the alias (and along a chain), so the
    # husk-reconsume / discharge / field-use scans fire on the alias too.

    def test_alias_husk_then_consume_alias_rejected(self):
        # Alias the spent husk, then consume the alias whole -> double-free.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    sink(c)\n"
        )

    def test_alias_husk_then_field_moved_again_rejected(self):
        # Alias the husk, then move the SAME (already-freed) field out again
        # through the alias.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    close(c.h)\n"
        )

    def test_alias_husk_then_returned_rejected(self):
        # Alias the husk, then return the alias from a by-consume function ->
        # re-transfers an already-moved field to the caller.
        self._rejects(
            self._BASE + "fun leak2(consume b: Box) -> Box\n"
            "    close(b.h)\n    let c = b\n    return c\n"
        )

    def test_chained_alias_husk_then_consume_tail_rejected(self):
        # Alias the alias (a chain), then consume the tail: the moved-out
        # sub-path must travel the whole chain.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    let d = c\n    sink(d)\n"
        )

    def test_reassign_husk_into_var_then_consume_rejected(self):
        # Reassign the husk into an existing (cleanly discharged) var, then
        # consume it whole -> double-free through the reassigned binding.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    var c = make_box()\n    sink(c)\n"
            "    c = b\n    sink(c)\n"
        )

    def test_typestate_alias_husk_then_consume_rejected(self):
        # Typestate facet: move out a carrier's typestate field, alias the
        # husk, then consume the alias whole.
        self._rejects(
            self._TS + "fun sink_rec(consume r: Rec) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let alias = rec\n    sink_rec(alias)\n"
        )

    # ---- STAY ACCEPTED: alias route must not over-reject ----

    def test_alias_full_carrier_consumed_once_ok(self):
        # A full carrier aliased then consumed exactly once, with NO prior
        # field-move: the obligation just moves onto the alias.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    let c = b\n    sink(c)\n"
        )

    def test_alias_husk_nonlinear_field_read_ok(self):
        # Aliasing a husk then reading the alias's NON-linear field stays
        # legal (only the moved linear sub-path travels, never the root).
        self._compiles(
            "linear type Handle { id: Int }\n"
            "fun open() -> Handle\n    return Handle { id: 1 }\n"
            "fun close(consume h: Handle) -> Unit\n    return ()\n"
            "type BoxT { h: Handle, tag: Int }\n"
            "fun make_boxt() -> BoxT\n    return BoxT { h: open(), tag: 0 }\n"
            "fun main(_s: Stdio)\n    let b = make_boxt()\n"
            "    close(b.h)\n    let c = b\n    let n = c.tag\n"
        )

    def test_alias_husk_dropped_ok(self):
        # Aliasing a husk and merely DROPPING the alias (never re-consumed)
        # stays legal, exactly as dropping the husk itself does.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n"
        )

    # ---- husk REASSIGNED to a FRESH value: re-arm must be fully live ----
    # A `var` husk (its linear/typestate field moved out) reassigned to a
    # brand-new value must be tracked as fully live again: the stale moved-out
    # sub-path must NOT survive the fresh re-arm, or a legitimate consume is
    # rejected (false positive) and the fresh value's own leak is masked
    # (soundness). Complement of the alias-carry route.

    def test_reassign_fresh_after_husk_consumed_ok(self):
        # FP face (linear): consuming the reassigned-to-fresh carrier once is
        # legal; the stale `c.h` from the spent husk must not linger.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    close(c.h)\n    c = make_box()\n    sink(c)\n"
        )

    def test_reassign_fresh_after_husk_dropped_rejected(self):
        # Soundness face (linear): dropping the reassigned-to-fresh carrier
        # without consuming leaks the fresh resource and must be rejected,
        # exactly as a plain fresh-drop is.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    close(c.h)\n    c = make_box()\n"
        )

    def test_typestate_reassign_fresh_after_husk_consumed_ok(self):
        # FP face (typestate): same, with a typestate field moved out by
        # projection before the fresh re-arm.
        self._compiles(
            self._TS + "fun sink_rec(consume r: Rec) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    var rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    rec = mkrec()\n    sink_rec(rec)\n"
        )

    def test_typestate_reassign_fresh_after_husk_dropped_rejected(self):
        # Soundness face (typestate): dropping the reassigned-to-fresh carrier
        # leaks and must be rejected.
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    var rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    rec = mkrec()\n"
        )

    def test_reassign_fresh_clears_only_own_subtree(self):
        # Precision: the fresh re-arm of `c` clears only `c.*`, never a sibling
        # husk `cc` (nor the root `c`). Consuming the fresh `c` is accepted,
        # while the untouched sibling husk `cc` still rejects its re-consume, so
        # an over-clear (or a whole-root wipe) cannot pass silently.
        errs = self._errs(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    var cc = make_box()\n    close(c.h)\n    close(cc.h)\n"
            "    c = make_box()\n    sink(c)\n    sink(cc)\n"
        )
        self.assertTrue(any("'cc'" in e for e in errs), errs)
        self.assertFalse(any("consume 'c'" in e for e in errs), errs)


class TestAssignAliasWholeValue(unittest.TestCase):
    """AssignStmt whole-value alias handling (T1 + T2).

    A re-assignment ``t = s`` to an Ident target is the SAME whole-value
    move / re-arm discipline a ``let`` / ``var`` introduction runs, so it
    routes through the ONE ``_linear_transfer_if_alias`` seam. Before this
    fix ``_check_assign`` re-implemented only a partial slice of that seam
    by hand, so on the re-assign path the whole-value obligation MOVE, the
    borrowed propagation, and the target-stale-clear were all missing:

    - T2 (double-frees accepted at --check): aliasing a live linear value
      (``t = s``) left BOTH names independently consumable, so
      ``close(s)`` / ``close(t)`` freed the same value twice. The carrier,
      typestate, chained, if / match-branch, projection, borrowed-launder,
      loop-carried, and consume-both shapes are all the one hole.
    - T1 (false positives): re-assigning a spent-husk target to a fresh
      whole value kept the stale moved-out sub-path, wrongly rejecting a
      later legitimate consume and leaking the fresh value; aliasing a
      borrowed value then only READING it, or a projection then a read of
      the REST, were rejected as leaks because the source obligation was
      never moved.

    The seam moves the whole obligation off an aliased source, re-carries
    the source's moved-out sub-paths onto the target, and propagates a
    borrowed marker; the borrowed-clear on a fresh re-arm is single-sourced
    in that seam's no-op top. A SELF-ASSIGN (``c = c``) stays a no-op re-arm
    that preserves the target's own sub-paths, so a husk ``c = c`` is still
    rejected when the whole husk is later consumed.

    Out of scope (each a SEPARATE class / seam, its own next brief): a
    field-store linear laundering ``s.h = t`` (the FieldAccess-target
    branch, not this Ident-target re-arm), the borrow-read residual, E3
    generic-return aliasing, destructure of a linear carrier, and the
    pre-existing live ``t = t`` self-assign drop FP."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _CARRIER = _LIN + (
        "type Box { h: Handle }\n"
        "fun make_box() -> Box\n"
        "    return Box { h: open() }\n"
        "fun sink(consume b: Box) -> Unit\n"
        "    return ()\n"
    )
    # A carrier whose linear field co-exists with an intact NON-linear
    # field, so a husk still has a readable scalar after the move.
    _BOXT = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n    return ()\n"
        "type BoxT { h: Handle, tag: Int }\n"
        "fun make_boxt() -> BoxT\n    return BoxT { h: open(), tag: 0 }\n"
        "fun sinkt(consume b: BoxT) -> Unit\n    return ()\n"
    )
    # A NON-linear carrier S owning a linear field conn plus a scalar tag.
    _NL = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n    return ()\n"
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n    return S { conn: open(), tag: 0 }\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n    return ()\n"
    )
    _TSCARR = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n    return ()\n"
        "type Rec { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Rec\n"
        "    return Rec { claim: become(mk(), Settled), tag: 0 }\n"
        "fun sink_rec(consume r: Rec) -> Unit\n    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _reject_with(self, body: str, needle: str) -> None:
        """Assert the SPECIFIC diagnostic ``needle`` is reported (C1: a bare
        'some rejection' is GREEN-on-broken for a member main already errors
        on for a spurious reason)."""
        errs = self._errs(body)
        self.assertTrue(any(needle in e for e in errs), errs)

    def _compiles(self, body: str) -> None:
        errs = self._errs(body)
        self.assertEqual(errs, [], errs)

    # ---- T2: double-frees now REJECTED (RED-first, right reason) ----

    def test_m1_bare_alias_double_free_rejected(self):
        # ``t = s`` moves s onto t; consuming the moved-out source rejects.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var s = open()\n    var t = open()\n"
            "    close(t)\n    t = s\n    close(s)\n    close(t)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m2_carrier_alias_double_free_rejected(self):
        self._reject_with(
            self._CARRIER + "fun main(_s: Stdio)\n"
            "    var s = make_box()\n    var t = make_box()\n"
            "    sink(t)\n    t = s\n    sink(s)\n    sink(t)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m3_typestate_alias_double_free_rejected(self):
        self._reject_with(
            self._TS + "fun main(_s: Stdio)\n"
            "    var s = become(mk(), Approved)\n"
            "    var t = become(mk(), Approved)\n"
            "    settle(t)\n    t = s\n    settle(s)\n    settle(t)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m4_chained_alias_double_free_rejected(self):
        # ``t = s; u = t`` chains the alias. C1: main already rejects this for
        # a SPURIOUS reason (``t``/``u`` dropped), masking the double-free, so
        # the test pins the double-free (``was consumed earlier``), which is
        # RED-absent on main and only appears once the move is routed.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var s = open()\n    var t = open()\n    var u = open()\n"
            "    t = s\n    u = t\n"
            "    close(s)\n    close(t)\n    close(u)\n",
            "was consumed earlier and cannot be used again",
        )

    def test_m5a_if_branch_alias_double_free_rejected(self):
        # Alias + consume inside an ``if`` branch; the branch's consume of s
        # unions into _consumed, so the post-if close(s) rejects.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio, cond: Bool)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    if cond\n        t = s\n        close(t)\n"
            "    close(s)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m5a_match_arm_alias_double_free_rejected(self):
        # The match-arm twin of the if-branch member.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio, flag: Bool)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    match flag\n"
            "        true ->\n            t = s\n            close(t)\n"
            "        false -> ()\n"
            "    close(s)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m6_preconsumed_target_consume_both_rejected(self):
        # Target pre-consumed, re-armed from a live source, then both freed.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    t = s\n    close(t)\n    close(s)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_m8_projection_alias_double_free_rejected(self):
        # ``t = s.conn`` moves the field out; re-consuming s.conn rejects.
        self._reject_with(
            self._NL + "fun main(_s: Stdio)\n"
            "    var s = mks()\n    var t = open()\n    close(t)\n"
            "    t = s.conn\n    close(s.conn)\n    close(t)\n",
            "linear value 's.conn' was consumed earlier and cannot be "
            "used again",
        )

    def test_m9_borrowed_launder_rejected(self):
        # ``t = h`` where h is borrowed propagates the borrowed marker; the
        # re-arm keeps it borrowed (Edit B), so close(t) hits the borrow guard.
        self._reject_with(
            self._LIN + "fun bad(h: Handle)\n"
            "    var t = open()\n    close(t)\n    t = h\n    close(t)\n",
            "cannot consume or transfer borrowed linear/typestate value 't'",
        )

    def test_loop_iteration_carried_alias_double_free_rejected(self):
        # The loop body aliases s into t and consumes t each iteration; the
        # two-pass loop analysis flags the re-consume of the moved-out s.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio, cond: Bool)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    while cond\n        t = s\n        close(t)\n"
            "    close(s)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    def test_alias_then_consume_both_rejected(self):
        # The canonical minimal double-free: alias then consume both aliases.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    t = s\n    close(s)\n    close(t)\n",
            "linear value 's' was consumed earlier and cannot be used again",
        )

    # ---- T1: false positives now ACCEPTED ----

    def test_m7_linear_carrier_reassign_over_husk_ok(self):
        # ``close(t.h); t = s; sink(t)``: the spent-husk target's stale t.h is
        # cleared and s moves onto t, so consuming t once is legal.
        self._compiles(
            self._CARRIER + "fun main(_s: Stdio)\n"
            "    var s = make_box()\n    var t = make_box()\n"
            "    close(t.h)\n    t = s\n    sink(t)\n"
        )

    def test_m7_typestate_carrier_reassign_over_husk_ok(self):
        self._compiles(
            self._TSCARR + "fun main(_s: Stdio)\n"
            "    var s = mkrec()\n    var t = mkrec()\n"
            "    let moved = t.claim\n    archive(moved)\n"
            "    t = s\n    sink_rec(t)\n"
        )

    def test_m7_boxt_intact_nonlinear_field_ok(self):
        # Husk target carries an intact non-linear field; re-arm over it and
        # consume the whole fresh value once.
        self._compiles(
            self._BOXT + "fun main(_s: Stdio)\n"
            "    var s = make_boxt()\n    var t = make_boxt()\n"
            "    close(t.h)\n    t = s\n    sinkt(t)\n"
        )

    def test_borrowed_alias_then_read_ok(self):
        # ``t = h`` (h borrowed) then only READING t must not leak: t stays
        # borrowed, the caller retains ownership, nothing is consumed.
        self._compiles(
            self._LIN + "fun peek(h: Handle) -> Int\n    return h.id\n"
            "fun bad(h: Handle)\n"
            "    var t = open()\n    close(t)\n    t = h\n"
            "    let n = peek(t)\n"
        )

    def test_alias_then_consume_alias_only_ok(self):
        # Alias then consume ONLY the alias once: the source moved off, so a
        # single consume of the target is legal (no leak, no double-free).
        self._compiles(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var s = open()\n    var t = open()\n    close(t)\n"
            "    t = s\n    close(t)\n"
        )

    def test_projection_then_use_rest_ok(self):
        # ``t = s.conn`` moves the field out; s becomes a husk whose scalar
        # rest stays readable, and the moved field is owned by t.
        self._compiles(
            self._NL + "fun main(_s: Stdio)\n"
            "    var s = mks()\n    var t = open()\n    close(t)\n"
            "    t = s.conn\n    close(t)\n    let n = s.tag\n"
        )

    def test_fresh_reassign_of_previously_borrowed_ok(self):
        # A name made borrowed by ``t = h`` then re-armed to a FRESH value
        # clears the stale borrow (single-sourced in the seam's no-op top) and
        # is owned again, so the final consume discharges it.
        self._compiles(
            self._LIN + "fun use(h: Handle)\n"
            "    var t = open()\n    close(t)\n    t = h\n"
            "    t = open()\n    close(t)\n"
        )

    # ---- boundary: stay-accepted / stay-rejected negatives ----

    def test_neg_rearm_after_consume_ok(self):
        self._compiles(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var h = open()\n    close(h)\n    h = open()\n    close(h)\n"
        )

    def test_neg_chained_fresh_rearm_ok(self):
        # Repeated fresh re-arm of the same name (no aliasing) stays legal.
        self._compiles(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var h = open()\n    close(h)\n    h = open()\n    close(h)\n"
            "    h = open()\n    close(h)\n"
        )

    def test_neg_live_value_drop_stays_rejected(self):
        # Re-assigning over a LIVE value drops it: an honest leak, unchanged.
        self._reject_with(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var h = open()\n    h = open()\n    close(h)\n",
            "linear value 'h' is dropped without being consumed; "
            "re-assigning to it overwrites the old value",
        )

    def test_neg_husk_self_assign_stays_rejected(self):
        # ``c = c`` on a spent husk is a no-op re-arm that PRESERVES c.h, so
        # consuming the whole husk still double-frees the moved-out field.
        self._reject_with(
            self._CARRIER + "fun main(_s: Stdio)\n"
            "    var c = make_box()\n    close(c.h)\n    c = c\n    sink(c)\n",
            "cannot consume 'c': its field 'c.h' was already consumed",
        )


if __name__ == "__main__":
    unittest.main()
