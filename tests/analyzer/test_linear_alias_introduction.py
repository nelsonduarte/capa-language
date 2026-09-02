"""Analyzer tests: the ALIAS-INTRODUCTION class on the linear discipline.

A rule that enforces "used at most once" must first RESOLVE its operand to a
place. Every such rule recognised exactly two spellings -- a bare ``Ident`` and
an ``Ident``-rooted ``FieldAccess`` -- while the language has two further ways
to name an existing value, and they compose:

* BINDING: a pattern binds a name to a value the analyzer already tracks (a
  ``match`` arm binder, a destructuring ``let``);
* SELECTION: an ``if`` / ``match`` EXPRESSION yields an existing place without
  ever naming it.

Both were invisible to every position-driven rule while the value still flowed
at runtime, so the direct spelling of a double-free was rejected and the alias
spelling of the SAME program was accepted.

The fix records two binding-time facts, each with exactly one producer
(``_linear_alias`` from ``_linear_bind_pattern_view``, ``_selection_place``
from the two selection checkers), and feeds them to ``_path_of``, the ONE
resolver every position-driven rule already calls. The rules inherit together
rather than each growing its own case.

The five position-driven rules, and what each test class here pins:

* R1 ``_move_linear_operand``, 11 operand positions -- ``TestSelectionMoves``,
  ``TestBinderMoves``;
* R2/R3, the capability discipline -- NOT touched by this release;
  ``TestCapabilityNeutral`` pins that;
* R4 ``_linear_check_borrowed_escape``, 5 aggregate-pack sites --
  ``TestBorrowedEscapePack``;
* R5 ``_linear_transfer_if_alias``'s borrowed PROPAGATION, 4 bind sites --
  ``TestBorrowedPropagation``.

``TestNoLaunderedSpelling`` is the connection test: it asserts that a direct
spelling and its two alias spellings AGREE at every position, which is the one
assertion that catches a new rule added without resolving through ``_path_of``.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


# ---------------------------------------------------------------- preludes

# A bare linear resource, a carrier that owns one, and a typestate facet.
_LIN = (
    "linear type Conn { id: Int }\n"
    "fun open() -> Conn\n"
    "    return Conn { id: 1 }\n"
    "fun close(consume c: Conn) -> Unit\n"
    "    return ()\n"
)
# The carrier and typestate-carrier declarations are kept as ADDITIONS to
# _LIN rather than as self-contained preludes, so a test that needs both can
# concatenate them without re-declaring Conn.
_CARRIER_DECLS = (
    "type Holder { c: Conn, tag: Int }\n"
    "fun mkh() -> Holder\n"
    "    return Holder { c: open(), tag: 0 }\n"
    "fun sink(consume h: Holder) -> Unit\n"
    "    close(h.c)\n"
    "    return ()\n"
)
_TSC_DECLS = (
    "typestate Sess { c: Conn }\n    Open\n    Shut\n"
    "fun mks() -> Sess[Open]\n"
    "    return Sess[Open] { c: open() }\n"
    "fun sinkt(consume x: Sess[Open]) -> Unit\n"
    "    close(x.c)\n"
    "    return ()\n"
)
_CARRIER = _LIN + _CARRIER_DECLS
_TSC = _LIN + _TSC_DECLS
_BOTH = _LIN + _CARRIER_DECLS + _TSC_DECLS
_TS = (
    "typestate Auth\n    Pending\n    Settled\n"
    "fun mk() -> Auth[Pending]\n"
    "    return Auth[Pending] {}\n"
    "fun settle(consume a: Auth[Pending]) -> Unit\n"
    "    return ()\n"
)
# A USER-DECLARED capability, for the neutrality checks: a built-in one
# cannot appear in a return type, so the selection-return shape needs this.
_UCAP = (
    "capability Notify\n"
    "    fun ping(self) -> Int\n"
    "type Bell { tone: Int }\n"
    "impl Notify for Bell\n"
    "    fun ping(self) -> Int\n"
    "        return self.tone\n"
)


def _errs(body: str) -> list[str]:
    """Errors, minus the unrelated unused-binding note."""
    return [e for e in errors_of(body) if "never used" not in e]


class _Base(unittest.TestCase):
    def assertRejects(self, body: str, needle: str = "") -> None:
        errs = _errs(body)
        self.assertTrue(errs, "expected a rejection, got none")
        if needle:
            self.assertTrue(
                any(needle in e for e in errs),
                f"expected {needle!r} among {errs}",
            )

    def assertAccepts(self, body: str) -> None:
        errs = _errs(body)
        self.assertEqual(errs, [], errs)

    def assertSameVerdict(self, *bodies: str) -> None:
        """Two spellings of ONE program must agree. A direct spelling that
        rejects while an alias spelling of the same program is accepted is a
        LAUNDERED rule at that position, which is the whole defect class."""
        verdicts = [bool(_errs(b)) for b in bodies]
        self.assertEqual(
            len(set(verdicts)), 1,
            "spellings disagree: rejected=%r" % (verdicts,),
        )


# ---------------------------------------------------------------- SPELLINGS
#
# The three ways to name an existing place ``x``. Every position test below
# substitutes all three into ONE program template, so a rule that resolves
# only the direct spelling shows up as a disagreement rather than as a
# hand-written expectation that could be wrong.

def direct(x: str) -> str:
    return x


def select(x: str) -> str:
    return f"(if true then {x} else {x})"


def binder(x: str) -> str:
    return f"(match 0 {{ _ -> {x} }})"


SPELLINGS = (direct, select, binder)


class TestSelectionMoves(_Base):
    """Family S: a SELECTION (``if`` / ``match`` EXPRESSION) hands over an
    existing place without naming it, at each of R1's move positions."""

    def test_s1_consume_argument_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    close({spell('a')})\n    close(a)\n"
                )

    def test_s1_let_rhs_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    let d = {spell('a')}\n    close(d)\n    close(a)\n"
                )

    def test_s1_var_rhs_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    var d = {spell('a')}\n    close(d)\n    close(a)\n"
                )

    def test_s1_struct_literal_pack_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _CARRIER + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    let h = Holder {{ c: {spell('a')}, tag: 0 }}\n"
                    "    sink(h)\n    close(a)\n"
                )

    def test_s1_typestate_literal_pack_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _TSC + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    let x = Sess[Open] {{ c: {spell('a')} }}\n"
                    "    sinkt(x)\n    close(a)\n"
                )

    def test_s1_return_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun give(consume a: Conn) -> Conn\n"
                    f"    close(a)\n    return {spell('a')}\n"
                )

    def test_s1_become_rejects_reuse(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _TS + "fun main(_s: Stdio)\n    let a = mk()\n"
                    f"    let b = become({spell('a')}, Settled)\n"
                    "    settle(a)\n    let _ = b\n"
                )

    def test_s2_field_projected_off_a_selection(self):
        # ``(if c then h else h).c`` is an ordinary field path once the
        # selection resolves, at ANY chain depth.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
                    f"    close({spell('h')}.c)\n    close(h.c)\n"
                )

    def test_s3_selection_over_a_spent_husk(self):
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    close(h.c)\n"
            "    sink(if true then h else h)\n"
        )

    def test_s4_selection_of_distinct_places_rejects_specifically(self):
        # Two DIFFERENT places: one branch necessarily leaks, so the
        # selection fails closed with its OWN wording rather than a generic
        # leak report. The specific wording is what mutation M1 bites on.
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n"
            "    let a = open()\n    let b = open()\n"
            "    let t = if true then a else b\n    close(t)\n",
            "selected through a conditional / match expression",
        )

    def test_s5_selection_mixing_a_place_and_a_fresh_value(self):
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n"
            "    let a = open()\n"
            "    let t = if true then a else open()\n    close(t)\n",
            "selected through a conditional / match expression",
        )

    # ---- negatives: legitimate selections stay ACCEPTED ----

    def test_s7_fresh_factory_selection_accepted(self):
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n"
            "    let t = if true then open() else open()\n    close(t)\n"
        )

    def test_b1_same_place_selection_consumed_once_accepted(self):
        # Blessing B-1: both arms hand over the SAME value and it is
        # consumed exactly once, so nothing doubles and nothing leaks.
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    close(if true then a else a)\n"
        )

    def test_b1_nested_same_place_selection_accepted(self):
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let t = if true then a else (if false then a else a)\n"
            "    close(t)\n"
        )

    def test_b2_merely_reading_through_a_selection_accepted(self):
        # Blessing B-2: a READ is not a move.
        self.assertAccepts(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    let n = (if true then h else h).tag\n"
            "    close(h.c)\n    let _ = n\n"
        )

    def test_non_linear_selection_untouched(self):
        self.assertAccepts(
            "fun verdict(live: Bool) -> String\n"
            "    return if live then \"yes\" else \"no\"\n"
        )


class TestBinderMoves(_Base):
    """Family P: a pattern BINDING introduces an alias the move positions
    could not see. The obligation stays under the scrutinee's name; the
    binder resolves to it through ``_path_of``."""

    def test_p1_match_arm_binder_then_reuse_scrutinee(self):
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    match 0\n        _ -> close(a)\n"
            "    close(a)\n"
        )

    def test_p1_binder_consumed_then_scrutinee_reused(self):
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let t = match 0\n        _ -> a\n"
            "    close(t)\n    close(a)\n"
        )

    def test_p2_carrier_facet_through_a_binder(self):
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    let t = match 0\n        _ -> h\n"
            "    close(t.c)\n    sink(h)\n"
        )

    def test_p4_typestate_facet_through_a_binder(self):
        self.assertRejects(
            _TS + "fun main(_s: Stdio)\n    let a = mk()\n"
            "    let t = match 0\n        _ -> a\n"
            "    settle(t)\n    settle(a)\n"
        )

    def test_p5_binder_packed_into_a_struct_literal(self):
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let t = match 0\n        _ -> a\n"
            "    let h = Holder { c: t, tag: 0 }\n"
            "    sink(h)\n    close(a)\n"
        )

    def test_p9_struct_pattern_destructuring_let(self):
        # ``let Holder { c: inner, tag: t } = h`` is the projection
        # ``let inner = h.c`` per field, so it MOVES the field out of the
        # carrier and the carrier can no longer consume it a second time.
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    let Holder { c: inner, tag: t } = h\n"
            "    close(inner)\n    sink(h)\n    let _ = t\n"
        )

    def test_p14_unresolvable_binder_fails_closed(self):
        # An or-pattern binder cannot be resolved to a single owner, so it
        # is rejected fail-closed rather than silently tracked as fresh.
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let t = match 0\n        0 | 1 -> a\n        _ -> a\n"
            "    close(t)\n    close(a)\n"
        )

    # ---- negatives ----

    def test_p10_struct_pattern_with_no_reuse_accepted(self):
        # The destructure moves the field out; consuming it once and NOT
        # re-consuming through the carrier is correct.
        self.assertAccepts(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    let Holder { c: inner, tag: t } = h\n"
            "    close(inner)\n    let _ = t\n"
        )

    def test_p12_binder_consumed_nothing_reused_accepted(self):
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    match 0\n        _ -> close(a)\n"
        )

    def test_p12_binder_via_let_consumed_once_accepted(self):
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let t = match 0\n        _ -> a\n"
            "    close(t)\n"
        )

    def test_no_stale_alias_between_two_matches(self):
        # Two matches sharing a binder NAME must not leak an alias from the
        # first into the second: the fact is saved and restored around each
        # arm exactly like the arm's own name scope.
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n"
            "    let a = open()\n    let b = open()\n"
            "    let x = match 0\n        _ -> a\n"
            "    let y = match 0\n        _ -> b\n"
            "    close(x)\n    close(y)\n"
        )

    def test_match_on_a_fresh_scrutinee_accepted(self):
        self.assertAccepts(
            _LIN + "fun main(_s: Stdio)\n"
            "    let t = match 0\n        _ -> open()\n"
            "    close(t)\n"
        )


class TestBorrowedEscapePack(_Base):
    """R4, ``_linear_check_borrowed_escape``, at the aggregate-PACK sites.

    A BORROWED single-use value packed into an aggregate escapes the callee
    while the caller still owns it. The rule tested syntactically, so both
    alias spellings laundered it at every pack site, and the ordering matters:
    the check must run AFTER the operand is typed or a selection has no
    recorded place yet.
    """

    _B = _BOTH

    def test_r4_struct_literal_field(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    self._B + "fun escape(c: Conn) -> Unit\n"
                    f"    let h = Holder {{ c: {spell('c')}, tag: 0 }}\n"
                    "    sink(h)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r4_typestate_literal_field(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    self._B + "fun escape(c: Conn) -> Unit\n"
                    f"    let x = Sess[Open] {{ c: {spell('c')} }}\n"
                    "    sinkt(x)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r4_field_store_rhs(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    self._B + "fun escape(c: Conn) -> Unit\n"
                    "    var h = mkh()\n"
                    f"    h.c = {spell('c')}\n"
                    "    sink(h)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r4_controls_keep_the_original_wording(self):
        # The DIRECT spelling's diagnostic must not change: increment B8 adds
        # resolution, not a new message.
        errs = _errs(
            self._B + "fun escape(c: Conn) -> Unit\n"
            "    let h = Holder { c: c, tag: 0 }\n"
            "    sink(h)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n"
        )
        self.assertTrue(
            any("cannot pack borrowed linear/typestate value" in e
                and "the caller retains" in e for e in errs), errs)

    def test_r4_owned_pack_still_accepted(self):
        # A pack of an OWNED value is the ordinary move; it must stay legal.
        self.assertAccepts(
            self._B + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let h = Holder { c: a, tag: 0 }\n    sink(h)\n"
        )

    def test_r4_masked_container_sites_reject_in_every_spelling(self):
        # The tuple- and list-literal pack sites are left spelling-sensitive
        # deliberately, because the container-of-linear bar rejects a
        # single-use element there in EVERY spelling. If that bar ever
        # relaxes, this test is what notices the hole opening.
        for spell in SPELLINGS:
            for lit in ("({X}, 0)", "[{X}]"):
                shape = lit.replace("{X}", spell("c"))
                with self.subTest(spelling=spell.__name__, lit=lit):
                    self.assertRejects(
                        self._B + "fun escape(c: Conn) -> Unit\n"
                        f"    let t = {shape}\n"
                        "    let _ = t\n    return ()\n"
                        "fun main(_s: Stdio)\n    let a = open()\n"
                        "    escape(a)\n    close(a)\n"
                    )


class TestBorrowedPropagation(_Base):
    """R5, the borrowed PROPAGATION half of ``_linear_transfer_if_alias``.

    Whether a ``let`` / ``var`` / assign TARGET inherits the BORROWED marker
    was decided syntactically -- on ``isinstance(value, Ident)`` and
    ``value.name``. For a borrowed source the move seam is a no-op (there is
    no obligation to move), so an alias spelling reached the bind with no
    marker and the target was armed as a FRESH OWNER: the caller's
    still-owned value laundered into a second obligation.

    This is the rule the release's own aggregate-escape increment DEPENDS on:
    ``blet_then_pack`` loses the marker one statement before the pack site,
    so the escape rule sees a name that is no longer borrowed.
    """

    def test_r5_let_rhs(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun escape(c: Conn) -> Unit\n"
                    f"    let d = {spell('c')}\n"
                    "    close(d)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r5_var_rhs(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun escape(c: Conn) -> Unit\n"
                    f"    var d = {spell('c')}\n"
                    "    close(d)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r5_assign_rhs(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun escape(c: Conn, o: Conn) -> Unit\n"
                    "    var d = o\n"
                    f"    d = {spell('c')}\n"
                    "    close(d)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    let b = open()\n"
                    "    escape(a, b)\n    close(a)\n    close(b)\n",
                    "borrowed",
                )

    def test_r5_alias_chain(self):
        # The marker must survive a CHAIN of aliases, not just one hop.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun escape(c: Conn) -> Unit\n"
                    f"    let d = {spell('c')}\n"
                    "    let e = d\n"
                    "    close(e)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r5_alias_then_pack_defeats_the_escape_rule(self):
        # THE interaction: losing the marker at the bind defeats R4 one
        # statement later, because R4 then sees a name that is not borrowed.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _CARRIER + "fun escape(c: Conn) -> Unit\n"
                    f"    let d = {spell('c')}\n"
                    "    let h = Holder { c: d, tag: 0 }\n"
                    "    sink(h)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    escape(a)\n    close(a)\n",
                    "borrowed",
                )

    def test_r5_typestate_facet(self):
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _TS + "fun escape(a: Auth[Pending]) -> Unit\n"
                    f"    let d = {spell('a')}\n"
                    "    settle(d)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let x = mk()\n"
                    "    escape(x)\n    settle(x)\n",
                    "borrowed",
                )

    def test_r5_carrier_facet(self):
        # Open on main as well: aliasing a borrowed CARRIER through a
        # selection and then consuming its field.
        for spell in (select, binder):
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _CARRIER + "fun escape(h: Holder) -> Unit\n"
                    f"    let d = {spell('h')}\n"
                    "    close(d.c)\n    return ()\n"
                    "fun main(_s: Stdio)\n    let x = mkh()\n"
                    "    escape(x)\n    sink(x)\n"
                )

    # ---- negatives: the propagation must not over-reject ----

    def test_r5_reading_a_borrowed_alias_accepted(self):
        # Merely READING through the alias is not a move. Rejecting this was
        # a false alarm the release still had before the propagation was
        # decided on the resolved place.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertAccepts(
                    _LIN + "fun peek(c: Conn) -> Int\n"
                    f"    let d = {spell('c')}\n"
                    "    return d.id\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    let _n = peek(a)\n    close(a)\n"
                )

    def test_r5_reborrowing_through_an_alias_accepted(self):
        # Passing the alias to ANOTHER borrower is legal: nothing is moved.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertAccepts(
                    _LIN + "fun peek2(c: Conn) -> Int\n"
                    "    return c.id\n"
                    "fun peek(c: Conn) -> Int\n"
                    f"    let d = {spell('c')}\n"
                    "    return peek2(d)\n"
                    "fun main(_s: Stdio)\n    let a = open()\n"
                    "    let _n = peek(a)\n    close(a)\n"
                )

    def test_r5_owned_alias_consumed_once_accepted(self):
        # An OWNED source aliased through a selection and consumed once is
        # correct; the propagation must not mark it borrowed.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertAccepts(
                    _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    let d = {spell('a')}\n"
                    "    close(d)\n"
                )

    def test_r5_owned_alias_left_unconsumed_still_leaks(self):
        # The mirror of the test above: the propagation must not turn an
        # OWNED alias into a borrowed one, which would swallow the leak.
        for spell in SPELLINGS:
            with self.subTest(spelling=spell.__name__):
                self.assertRejects(
                    _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
                    f"    let d = {spell('a')}\n"
                    "    let _ = d.id\n"
                )

    def test_r5_borrowed_field_projection_unchanged(self):
        # A borrowed FIELD projected into a name was already handled; it must
        # keep its behaviour and its wording.
        self.assertRejects(
            _CARRIER + "fun escape(h: Holder) -> Unit\n"
            "    let d = h.c\n"
            "    close(d)\n    return ()\n"
            "fun main(_s: Stdio)\n    let x = mkh()\n"
            "    escape(x)\n    sink(x)\n"
        )


class TestLambdaResultTransfer(_Base):
    """Family L: a lambda's RESULT hands the value to whoever invokes the
    closure, so it is a transfer position exactly as ``return`` is. Both
    body spellings must agree."""

    _L = _LIN + "fun apply(f: Fun() -> Conn) -> Conn\n    return f()\n"

    def test_l1_expression_body_capture_launder(self):
        self.assertRejects(
            self._L + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let g = fun () -> Conn => a\n"
            "    close(apply(g))\n    close(a)\n"
        )

    def test_l3_block_body_capture_launder(self):
        self.assertRejects(
            self._L + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let g = fun () -> Conn =>\n        return a\n"
            "    close(apply(g))\n    close(a)\n"
        )

    def test_l1_l3_the_two_spellings_agree(self):
        self.assertSameVerdict(
            self._L + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let g = fun () -> Conn => a\n"
            "    close(apply(g))\n    close(a)\n",
            self._L + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let g = fun () -> Conn =>\n        return a\n"
            "    close(apply(g))\n    close(a)\n",
        )

    def test_l2_capture_wrapped_in_a_selection(self):
        self.assertRejects(
            self._L + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let g = fun () -> Conn => (if true then a else a)\n"
            "    close(apply(g))\n    close(a)\n"
        )

    def test_fresh_factory_lambda_accepted(self):
        self.assertAccepts(
            self._L + "fun main(_s: Stdio)\n"
            "    let g = fun () -> Conn => open()\n"
            "    close(apply(g))\n"
        )


class TestBranchMerge(_Base):
    """The alias facts must not disturb the intersection merge: a PARTIAL
    consume across branches still leaks, a FULL consume through an alias is
    correctly discharged, and a reuse after it is still caught."""

    def test_partial_consume_across_arms_still_leaks(self):
        self.assertRejects(
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    match 0\n        0 -> close(a)\n        _ -> ()\n"
        )

    def test_full_consume_through_a_view_on_both_arms_accepted(self):
        self.assertAccepts(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    match 0\n"
            "        0 -> close(h.c)\n"
            "        _ -> close(h.c)\n"
        )

    def test_reuse_after_a_full_consume_through_a_view_rejected(self):
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    match 0\n"
            "        0 -> close(h.c)\n"
            "        _ -> close(h.c)\n"
            "    close(h.c)\n"
        )

    def test_partial_field_consume_through_a_view_still_leaks(self):
        self.assertRejects(
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    match 0\n"
            "        0 -> close(h.c)\n"
            "        _ -> ()\n"
        )


class TestCapabilityNeutral(_Base):
    """This release changes the LINEAR discipline only. The capability
    discipline (must-not-use-after-consume) must be exactly where it was:
    the capability twin of this fix is a separate piece of work, and these
    shapes are its members, deliberately left open here."""

    _C = (
        "fun adopt(consume s: Stdio) -> Unit\n"
        "    return ()\n"
    )

    def test_direct_capability_use_after_consume_still_rejected(self):
        self.assertRejects(
            self._C + "fun main(s: Stdio)\n"
            "    adopt(s)\n    s.println(\"after\")\n",
            "consumed earlier",
        )

    def test_capability_binder_is_not_newly_rejected(self):
        # A capability bound by a match arm binder: accepted before this
        # release and still accepted. If this starts rejecting, the linear
        # facts have reached a discipline they are not meant to touch.
        self.assertAccepts(
            "fun main(s: Stdio)\n"
            "    match 0\n        _ -> s.println(\"x\")\n"
        )

    def test_capability_selection_return_is_not_newly_rejected(self):
        # Returning one of two USER-DECLARED capability values through a
        # selection is correct and is accepted today. If this starts
        # rejecting, the linear fail-closed policy has been applied to a
        # discipline whose rule is must-not-use-after-consume, where a
        # `return` is not a consume and nothing needs to fail closed.
        self.assertAccepts(
            _UCAP + "fun pick(a: Bell, b: Bell, flag: Bool) -> Bell\n"
            "    return if flag then a else b\n"
        )


class TestNoLaunderedSpelling(_Base):
    """THE connection test. For every operand POSITION, the direct spelling
    and its two alias spellings must reach the SAME verdict.

    This is the assertion that catches a position-driven rule added, or
    edited, without resolving through ``_path_of``: such a rule rejects the
    direct spelling and accepts the alias, and every defect in this class
    found across three review rounds had exactly that signature. A
    hand-written per-position expectation would not, because the expectation
    itself would have to be guessed right.
    """

    # (name, template with {X} for the operand spelling). Half carry an
    # OWNED value being reused, half a BORROWED one escaping.
    POSITIONS = {
        "consume_arg": (
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    close({X})\n    close(a)\n", "a"),
        "let_rhs": (
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let d = {X}\n    close(d)\n    close(a)\n", "a"),
        "var_rhs": (
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    var d = {X}\n    close(d)\n    close(a)\n", "a"),
        "structlit": (
            _CARRIER + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let h = Holder { c: {X}, tag: 0 }\n"
            "    sink(h)\n    close(a)\n", "a"),
        "typestatelit": (
            _TSC + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let x = Sess[Open] { c: {X} }\n"
            "    sinkt(x)\n    close(a)\n", "a"),
        "fieldstore_rhs": (
            _CARRIER + "fun main(_s: Stdio)\n    let a = open()\n"
            "    var h = mkh()\n    close(h.c)\n"
            "    h.c = {X}\n    sink(h)\n    close(a)\n", "a"),
        "return": (
            _LIN + "fun give(consume a: Conn) -> Conn\n"
            "    close(a)\n    return {X}\n", "a"),
        "become": (
            _TS + "fun main(_s: Stdio)\n    let a = mk()\n"
            "    let b = become({X}, Settled)\n"
            "    settle(a)\n    let _ = b\n", "a"),
        "field_projection": (
            _CARRIER + "fun main(_s: Stdio)\n    let h = mkh()\n"
            "    close({X}.c)\n    close(h.c)\n", "h"),
        "anon_drop": (
            _LIN + "fun main(_s: Stdio)\n    let a = open()\n"
            "    let _ = {X}\n    close(a)\n", "a"),
        # ---- borrowed positions: the value escapes the callee ----
        "b_let_rhs": (
            _LIN + "fun escape(c: Conn) -> Unit\n"
            "    let d = {X}\n    close(d)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_var_rhs": (
            _LIN + "fun escape(c: Conn) -> Unit\n"
            "    var d = {X}\n    close(d)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_structlit": (
            _CARRIER + "fun escape(c: Conn) -> Unit\n"
            "    let h = Holder { c: {X}, tag: 0 }\n"
            "    sink(h)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_typestatelit": (
            _TSC + "fun escape(c: Conn) -> Unit\n"
            "    let x = Sess[Open] { c: {X} }\n"
            "    sinkt(x)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_fieldstore_rhs": (
            _CARRIER + "fun escape(c: Conn) -> Unit\n"
            "    var h = mkh()\n    close(h.c)\n"
            "    h.c = {X}\n    sink(h)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_return": (
            _LIN + "fun escape(c: Conn) -> Conn\n"
            "    return {X}\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    close(escape(a))\n    close(a)\n", "c"),
        "b_consume_arg": (
            _LIN + "fun escape(c: Conn) -> Unit\n"
            "    close({X})\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_alias_then_pack": (
            _CARRIER + "fun escape(c: Conn) -> Unit\n"
            "    let d = {X}\n"
            "    let h = Holder { c: d, tag: 0 }\n"
            "    sink(h)\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_tuplelit": (
            _LIN + "fun escape(c: Conn) -> Unit\n"
            "    let t = ({X}, 0)\n    let _ = t\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
        "b_listlit": (
            _LIN + "fun escape(c: Conn) -> Unit\n"
            "    let t = [{X}]\n    let _ = t\n    return ()\n"
            "fun main(_s: Stdio)\n    let a = open()\n"
            "    escape(a)\n    close(a)\n", "c"),
    }

    def test_no_position_is_laundered_by_an_alias_spelling(self):
        laundered = []
        for name, (tmpl, operand) in sorted(self.POSITIONS.items()):
            verdicts = {}
            for spell in SPELLINGS:
                body = tmpl.replace("{X}", spell(operand))
                verdicts[spell.__name__] = bool(_errs(body))
            with self.subTest(position=name):
                self.assertEqual(
                    len(set(verdicts.values())), 1,
                    f"{name}: spellings disagree {verdicts}",
                )
            if len(set(verdicts.values())) != 1:
                laundered.append(name)
        self.assertEqual(laundered, [], f"laundered positions: {laundered}")

    def test_every_position_parses_in_every_spelling(self):
        # A cell that is silently a parse error tests nothing, so the
        # differencing above would report agreement for the wrong reason.
        for name, (tmpl, operand) in sorted(self.POSITIONS.items()):
            for spell in SPELLINGS:
                body = tmpl.replace("{X}", spell(operand))
                with self.subTest(position=name, spelling=spell.__name__):
                    msgs = errors_of(body)
                    self.assertFalse(
                        any("parse" in m.lower() or "expected" in m.lower()
                            for m in msgs),
                        f"{name}/{spell.__name__} does not parse: {msgs}",
                    )


if __name__ == "__main__":
    unittest.main()
