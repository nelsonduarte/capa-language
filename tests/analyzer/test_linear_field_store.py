"""Analyzer tests: the ``s.h = t`` field-store into a linear/typestate LEAF.

Split out of tests/analyzer/test_linear_obligation.py (which crossed the
~1800-line growth trigger; see tests/analyzer/__init__.py) along the named
field-store-laundering seam. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.

A store into a bare-linear/typestate LEAF field routes its RHS through the
SAME ``_move_linear_operand`` move seam the struct-literal pack uses and
re-arms the stored-into place through the single ``_moved_subpath_sets``
source. One root omission (the field-store never moved its RHS and its inline
re-arm skipped ``_linear_field_moved`` and never re-added the carrier root to
the live set) was three-faced:

- Face A -- double-free (was ACCEPTED): the laundered RHS is now discharged,
  so a later consume of it is a use-after-move.
- Face B -- false-positive leak (was REJECTED): the RHS is moved into the
  field, so it is no longer reported dropped at scope exit.
- Face C -- missed leak (was ACCEPTED): re-arming re-opens the carrier root's
  obligation, so a re-stored-then-dropped field now leaks.

Also: a borrowed RHS is rejected with the struct-literal pack wording, and a
field-to-field owned move (``s.conn = a.conn``) turns the source into a husk.

OUT OF SCOPE (separate mechanisms, unchanged here): the carrier-typed TARGET
field ``o.inner = a`` (the target is itself a carrier, not a bare leaf, so the
``_linear_place`` gate excludes it -- its own next increment), an Index
target/receiver, a degenerate self-field-store ``s.conn = s.conn``, the
borrow-read residual, and E3 generic-return aliasing.

Analyzer-only, reject/accept decisions only; the accepted shapes are run
byte-identically on all three backends by test_ir_wasm_parity.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


class TestFieldStoreLinearAlias(unittest.TestCase):
    # NON-linear carrier S owning one linear field conn + a scalar tag.
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
    # Typestate facet: a Claim leaf inside a non-linear Record carrier.
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
    # A NESTED carrier: the target leaf is o.inner.conn (nested receiver).
    _NEST = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "type Inner { conn: Conn, tag: Int }\n"
        "type Outer { inner: Inner, tag: Int }\n"
        "fun mko() -> Outer\n"
        "    return Outer { inner: Inner { conn: open(), tag: 0 }, tag: 0 }\n"
        "fun sinko(consume o: Outer) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    # ---- Face A: double-free (laundered RHS re-consumed) -> REJECT ----

    def test_face_a_field_consume_twin_rejected(self):
        # close(s.conn); s.conn = t; close(s.conn); close(t): the final
        # close(t) is a use-after-move because t was moved into the field.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    let t = open()\n    close(s.conn)\n    s.conn = t\n"
            "    close(s.conn)\n    close(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_face_a_whole_consume_twin_rejected(self):
        # close(s.conn); s.conn = t; sink(s); close(t): sink consumes the
        # re-armed carrier and close(t) is the use-after-move of t.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    let t = open()\n    close(s.conn)\n    s.conn = t\n"
            "    sink(s)\n    close(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- Face B: false-positive leak of a moved RHS -> ACCEPT ----

    def test_face_b_moved_rhs_not_reported_dropped_ok(self):
        # The RHS t is moved into s.conn, so it must NOT be reported dropped
        # at scope exit (the carrier is consumed via sink). It already errors
        # on main for the wrong reason ('t' dropped), so a bare pass here
        # would be theatre -- assert .ok.
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    let t = open()\n    s.conn = t\n"
            "    sink(s)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertFalse(
            any("'t'" in e and "dropped" in e for e in self._errs(
                self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
                "    close(s.conn)\n    let t = open()\n    s.conn = t\n"
                "    sink(s)\n"
            )),
        )

    # ---- Face C: missed leak of a re-stored-then-dropped field -> REJECT ----

    def test_face_c_restore_then_drop_leaks_carrier(self):
        # close(s.conn); s.conn = open(): the carrier is re-armed and then
        # dropped, so it leaks the fresh value.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n"
        )
        self.assertTrue(
            any("'s'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_face_c_partial_restore_then_drop_leaks_field(self):
        # Two linear fields, one restored then dropped: the restored field
        # leaks by path while the other stays discharged (partial move).
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    var p = mkp()\n"
            "    close(p.a)\n    close(p.b)\n    p.a = open()\n"
        )
        self.assertTrue(
            any("'p.a'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    # ---- member 5: nested LEAF target o.inner.conn = t ----

    def test_nested_leaf_face_a_rejected(self):
        errs = self._errs(
            self._NEST + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    let t = open()\n    close(o.inner.conn)\n"
            "    o.inner.conn = t\n    close(o.inner.conn)\n    close(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_nested_leaf_face_c_leaks_root(self):
        errs = self._errs(
            self._NEST + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner.conn = open()\n"
        )
        self.assertTrue(
            any("'o'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    # ---- member 6: typestate LEAF target r.claim = t ----

    def test_typestate_leaf_face_a_rejected(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    var r = mkrec()\n"
            "    let t = become(mk(), Settled)\n    archive(r.claim)\n"
            "    r.claim = t\n    archive(r.claim)\n    archive(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_typestate_leaf_face_c_leaks_root(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    var r = mkrec()\n"
            "    archive(r.claim)\n    r.claim = become(mk(), Settled)\n"
        )
        self.assertTrue(
            any("'r'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    # ---- member 7: store inside an if branch AND a match arm ----

    def test_face_a_inside_if_branch_rejected(self):
        # The clean in-branch form: the THEN close(t) rejects; the ELSE
        # consumes s.conn and t so the merge is husk-free.
        errs = self._errs(
            self._NL + "fun run(cond: Bool) -> Unit\n"
            "    var s = mks()\n    let t = open()\n    if cond\n"
            "        close(s.conn)\n        s.conn = t\n"
            "        close(s.conn)\n        close(t)\n    else\n"
            "        close(s.conn)\n        close(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_face_a_inside_match_arm_rejected(self):
        errs = self._errs(
            self._NL + "fun run(cond: Bool) -> Unit\n"
            "    var s = mks()\n    let t = open()\n    match cond\n"
            "        true ->\n            close(s.conn)\n"
            "            s.conn = t\n            close(s.conn)\n"
            "            close(t)\n        false ->\n"
            "            close(s.conn)\n            close(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- member 8: F10 borrowed RHS launder -> REJECT (pack wording) ----

    def test_f10_borrowed_ident_rhs_rejected(self):
        errs = self._errs(
            self._NL + "fun launder(h: Conn) -> Unit\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = h\n    close(s.conn)\n"
        )
        self.assertTrue(
            any("cannot pack borrowed" in e and "'h'" in e for e in errs),
            errs,
        )

    def test_f10_borrowed_field_rhs_rejected(self):
        errs = self._errs(
            self._NL + "fun launder(a: S) -> Unit\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = a.conn\n    close(s.conn)\n"
        )
        self.assertTrue(
            any("belongs to a borrowed value" in e and "'a.conn'" in e
                for e in errs),
            errs,
        )

    # ---- member 9: field-to-field OWNED move -> ACCEPT (source becomes husk) ----

    def test_field_to_field_owned_move_ok(self):
        # s.conn = a.conn moves a.conn out (a becomes a husk, its scalar
        # a.tag still readable). It errors on main for the wrong reason
        # ('a' dropped), so assert .ok, not a bare pass.
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    var a = mks()\n    close(s.conn)\n    s.conn = a.conn\n"
            "    close(s.conn)\n    let n = a.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- connection: overwrite a LIVE field emits EXACTLY ONE diagnostic ----

    def test_overwrite_live_field_exactly_one_diagnostic(self):
        # FRESH-RHS overwrite of a live field: exactly one diagnostic (the
        # overwrite leak). An aliased RHS would legitimately give two.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    s.conn = open()\n    let c = s.conn\n    close(c)\n"
        )
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("'s.conn' is overwritten without being consumed", errs[0])

    # ---- stay-ACCEPTED negatives (the fix must NOT over-reject) ----

    def test_fresh_store_then_consume_whole_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    sink(s)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_rearmed_field_single_consume_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    close(s.conn)\n"
            "    let n = s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_read_other_field_after_store_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    let n = s.tag\n"
            "    close(s.conn)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_param_carrier_store_stays_drop_exempt(self):
        # The critical negative: after the fix the re-arm re-adds s to the
        # live set, so this proves _drop_exempt_linear (checked first in
        # _linear_check_dropped) still exempts a consume-param carrier.
        r = check(
            self._NL + "fun take(consume s: S) -> Unit\n"
            "    close(s.conn)\n    s.conn = open()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_carrier_returned_after_store_ok(self):
        r = check(
            self._NL + "fun make() -> S\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    return s\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_nested_store_then_consume_whole_ok(self):
        r = check(
            self._NEST + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner.conn = open()\n    sinko(o)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_two_field_partial_restore_then_consume_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    var p = mkp()\n"
            "    close(p.a)\n    p.a = open()\n    close(p.a)\n    close(p.b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
