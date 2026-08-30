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


class TestFieldStoreCarrierTarget(unittest.TestCase):
    """The `o.inner = a` store into a CARRIER-typed target field (a subtree of
    linear/typestate leaves, not a bare leaf).

    This is the carrier facet of the same field-store subject as
    TestFieldStoreLinearAlias: both drive off the ONE leaf-set enumerator
    `_field_linear_leaves`, where the bare leaf is the degenerate one-element
    instance. A carrier-typed target field owns a whole SUBTREE of leaves, which
    the leaf-only `_linear_place` gate excluded, reopening the same three faces
    at subtree scale:

    - Face A (double-free, was ACCEPTED): the RHS carrier (whole or projection)
      is now discharged, so a later consume of it is use-after-move.
    - Face B (false-positive, was REJECTED for a spurious husk-reconsume): the
      RHS is moved and the subtree re-armed, so no spurious drop / husk error.
    - Face C (missed leak, was ACCEPTED): re-arming re-opens the carrier root, so
      an overwritten-live or re-stored-then-dropped leaf now leaks by path.

    A borrowed RHS carrier is rejected with the struct-literal PACK wording; a
    carrier PROJECTION RHS (`o.inner = p.inner`) has its subtree moved so the
    source becomes a husk (Correction 1).

    OUT OF SCOPE (separate mechanisms, unchanged here): the deep-8
    `_LINEAR_PATH_MAX_DEPTH` fail-open (its own depth-cap item), an Index
    target/receiver, the borrow-read residual, and E3 generic-return aliasing.
    Analyzer-only; the accepted shapes run byte-identically on all backends via
    test_ir_wasm_parity."""

    # Carrier zoo over one linear leaf Conn: S(conn), Outer(inner:S),
    # Mid(s:S)/Deep(mid:Mid) for depth, Two(a,b:Conn)/Box(two:Two) for multi-leaf.
    _C = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
        "fun sinks(consume s: S) -> Unit\n"
        "    return ()\n"
        "type Outer { inner: S, tag: Int }\n"
        "fun mko() -> Outer\n"
        "    return Outer { inner: mks(), tag: 0 }\n"
        "fun sinko(consume o: Outer) -> Unit\n"
        "    return ()\n"
        "type Mid { s: S, tag: Int }\n"
        "type Deep { mid: Mid, tag: Int }\n"
        "fun mkdeep() -> Deep\n"
        "    return Deep { mid: Mid { s: mks(), tag: 0 }, tag: 0 }\n"
        "fun sinkdeep(consume d: Deep) -> Unit\n"
        "    return ()\n"
        "type Two { a: Conn, b: Conn, tag: Int }\n"
        "fun mk2() -> Two\n"
        "    return Two { a: open(), b: open(), tag: 0 }\n"
        "fun close2(consume t: Two) -> Unit\n"
        "    return ()\n"
        "type Box { two: Two, tag: Int }\n"
        "fun mkbox() -> Box\n"
        "    return Box { two: mk2(), tag: 0 }\n"
        "fun sinkbox(consume b: Box) -> Unit\n"
        "    return ()\n"
    )
    # Typestate carrier: Rec(claim:Claim[Settled]) inside TBox(rec:Rec).
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Rec { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Rec\n"
        "    return Rec { claim: become(mk(), Settled), tag: 0 }\n"
        "type TBox { rec: Rec, tag: Int }\n"
        "fun mktbox() -> TBox\n"
        "    return TBox { rec: mkrec(), tag: 0 }\n"
        "fun sinktbox(consume b: TBox) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    # ---- Face A: double-free of the laundered RHS carrier -> REJECT ----

    def test_carrier_single_leaf_face_a(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    var a = mks()\n    o.inner = a\n    sinko(o)\n    close(a.conn)\n"
        )
        self.assertTrue(
            any("'a'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_carrier_multi_leaf_launder_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let t = mk2()\n    close(b.two.a)\n    close(b.two.b)\n"
            "    b.two = t\n    sinkbox(b)\n    close2(t)\n"
        )
        self.assertTrue(
            any("'t'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- Face B: FP husk-reconsume / drop repaired -> ACCEPT ----

    def test_carrier_single_leaf_face_b(self):
        body = (
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    close(o.inner.conn)\n    let a = mks()\n    o.inner = a\n"
            "    sinko(o)\n"
        )
        r = check(body)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        errs = self._errs(body)
        self.assertFalse(any("'a'" in e and "dropped" in e for e in errs), errs)
        self.assertFalse(any("already consumed" in e for e in errs), errs)

    # ---- Face C: overwrite-live and drop-after-fresh -> REJECT ----

    def test_carrier_single_leaf_overwrite(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    o.inner = mks()\n    sinko(o)\n"
        )
        self.assertTrue(
            any("'o.inner.conn' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )

    def test_carrier_single_leaf_drop_after_fresh(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner = mks()\n"
        )
        self.assertTrue(
            any("'o'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    # ---- member 5: intermediate (depth-2) carrier target ----

    def test_carrier_intermediate_overwrite(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var d = mkdeep()\n"
            "    d.mid = Mid { s: mks(), tag: 0 }\n    sinkdeep(d)\n"
        )
        self.assertTrue(
            any("'d.mid.s.conn' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )

    # ---- member 6: multi-leaf overwrite = one diagnostic PER leaf ----

    def test_carrier_multi_leaf_overwrite_two_diagnostics(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    b.two = mk2()\n    sinkbox(b)\n"
        )
        overwrites = [e for e in errs if "is overwritten without being consumed" in e]
        self.assertEqual(len(overwrites), 2, errs)
        self.assertTrue(any("'b.two.a'" in e for e in overwrites), errs)
        self.assertTrue(any("'b.two.b'" in e for e in overwrites), errs)

    # ---- member 8: multi-leaf partial -> store-time by-path, not scope-exit ----

    def test_carrier_multi_leaf_partial_store_time(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    close(b.two.a)\n    b.two = mk2()\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.b' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )
        # The STORE-time overwrite form, not the scope-exit leak form.
        self.assertFalse(
            any("is dropped without being consumed" in e for e in errs), errs,
        )

    # ---- member 10: typestate carrier target ----

    def test_typestate_carrier_overwrite(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    var b = mktbox()\n"
            "    b.rec = mkrec()\n    sinktbox(b)\n"
        )
        self.assertTrue(
            any("'b.rec.claim' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )

    def test_typestate_carrier_launder_double_free(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    var b = mktbox()\n"
            "    let r = mkrec()\n    archive(b.rec.claim)\n    b.rec = r\n"
            "    sinktbox(b)\n    archive(r.claim)\n"
        )
        self.assertTrue(
            any("'r'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- member 11: borrowed-RHS carrier -> struct-literal PACK wording ----

    def test_borrowed_rhs_carrier(self):
        errs = self._errs(
            self._C + "fun launder(s: S) -> Unit\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner = s\n    sinko(o)\n"
        )
        self.assertTrue(
            any("cannot pack borrowed" in e and "'s'" in e for e in errs), errs,
        )

    # ---- member 12: Face A inside an if branch AND a match arm ----

    def test_carrier_face_a_inside_if(self):
        errs = self._errs(
            self._C + "fun run(cond: Bool) -> Unit\n"
            "    var o = mko()\n    var a = mks()\n    if cond\n"
            "        close(o.inner.conn)\n        o.inner = a\n"
            "        sinko(o)\n        close(a.conn)\n    else\n"
            "        close(o.inner.conn)\n        close(a.conn)\n"
        )
        self.assertTrue(
            any("'a'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_carrier_face_a_inside_match(self):
        errs = self._errs(
            self._C + "fun run(cond: Bool) -> Unit\n"
            "    var o = mko()\n    var a = mks()\n    match cond\n"
            "        true ->\n            close(o.inner.conn)\n"
            "            o.inner = a\n            sinko(o)\n"
            "            close(a.conn)\n        false ->\n"
            "            close(o.inner.conn)\n            close(a.conn)\n"
        )
        self.assertTrue(
            any("'a'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- member 13: re-arm + consume inside a while loop -> ACCEPT ----

    def test_carrier_inside_while_ok(self):
        r = check(
            self._C + "fun run(n: Int) -> Unit\n    var o = mko()\n"
            "    var i = n\n    while i > 0\n        close(o.inner.conn)\n"
            "        o.inner = mks()\n        i = i - 1\n    sinko(o)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- Correction 1: carrier-projection RHS + self-store ----

    def test_self_store_ok(self):
        # Bites Correction 1: without the RHS-projection subtree move this
        # spuriously rejects (overwrite of the still-live leaf).
        r = check(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    o.inner = o.inner\n    sinko(o)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_carrier_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    var p = mko()\n    close(o.inner.conn)\n    o.inner = p.inner\n"
            "    sinko(o)\n    sinko(p)\n"
        )
        self.assertTrue(
            any("'p.inner.conn'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    def test_deeper_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    var d = mkdeep()\n    close(o.inner.conn)\n"
            "    o.inner = d.mid.s\n    sinko(o)\n    sinkdeep(d)\n"
        )
        self.assertTrue(
            any("'d.mid.s.conn'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    def test_borrowed_projection_rhs_rejected(self):
        errs = self._errs(
            self._C + "fun launder(p: Outer) -> Unit\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner = p.inner\n    sinko(o)\n"
        )
        self.assertTrue(
            any("belongs to a borrowed value" in e and "'p.inner.conn'" in e
                for e in errs),
            errs,
        )

    # ---- Correction 2: these REJECT on main (husk-reconsume) -> FLIP to ACCEPT ----

    def test_fresh_store_then_consume_whole_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner = mks()\n    sinko(o)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_carrier_returned_after_store_ok(self):
        r = check(
            self._C + "fun make() -> Outer\n    var o = mko()\n"
            "    close(o.inner.conn)\n    o.inner = mks()\n    return o\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_multi_leaf_restore_then_consume_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    close(b.two.a)\n    close(b.two.b)\n    b.two = mk2()\n"
            "    close(b.two.a)\n    close(b.two.b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- genuine stay-accepted negatives (green on main, stay green) ----

    def test_drop_exempt_consume_param_carrier_target_ok(self):
        # The critical negative: the re-key re-adds o to _live_linear, so this
        # proves _drop_exempt_linear (checked first) still exempts it.
        r = check(
            self._C + "fun take(consume o: Outer) -> Unit\n"
            "    close(o.inner.conn)\n    o.inner = mks()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_sibling_scalar_read_after_store_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    close(b.two.a)\n    close(b.two.b)\n    b.two = mk2()\n"
            "    let n = b.two.tag\n    sinkbox(b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_overwrite_live_single_leaf_one_diagnostic(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var o = mko()\n"
            "    o.inner = mks()\n    sinko(o)\n"
        )
        self.assertEqual(len(errs), 1, errs)
        self.assertIn(
            "'o.inner.conn' is overwritten without being consumed", errs[0],
        )


if __name__ == "__main__":
    unittest.main()
