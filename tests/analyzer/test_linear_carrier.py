"""Analyzer tests: a CARRIER-field projection used as a MOVE OPERAND.

This realizes the ``test_linear_carrier.py`` seam the tests/analyzer/__init__.py
growth convention already named. It is the carrier move-operand facet ACROSS
move positions (consume-arg, struct/typestate pack, return, let/var/reassign
binding, field-store RHS, and the ``consume self`` receiver), distinct from the
field-store subject in test_linear_field_store.py. The shared check/errors_of
helpers come from tests/analyzer/_helpers.py.

A whole carrier field (``b.two`` whose field type is a carrier owning linear
leaves, not a bare leaf) used as a move operand was silently unmoved in every
non-store move position, laundering the obligation. All field-projection moves
now route through one helper ``_move_field_leaves`` driven by the single leaf-set
enumerator ``_field_linear_leaves``: a bare leaf moves its one place, a carrier
field moves its whole subtree, identically. The helper also rejects re-consuming
an already-moved carrier field (the husk-reconsume analogue for a FieldAccess
operand), which the per-leaf move alone would swallow.

The deep ``_LINEAR_PATH_MAX_DEPTH`` fail-open is now CLOSED: the carrier walk
cycle-detects instead of failing open past depth 8 (the cycle-detecting
``owned_obligation`` predicate plus the fail-closed enumerator budget), covered
by test_linear_depth.py. OUT OF SCOPE (separate items, unchanged here): an Index
target/receiver, the borrow-read residual, E3 generic-return aliasing, and the
compiler-wide diamond wall-clock DoS. Analyzer-only; accepted shapes run
byte-identically on all backends via test_ir_wasm_parity."""

import unittest

from tests.analyzer._helpers import check, errors_of


class TestCarrierMoveOperand(unittest.TestCase):
    # Struct carriers over one linear leaf Conn: S(conn) is the carrier field
    # type; Box(two:S), Box2(inner:S), Mid(s:S)/Deep(mid:Mid) for depth. S has a
    # `consume self` method eat for the method-receiver position.
    _C = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "type S { conn: Conn, tag: Int }\n"
        "impl S\n"
        "    fun eat(consume self) -> Unit\n"
        "        return ()\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
        "fun close2(consume t: S) -> Unit\n"
        "    return ()\n"
        "fun peek2(t: S) -> Int\n"
        "    return t.tag\n"
        "type Box { two: S, tag: Int }\n"
        "fun mkbox() -> Box\n"
        "    return Box { two: mks(), tag: 0 }\n"
        "fun sinkbox(consume b: Box) -> Unit\n"
        "    return ()\n"
        "type Box2 { inner: S, tag: Int }\n"
        "fun sinkb2(consume w: Box2) -> Unit\n"
        "    return ()\n"
        "type Mid { s: S, tag: Int }\n"
        "fun close_mid(consume m: Mid) -> Unit\n"
        "    return ()\n"
        "type Deep { mid: Mid, tag: Int }\n"
        "fun mkdeep() -> Deep\n"
        "    return Deep { mid: Mid { s: mks(), tag: 0 }, tag: 0 }\n"
        "fun sinkdeep(consume d: Deep) -> Unit\n"
        "    return ()\n"
    )
    # Typestate carrier: Rec(claim:Claim[Settled]) inside TBox(rec:Rec); Hold
    # receives a projected Rec for the typestate-pack position.
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
        "type Hold { held: Rec, tag: Int }\n"
        "fun sinkhold(consume h: Hold) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    # ---- position 1: consume-arg ----

    def test_consume_arg_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    close2(b.two)\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    # ---- position 2: struct-literal pack ----

    def test_struct_pack_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let w = Box2 { inner: b.two, tag: 0 }\n"
            "    sinkbox(b)\n    sinkb2(w)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    # ---- position 3: typestate pack ----

    def test_typestate_pack_projection_double_free(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    var tb = mktbox()\n"
            "    let h = Hold { held: tb.rec, tag: 0 }\n"
            "    sinktbox(tb)\n    sinkhold(h)\n"
        )
        self.assertTrue(
            any("'tb.rec.claim'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    # ---- position 5: return ----

    def test_return_projection_transfer_double_free(self):
        errs = self._errs(
            self._C + "fun make() -> S\n    var b = mkbox()\n"
            "    let t = b.two\n    sinkbox(b)\n    return t\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    def test_return_already_moved_projection_use_after_move(self):
        # Direct return of an already-moved carrier field: use-after-move via
        # the carrier-field reconsume reject, NOT the spurious 'b' dropped leak.
        errs = self._errs(
            self._C + "fun make() -> S\n    var b = mkbox()\n"
            "    close2(b.two)\n    return b.two\n"
        )
        self.assertTrue(
            any("carrier field 'b.two'" in e and "already consumed" in e
                for e in errs),
            errs,
        )
        self.assertFalse(
            any("'b' is dropped" in e for e in errs), errs,
        )

    # ---- position 6: let / var / name-reassign (one transfer widening) ----

    def test_let_binding_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let t = b.two\n    close2(t)\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    def test_var_binding_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    var t = b.two\n    close2(t)\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    def test_name_reassign_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    var t = mks()\n    close2(t)\n    t = b.two\n"
            "    close2(t)\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    # ---- position 7: borrowed carrier-field consume launder ----

    def test_borrowed_carrier_field_consume_rejected(self):
        errs = self._errs(
            self._C + "fun peek(b: Box) -> Unit\n    close2(b.two)\n"
        )
        self.assertTrue(
            any("belongs to a borrowed value" in e for e in errs), errs,
        )

    # ---- Correction B: consume-self method receiver ----

    def test_method_receiver_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    b.two.eat()\n    sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    # ---- nesting: a deeper carrier projection ----

    def test_nested_projection_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var d = mkdeep()\n"
            "    close_mid(d.mid)\n    sinkdeep(d)\n"
        )
        self.assertTrue(
            any("'d.mid.s.conn'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    # ---- branch-merge bite: consume in an if arm and a match arm ----

    def test_projection_consume_in_if_arm_rejected(self):
        errs = self._errs(
            self._C + "fun run(cond: Bool) -> Unit\n    var b = mkbox()\n"
            "    if cond\n        close2(b.two)\n        sinkbox(b)\n"
            "    else\n        sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    def test_projection_consume_in_match_arm_rejected(self):
        errs = self._errs(
            self._C + "fun run(cond: Bool) -> Unit\n    var b = mkbox()\n"
            "    match cond\n"
            "        true ->\n            close2(b.two)\n            sinkbox(b)\n"
            "        false ->\n            sinkbox(b)\n"
        )
        self.assertTrue(
            any("'b.two.conn'" in e and "already consumed" in e for e in errs),
            errs,
        )

    # ---- Correction A: re-consuming an already-moved carrier field ----

    def test_reconsume_carrier_field_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    close2(b.two)\n    close2(b.two)\n"
        )
        self.assertTrue(
            any("carrier field 'b.two'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    def test_double_projection_then_consume_both_double_free(self):
        errs = self._errs(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let t = b.two\n    let u = b.two\n    close2(t)\n    close2(u)\n"
        )
        self.assertTrue(
            any("carrier field 'b.two'" in e and "already consumed" in e
                for e in errs),
            errs,
        )

    # ---- FP face: project then consume ONLY the projection -> ACCEPT ----

    def test_project_then_consume_projection_ok(self):
        body = (
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let t = b.two\n    close2(t)\n"
        )
        r = check(body)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertFalse(
            any("'b' is dropped" in e for e in self._errs(body)), self._errs(body),
        )

    # ---- stay-accepted negatives (the fix must NOT over-reject) ----

    def test_borrow_arg_projection_ok(self):
        # THE critical no-FP negative: a carrier field passed BY BORROW is not
        # moved, so the carrier can still be consumed.
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let n = peek2(b.two)\n    sinkbox(b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_read_scalar_subfield_then_consume_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let n = b.two.tag\n    sinkbox(b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_whole_carrier_fresh_operand_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    close2(mks())\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_whole_carrier_alias_move_ok(self):
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let c = b\n    sinkbox(c)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_whole_carrier_after_projection_read_ok(self):
        # Read a sub-field of the projection is fine; consuming the WHOLE
        # carrier once stays legal.
        r = check(
            self._C + "fun main(_s: Stdio)\n    var b = mkbox()\n"
            "    let n = b.two.tag\n    close2(b.two)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
