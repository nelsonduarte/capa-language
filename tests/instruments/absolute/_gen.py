"""The generator of instrument (a): the primitive builders (the clauses as
code), the parameterised statement shapes, the random draws over the
registered kinds, and the program-level evaluation.

Builders are instance attributes on purpose: the evaluator self-test
replaces one at a time on a generator and rebuilds the anchors from it.
"""

from __future__ import annotations

import random
from typing import Optional

from tests.instruments._outcome import ABORT, OK
from tests.instruments.absolute._rule import BOOL, INT, STMT, Abort, Return, chk, fmt, idiv, imod


class Gen:
    """The generator: random draws over the registered kinds, and the
    primitive builders (the clauses as code). Builders are instance
    attributes on purpose: the evaluator self-test replaces one at a time."""

    def __init__(self, rnd: random.Random, kinds: Optional[dict] = None):
        self.r = rnd
        if kinds is None:
            from tests.instruments.absolute._kinds import PUBLIC_KINDS
            kinds = PUBLIC_KINDS
        self.kinds = dict(kinds)
        self.k = 0

    def mk(self) -> int:
        self.k += 1
        return self.k

    def names(self, category: str) -> list:
        return [k.name for k in self.kinds.values() if k.category == category]

    # ---- primitive builders: (source, evaluator) ----
    def b_leaf(self, n):
        return "t(stdio, %d)" % n, (lambda out: (out.append("[%d]" % n), n)[1])

    def b_lit(self, n):
        return str(n), (lambda out: n)

    def b_bin(self, op, a, b):                                                      # R1, R9
        (sa, ea), (sb, eb) = a, b
        f = {"+": lambda x, y: chk(x + y), "-": lambda x, y: chk(x - y), "*": lambda x, y: chk(x * y),
             "/": idiv, "%": imod}[op]
        return "(%s %s %s)" % (sa, op, sb), (lambda out: f(ea(out), eb(out)))

    def b_neg(self, a):                                                             # R9
        sa, ea = a
        return "(-%s)" % sa, (lambda out: chk(-ea(out)))

    def b_ife(self, c, a, b):                                                       # R3
        (sc, ec), (sa, ea), (sb, eb) = c, a, b
        return "(if %s then %s else %s)" % (sc, sa, sb), (lambda out: ea(out) if ec(out) else eb(out))

    def b_match(self, s, arms, lits):                                               # R4
        ss, es = s
        src = "(match %s { %d -> %s, %d -> %s, _ -> %s })" % (
            ss, lits[0], arms[0][0], lits[1], arms[1][0], arms[2][0])

        def ev(out):
            v = es(out)
            if v == lits[0]:
                return arms[0][1](out)
            if v == lits[1]:
                return arms[1][1](out)
            return arms[2][1](out)
        return src, ev

    def b_call(self, a, b):                                                         # R1
        (sa, ea), (sb, eb) = a, b
        return "h(%s, %s)" % (sa, sb), (lambda out: (lambda x, y: chk(x * 10 + y))(ea(out), eb(out)))

    def b_lam(self, a, b):                                                          # R6
        (sa, ea), (sb, eb) = a, b
        return ("(fun (q: Int) -> Int => q + %s)(%s)" % (sa, sb),
                (lambda out: (lambda qv: chk(qv + ea(out)))(eb(out))))

    def b_struct(self, a, b, swapped):                                              # R1
        (sa, ea), (sb, eb) = a, b
        if swapped:
            return ("P { y: %s, x: %s }.sum()" % (sb, sa),
                    (lambda out: (lambda yv, xv: chk(xv * 3 + yv))(eb(out), ea(out))))
        return ("P { x: %s, y: %s }.sum()" % (sa, sb),
                (lambda out: (lambda xv, yv: chk(xv * 3 + yv))(ea(out), eb(out))))

    def b_field(self, a, b, swapped, which):                                        # R1
        (sa, ea), (sb, eb) = a, b
        pick = (lambda xv, yv: xv if which == "x" else yv)
        if swapped:
            return ("P { y: %s, x: %s }.%s" % (sb, sa, which),
                    (lambda out: (lambda yv, xv: pick(xv, yv))(eb(out), ea(out))))
        return ("P { x: %s, y: %s }.%s" % (sa, sb, which),
                (lambda out: (lambda xv, yv: pick(xv, yv))(ea(out), eb(out))))

    def b_list(self, items, i):                                                     # R14
        def ev(out):
            vals = [e(out) for _, e in items]
            return vals[i] if i < len(vals) else 0
        return "[%s].get(%d).unwrap_or(0)" % (", ".join(s for s, _ in items), i), ev

    def b_index(self, items, i):                                                    # R10
        def ev(out):
            vals = [e(out) for _, e in items]
            if i >= len(vals):
                raise Abort("index")
            return vals[i]
        return "[%s][%d]" % (", ".join(s for s, _ in items), i), ev

    def b_interp(self, a, b):                                                       # R1
        (sa, ea), (sb, eb) = a, b
        return '"${%s}|${%s}".length()' % (sa, sb), (lambda out: len("%d|%d" % (ea(out), eb(out))))

    def b_strlen(self, s):                                                          # R14
        return '"%s".length()' % s, (lambda out: len(s))

    def b_bleaf(self, n, b):
        return "tb(stdio, %d, %s)" % (n, fmt(b)), (lambda out: (out.append("[%d]" % n), b)[1])

    def b_cmp(self, op, a, b):                                                      # R13
        (sa, ea), (sb, eb) = a, b
        f = {"<": lambda x, y: x < y, "==": lambda x, y: x == y, ">": lambda x, y: x > y,
             "<=": lambda x, y: x <= y, ">=": lambda x, y: x >= y, "!=": lambda x, y: x != y}[op]
        return "(%s %s %s)" % (sa, op, sb), (lambda out: f(ea(out), eb(out)))

    def b_and(self, a, b):                                                          # R2
        (sa, ea), (sb, eb) = a, b
        return "(%s and %s)" % (sa, sb), (lambda out: ea(out) and eb(out))

    def b_or(self, a, b):                                                           # R2
        (sa, ea), (sb, eb) = a, b
        return "(%s or %s)" % (sa, sb), (lambda out: ea(out) or eb(out))

    def b_not(self, a):                                                             # R13
        sa, ea = a
        return "(not %s)" % sa, (lambda out: not ea(out))

    # ---- statement shapes, parameterised: (lines, evaluator) ----
    def s_while(self, v, nlim):                                                     # R7
        def ev(out):
            i = 0
            while True:
                out.append("[%d]" % i)
                if not (i < nlim):
                    break
                i += 1
            out.append(" w=%d\n" % i)
        return ["    var i%d = 0" % v, "    while t(stdio, i%d) < %d" % (v, nlim),
                "        i%d = i%d + 1" % (v, v), '    stdio.println(" w=${i%d}")' % v], ev

    def s_while_match(self, v, nlim):                                               # R7, R4
        def ev(out):
            i = 0
            while True:
                out.append("[%d]" % i)
                if i == nlim:
                    break
                i += 1
            out.append(" wm=%d\n" % i)
        return ["    var j%d = 0" % v, "    while match t(stdio, j%d) { %d -> false, _ -> true }" % (v, nlim),
                "        j%d = j%d + 1" % (v, v), '    stdio.println(" wm=${j%d}")' % v], ev

    def s_for(self, v, items):                                                      # R8
        def ev(out):
            vals = [e(out) for _, e in items]
            tot = 0
            for x in vals:
                out.append("<%d>" % x)
                tot = chk(tot + x)
            out.append(" f=%d\n" % tot)
        return ["    var s%d = 0" % v, "    for x in [%s]" % ", ".join(s for s, _ in items),
                '        stdio.print("<${x}>")', "        s%d = s%d + x" % (v, v),
                '    stdio.println(" f=${s%d}")' % v], ev

    def s_for_range(self, v, a, n):                                                 # R8
        sa, ea = a

        def ev(out):
            start = ea(out)
            tot = 0
            for x in range(start, start + n):
                out.append("<%d>" % x)
                tot = chk(tot + x)
            out.append(" fr=%d\n" % tot)
        return ["    var s%d = 0" % v, "    let a%d = %s" % (v, sa),
                "    for x in a%d..(a%d + %d)" % (v, v, n), '        stdio.print("<${x}>")',
                "        s%d = s%d + x" % (v, v), '    stdio.println(" fr=${s%d}")' % v], ev

    def s_lam_twice(self, v, a):                                                    # R6
        sa, ea = a

        def ev(out):
            first = chk(1 + ea(out))
            second = chk(2 + ea(out))
            out.append(" l=%d\n" % chk(first + second))
        return ["    let g%d = fun (q: Int) -> Int => q + %s" % (v, sa),
                '    stdio.println(" l=${g%d(1) + g%d(2)}")' % (v, v)], ev

    def s_elif(self, a, b):                                                         # R3
        def ev(out):
            out.append("[%d]" % a)
            if a > 50:
                res = 1
            else:
                out.append("[%d]" % b)
                res = 2 if b > 50 else 3
            out.append(" e=%d\n" % res)
        return ['    stdio.println(" e=${firstpos(stdio, %d, %d)}")' % (a, b)], ev

    def s_if_stmt(self, c1, c2, b1, b2, b3):                                        # R3
        def ev(out):
            if c1[1](out):
                out.append(" A%d\n" % b1[1](out))
            elif c2[1](out):
                out.append(" B%d\n" % b2[1](out))
            else:
                out.append(" C%d\n" % b3[1](out))
        return ["    if %s" % c1[0], '        stdio.println(" A${%s}")' % b1[0], "    elif %s" % c2[0],
                '        stdio.println(" B${%s}")' % b2[0], "    else",
                '        stdio.println(" C${%s}")' % b3[0]], ev

    def s_match_variant(self, v, s, variant):                                       # R4
        lit = {"Circ": "Circ(%s)" % s[0], "Sq": "Sq(%s, 2)" % s[0], "Dot": "Dot"}[variant]

        def ev(out):
            val = s[1](out) if variant != "Dot" else None
            if variant == "Circ":
                if val > 3:
                    out.append(" bigcirc\n")
                else:
                    out.append(" circ=%d\n" % val)
            elif variant == "Sq":
                out.append(" sq=%d\n" % chk(val * 2))
            else:
                out.append(" dot\n")
        return ["    let sh%d: Sh = %s" % (v, lit), "    match sh%d" % v,
                '        Circ(rr) if rr > 3 -> stdio.println(" bigcirc")',
                '        Circ(rr) -> stdio.println(" circ=${rr}")',
                '        Sq(w, hh) -> stdio.println(" sq=${w * hh}")',
                '        Dot -> stdio.println(" dot")'], ev

    def s_match_struct(self, v, s, s2):                                             # R4, R1
        def ev(out):
            x = s[1](out)
            y = s2[1](out)
            if x == y:
                out.append(" eq=%d\n" % x)
            else:
                out.append(" ne=%d\n" % chk(x - y))
        return ["    let p%d = P { x: %s, y: %s }" % (v, s[0], s2[0]), "    match p%d" % v,
                '        P { x, y } if x == y -> stdio.println(" eq=${x}")',
                '        P { x, y } -> stdio.println(" ne=${x - y}")'], ev

    def s_match_or(self, s, l0):                                                    # R4
        def ev(out):
            val = s[1](out)
            if val in (l0, l0 + 1):
                out.append(" lo\n")
            elif val == l0 + 2:
                out.append(" mid\n")
            else:
                out.append(" hi=%d\n" % val)
        return ["    match %s" % s[0], '        %d | %d -> stdio.println(" lo")' % (l0, l0 + 1),
                '        %d -> stdio.println(" mid")' % (l0 + 2),
                '        other -> stdio.println(" hi=${other}")'], ev

    def s_match_guard_effect(self, s, l0, g1, g2, gtrue):                           # R4
        def ev(out):
            val = s[1](out)
            if val == l0:
                out.append("[%d]" % g1)
                if gtrue:
                    out.append(" g1\n")
                    return
            out.append("[%d]" % g2)
            if val > 1:
                out.append(" g2\n")
                return
            out.append(" g3\n")
        return ["    match %s" % s[0],
                '        %d if tb(stdio, %d, %s) -> stdio.println(" g1")' % (l0, g1, fmt(gtrue)),
                '        n if t(stdio, %d) > 0 and n > 1 -> stdio.println(" g2")' % g2,
                '        _ -> stdio.println(" g3")'], ev

    def s_break_continue(self, v, lim, skip, stop):                                 # R7
        def ev(out):
            k = 0
            while k < lim:
                k += 1
                if k == skip:
                    continue
                if k == stop:
                    break
                out.append("{%d}" % k)
            out.append(" k=%d\n" % k)
        return ["    var k%d = 0" % v, "    while k%d < %d" % (v, lim), "        k%d = k%d + 1" % (v, v),
                "        if k%d == %d" % (v, skip), "            continue",
                "        if k%d == %d" % (v, stop), "            break",
                '        stdio.print("{${k%d}}")' % v, '    stdio.println(" k=${k%d}")' % v], ev

    def s_tuple(self, v, a, b):                                                     # R1
        def ev(out):
            x = a[1](out)
            y = b[1](out)
            out.append(" tup=%d\n" % chk(chk(x * 10) + y))
        return ["    let (a%d, b%d) = (%s, %s)" % (v, v, a[0], b[0]),
                '    stdio.println(" tup=${a%d * 10 + b%d}")' % (v, v)], ev

    def s_try_call(self, a, b):                                                     # R11, R1
        def ev(out):
            x = a[1](out)
            y = b[1](out)
            out.append("[%d]" % x)
            if x % 2 != 0:
                out.append(" err=odd\n")
                return
            out.append("[%d]" % y)
            if y % 2 != 0:
                out.append(" err=odd\n")
                return
            out.append(" ok=%d\n" % chk((x // 2) * 10 + y // 2))
        return ["    match tryf(stdio, %s, %s)" % (a[0], b[0]),
                '        Ok(rr) -> stdio.println(" ok=${rr}")',
                '        Err(e) -> stdio.println(" err=${e}")'], ev

    def s_early_return(self, n, b):                                                 # R3
        def ev(out):
            out.append("[%d]" % n)
            if b:
                raise Return()
        return ["    if tb(stdio, %d, %s)" % (n, fmt(b)), "        return"], ev

    def s_ovf(self, big_lit, op, a):                                                # R9, R12
        e = self.b_bin(op, self.b_lit(big_lit), a)

        def ev(out):
            out.append(" o=%d\n" % e[1](out))
        return ['    stdio.println(" o=${%s}")' % e[0]], ev

    # ---- random trees over the kinds ----
    def int_expr(self, d: int, ns: bool = False, big: bool = False):
        ks = self.names(INT) if d > 0 else ["leaf", "lit"]
        if ns:
            ks = [k for k in ks if k not in ("struct", "field")]
        kd = self.r.choice(ks)
        return self.kinds[kd].build(self, d, ns, big)

    def bool_expr(self, d: int, ns: bool = False):
        ks = self.names(BOOL) if d > 0 else ["bleaf", "cmp"]
        kd = self.r.choice(ks)
        return self.kinds[kd].build(self, d, ns, False)

    def stmt_block(self):
        kd = self.r.choice(self.names(STMT))
        return self.kinds[kd].build(self)

    def evaluate(self, evs) -> tuple:                                               # R12
        """Run the statements' evaluators in order: an abort keeps the stdout
        written so far and exits non-zero; an early return stops the rest."""
        out: list = []
        exit = OK
        for ev in evs:
            try:
                ev(out)
            except Abort:
                exit = ABORT
                break
            except Return:
                break
        return exit, "".join(out)
