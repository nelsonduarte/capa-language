"""THE RULE of the absolute oracle, stated ONCE as numbered clauses.

Each clause names where the language reference states it, or says SPEC GAP
when the reference does not (the documenter's list). The builder methods of
``Gen`` ARE the clauses in code: each returns the Capa source of a construct
and an evaluator that appends the markers the construct prints and yields
its value, under the clause. The hand-written ANCHORS pin each clause with
an expected output written from the clause text, never computed; the
evaluator must reproduce every anchor before a corpus is written, and the
anchor programs run on every backend against the same hand-written
expectation.

A grammar KIND is a registered way of drawing a construct; the public kinds
live here, and a private extension may add kinds (and their anchors) whose
shapes are not public yet. A node class the grammar deliberately never
produces is listed in ``EXCLUDED`` with its reason, which the completeness
pin reads.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Optional

from tests.instruments._outcome import ABORT, OK

I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1


class Abort(Exception):
    """The program aborts (R9, R10); stdout written so far is kept (R12)."""


class Return(Exception):
    """``main`` returns early; the statements after it do not run (R3)."""


def chk(v: int) -> int:
    if v < I64_MIN or v > I64_MAX:
        raise Abort("overflow")
    return v


def idiv(a: int, b: int) -> int:
    if b == 0:
        raise Abort("division by zero")
    return chk(a // b)


def imod(a: int, b: int) -> int:
    if b == 0:
        raise Abort("division by zero")
    return a % b


@dataclass(frozen=True)
class Clause:
    id: str
    text: str
    source: str


CLAUSES = (
    Clause("R1", "operands of a binary operator, call arguments, struct-literal fields, tuple "
                 "elements and interpolation segments are evaluated exactly once, left to right "
                 "in written order",
           "SPEC GAP: specs 04, 08 and 09 state no order"),
    Clause("R2", "`and` and `or` evaluate the right operand only when the left does not decide",
           "specs/09 section 8.2"),
    Clause("R3", "an `if` (expression or statement) evaluates its condition, then only the chosen "
                 "branch; `elif` conditions are evaluated in order until one holds; a `return` "
                 "ends the function at once",
           "SPEC GAP: specs/09 section 2 describes the syntax only"),
    Clause("R4", "a `match` evaluates its scrutinee once; arms are tried in order; an arm's guard "
                 "is evaluated only after its pattern matched; the first arm whose pattern matches "
                 "and whose guard holds runs, and only it",
           "specs/07 sections 1 and 3"),
    Clause("R5", "a named-argument call binds each argument by its name, whatever the written order",
           "specs/04 (allowed); the order of evaluation is a SPEC GAP"),
    Clause("R6", "a lambda body runs only when the lambda is called, once per call",
           "SPEC GAP: specs/08"),
    Clause("R7", "a `while` condition is evaluated before every iteration and once more at exit; "
                 "`break` leaves the innermost loop; `continue` goes to the next condition evaluation",
           "specs/09 section 6 names break and continue; the condition count is a SPEC GAP"),
    Clause("R8", "a `for` iterable (list or range) is evaluated once; `a..b` runs a to b-1",
           "specs/09 section 6 (range example)"),
    Clause("R9", "`Int` is a checked signed 64-bit integer: overflow on + - * and on unary minus "
                 "aborts the program; `/` is floored and `%` takes the divisor's sign; division by "
                 "zero aborts",
           "specs/05 section 2, specs/09 section 8.1"),
    Clause("R10", "an out-of-bounds list index aborts", "specs/05 (xs[i])"),
    Clause("R11", "`expr?` on `Err(e)` returns `Err(e)` from the enclosing function at once",
           "specs/09 section 5"),
    Clause("R12", "an abort keeps the stdout written before it and exits non-zero",
           "specs/05 section 2"),
    Clause("R13", "the comparison operators order `Int` values mathematically, `<=` and `>=` "
                  "holding on equality and `==` / `!=` testing equality and its negation; `not` "
                  "negates a `Bool`",
           "specs/09 section 1 (operator table) and 8.2"),
    Clause("R14", "`List.get(i)` is `None` out of range, so `.unwrap_or(d)` yields `d` there and "
                  "the element otherwise; `String.length()` counts the characters",
           "specs/05 (collections)"),
)
CLAUSE_IDS = tuple(c.id for c in CLAUSES)

HEADER = """type P { x: Int, y: Int }
type Sh =
    Circ(Int)
    Sq(Int, Int)
    Dot
impl P
    fun sum(self) -> Int
        return self.x * 3 + self.y
fun t(stdio: Stdio, n: Int) -> Int
    stdio.print("[${n}]")
    return n
fun tb(stdio: Stdio, n: Int, b: Bool) -> Bool
    stdio.print("[${n}]")
    return b
fun h(x: Int, y: Int) -> Int
    return x * 10 + y
fun firstpos(stdio: Stdio, a: Int, b: Int) -> Int
    if t(stdio, a) > 50
        return 1
    elif t(stdio, b) > 50
        return 2
    return 3
fun half(n: Int) -> Result<Int, String>
    if n % 2 == 0
        return Ok(n / 2)
    return Err("odd")
fun tryf(stdio: Stdio, a: Int, b: Int) -> Result<Int, String>
    let v = half(t(stdio, a))?
    let w = half(t(stdio, b))?
    return Ok(v * 10 + w)
"""
MAIN = "fun main(stdio: Stdio)\n"

#: AST node classes the grammar deliberately does not produce in a generated
#: body, each with the reason the completeness pin reports.
EXCLUDED = {
    "FloatLit": "Float formatting across backends is not stated in the reference (SPEC GAP); "
                "out of this oracle until it is",
    "CharLit": "a Char literal has no evaluation rule; its printed form is a formatting question, "
               "like Float's",
    "Become": "typestate transitions belong to the discipline instruments, not the evaluation-order oracle",
    "UnitLit": "a unit value has no observable; nothing to compare",
    "Try": "`?` needs a Result-returning function and main returns Unit; the `try_call` kind drives "
           "the header's `tryf` helper and the R11 anchors pin the rule",
}

INT, BOOL, STMT = "int", "bool", "stmt"


@dataclass(frozen=True)
class Kind:
    name: str
    category: str
    clauses: tuple
    build: Callable


PUBLIC_KINDS: dict = {}


def _kind(name: str, category: str, *clauses: str):
    def register(fn):
        PUBLIC_KINDS[name] = Kind(name, category, tuple(clauses), fn)
        return fn
    return register


def fmt(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


class Gen:
    """The generator: random draws over the registered kinds, and the
    primitive builders (the clauses as code). Builders are instance
    attributes on purpose: the evaluator self-test replaces one at a time."""

    def __init__(self, rnd: random.Random, kinds: Optional[dict] = None):
        self.r = rnd
        self.kinds = dict(PUBLIC_KINDS if kinds is None else kinds)
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


# ---- the public kinds: each draws its parameters and calls a builder ----
@_kind("leaf", INT)
def k_leaf(g, d, ns, big):
    return g.b_leaf(g.mk() % 97 + 1)


@_kind("lit", INT)
def k_lit(g, d, ns, big):
    return g.b_lit(g.r.choice(list(range(10)) + ([3037000500, 4611686018427387904] if big else [])))


def _k_arith(op):
    def build(g, d, ns, big):
        return g.b_bin(op, g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big))
    return build


for _name, _op in (("add", "+"), ("sub", "-"), ("mul", "*")):
    _kind(_name, INT, "R1", "R9")(_k_arith(_op))


def _k_divmod(op):
    def build(g, d, ns, big):
        a = g.int_expr(d - 1, ns, big)
        r = g.r
        if r.random() < 0.7:
            b = g.b_lit(r.choice([1, 2, 3, 4, 0] if r.random() < 0.15 else [1, 2, 3, 4]))
        else:
            b = g.b_leaf(g.mk() % 97 + 1)
        if r.random() < 0.3:
            a = g.b_neg(a)
        return g.b_bin(op, a, b)
    return build


_kind("div", INT, "R1", "R9")(_k_divmod("/"))
_kind("mod", INT, "R1", "R9")(_k_divmod("%"))


@_kind("neg", INT, "R9")
def k_neg(g, d, ns, big):
    return g.b_neg(g.int_expr(d - 1, ns, big))


@_kind("ife", INT, "R3")
def k_ife(g, d, ns, big):
    return g.b_ife(g.bool_expr(d - 1, ns), g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big))


@_kind("match", INT, "R4")
def k_match(g, d, ns, big):
    l0 = g.r.randint(0, 4)
    s = g.int_expr(d - 1, True, big)
    arms = [g.int_expr(d - 1, ns, big) for _ in range(3)]
    return g.b_match(s, arms, [l0, l0 + 1])


@_kind("call", INT, "R1")
def k_call(g, d, ns, big):
    return g.b_call(g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big))


@_kind("lam", INT, "R6")
def k_lam(g, d, ns, big):
    return g.b_lam(g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big))


@_kind("struct", INT, "R1")
def k_struct(g, d, ns, big):
    a, b = g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big)
    return g.b_struct(a, b, g.r.random() < 0.5)


@_kind("field", INT, "R1")
def k_field(g, d, ns, big):
    a, b = g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big)
    return g.b_field(a, b, g.r.random() < 0.5, g.r.choice(["x", "y"]))


@_kind("list", INT, "R14", "R1")
def k_list(g, d, ns, big):
    items = [g.int_expr(d - 1, ns, big) for _ in range(3)]
    return g.b_list(items, g.r.randint(0, 3))


@_kind("index", INT, "R10", "R1")
def k_index(g, d, ns, big):
    items = [g.int_expr(d - 1, ns, big) for _ in range(3)]
    return g.b_index(items, g.r.choice([0, 1, 2, 2, 1, 0, 3]))


@_kind("interp", INT, "R1")
def k_interp(g, d, ns, big):
    return g.b_interp(g.int_expr(d - 1, ns, big), g.int_expr(d - 1, ns, big))


@_kind("strlen", INT, "R14")
def k_strlen(g, d, ns, big):
    return g.b_strlen(g.r.choice(["ab", "abc", "", "hello"]))


@_kind("bleaf", BOOL)
def k_bleaf(g, d, ns, big):
    return g.b_bleaf(g.mk() % 97 + 1, g.r.random() < 0.5)


@_kind("cmp", BOOL, "R13", "R1")
def k_cmp(g, d, ns, big):
    op = g.r.choice(["<", "==", ">", "<=", ">=", "!="])
    return g.b_cmp(op, g.int_expr(max(d - 1, 0), ns), g.int_expr(max(d - 1, 0), ns))


@_kind("and", BOOL, "R2")
def k_and(g, d, ns, big):
    return g.b_and(g.bool_expr(d - 1, ns), g.bool_expr(d - 1, ns))


@_kind("or", BOOL, "R2")
def k_or(g, d, ns, big):
    return g.b_or(g.bool_expr(d - 1, ns), g.bool_expr(d - 1, ns))


@_kind("not", BOOL, "R13")
def k_not(g, d, ns, big):
    return g.b_not(g.bool_expr(d - 1, ns))


@_kind("while", STMT, "R7")
def k_while(g):
    return g.s_while(g.mk(), g.r.randint(0, 3))


@_kind("while_match", STMT, "R7", "R4")
def k_while_match(g):
    return g.s_while_match(g.mk(), g.r.randint(0, 3))


@_kind("for", STMT, "R8")
def k_for(g):
    v = g.mk()
    return g.s_for(v, [g.int_expr(1, True) for _ in range(3)])


@_kind("for_range", STMT, "R8")
def k_for_range(g):
    v = g.mk()
    return g.s_for_range(v, g.int_expr(1, True), g.r.randint(0, 3))


@_kind("lam_twice", STMT, "R6")
def k_lam_twice(g):
    v = g.mk()
    return g.s_lam_twice(v, g.int_expr(1))


@_kind("elif", STMT, "R3")
def k_elif(g):
    return g.s_elif(g.r.choice([10, 60]), g.r.choice([10, 60]))


@_kind("if_stmt", STMT, "R3")
def k_if_stmt(g):
    c1, c2 = g.bool_expr(1), g.bool_expr(1)
    b1, b2, b3 = g.int_expr(1), g.int_expr(1), g.int_expr(1)
    return g.s_if_stmt(c1, c2, b1, b2, b3)


@_kind("match_stmt", STMT, "R4")
def k_match_stmt(g):
    v = g.mk()
    which = g.r.choice(["sh", "p", "or"])
    s = g.int_expr(1, True)
    if which == "sh":
        return g.s_match_variant(v, s, g.r.choice(["Circ", "Sq", "Dot"]))
    if which == "p":
        return g.s_match_struct(v, s, g.int_expr(1, True))
    return g.s_match_or(s, g.r.randint(0, 3))


@_kind("match_guard_effect", STMT, "R4")
def k_match_guard_effect(g):
    # A guard with a side effect: R4 says the guard runs only after its
    # pattern matched. Today the CIR Python emitter refuses a guard that
    # carries a call (UnsupportedInIR): BROKEN on the IR leg, a documented gap.
    s = g.int_expr(1, True)
    l0 = g.r.randint(0, 3)
    g1, g2 = g.mk() % 97 + 1, g.mk() % 97 + 1
    return g.s_match_guard_effect(s, l0, g1, g2, g.r.random() < 0.5)


@_kind("break_continue", STMT, "R7")
def k_break_continue(g):
    v = g.mk()
    return g.s_break_continue(v, g.r.randint(3, 6), g.r.randint(1, 3), g.r.randint(2, 7))


@_kind("tuple", STMT, "R1")
def k_tuple(g):
    v = g.mk()
    return g.s_tuple(v, g.int_expr(1, True), g.int_expr(1, True))


@_kind("try_call", STMT, "R11")
def k_try_call(g):
    return g.s_try_call(g.int_expr(1, True), g.int_expr(1, True))


@_kind("early_return", STMT, "R3")
def k_early_return(g):
    return g.s_early_return(g.mk() % 97 + 1, g.r.random() < 0.3)


@_kind("ovf", STMT, "R9", "R12")
def k_ovf(g):
    big_lit = g.r.choice([4611686018427387904, 3037000500, 9223372036854775807])
    op = g.r.choice(["+", "*", "-"])
    return g.s_ovf(big_lit, op, g.int_expr(1, True))


# ---- programs ----
FAMILIES = ("expr", "sc", "stmt", "mix")


def program(rnd: random.Random, family: str, kinds: Optional[dict] = None) -> tuple:
    """One generated program and its expectation ``(exit, stdout)``, the
    expectation computed by the evaluators of the constructs drawn."""
    g = Gen(rnd, kinds)
    lines, evs = [], []
    for idx in range(rnd.randint(2, 4)):
        fam = family if family != "mix" else rnd.choice(["expr", "sc", "stmt"])
        if fam == "expr":
            s, e = g.int_expr(rnd.randint(1, 3))
            lines += ["    let v%d = %s" % (idx, s), '    stdio.println(" r%d=${v%d}")' % (idx, idx)]
            evs.append(lambda out, e=e, idx=idx: out.append(" r%d=%d\n" % (idx, e(out))))
        elif fam == "sc":
            sb, eb = g.bool_expr(rnd.randint(1, 3))
            lines += ["    let v%d = if %s then 1 else 0" % (idx, sb), '    stdio.println(" b%d=${v%d}")' % (idx, idx)]
            evs.append(lambda out, eb=eb, idx=idx: out.append(" b%d=%d\n" % (idx, 1 if eb(out) else 0)))
        else:
            ls, ev = g.stmt_block()
            lines += ls
            evs.append(ev)
    exit, stdout = g.evaluate(evs)
    return HEADER + MAIN + "\n".join(lines) + "\n", (exit, stdout)


# ---- ANCHORS: expected output written BY HAND from the clause text ----
@dataclass(frozen=True)
class Anchor:
    clause: str
    title: str
    lines: tuple
    evaluate: Callable
    expected_exit: str
    expected_stdout: str

    @property
    def slug(self) -> str:
        return "".join(c if c.isalnum() else "_" for c in self.title).strip("_").lower()

    @property
    def source(self) -> str:
        return HEADER + MAIN + "\n".join(self.lines) + "\n"


def expr_anchor(clause, title, built, markers, value) -> Anchor:
    """An expression anchor: ``let v = <expr>`` then ``v`` printed. ``value``
    is the hand-written result, or ``None`` for an abort; ``markers`` is the
    stdout the expression writes before that."""
    src, ev = built

    def evaluate(out):
        v = ev(out)
        out.append(" v=%s\n" % fmt(v))
    expected = markers if value is None else markers + " v=%s\n" % fmt(value)
    return Anchor(clause, title, ("    let v = %s" % src, '    stdio.println(" v=${v}")'),
                  evaluate, ABORT if value is None else OK, expected)


def stmt_anchor(clause, title, built, expected_stdout, expected_exit=OK) -> Anchor:
    lines, ev = built
    return Anchor(clause, title, tuple(lines), ev, expected_exit, expected_stdout)


def anchors(g: Gen) -> list:
    L, B, C = g.b_leaf, g.b_bleaf, g.b_lit
    MAX = 9223372036854775807
    A = [
        expr_anchor("R1", "R1 operands left to right", g.b_bin("+", L(1), L(2)), "[1][2]", 3),
        expr_anchor("R1", "R1 call arguments in written order", g.b_call(L(3), L(4)), "[3][4]", 34),
        expr_anchor("R1", "R1 struct fields in written order y first", g.b_struct(L(5), L(6), True), "[6][5]", 21),
        expr_anchor("R1", "R1 struct fields evaluated before a field is read", g.b_field(L(5), L(6), True, "x"), "[6][5]", 5),
        expr_anchor("R1", "R1 interpolation segments left to right", g.b_interp(L(7), L(8)), "[7][8]", 3),
        stmt_anchor("R1", "R1 tuple elements left to right", g.s_tuple(1, L(1), L(2)), "[1][2] tup=12\n"),
        expr_anchor("R2", "R2 and short-circuits on false", g.b_and(B(1, False), B(2, True)), "[1]", False),
        expr_anchor("R2", "R2 or short-circuits on true", g.b_or(B(1, True), B(2, False)), "[1]", True),
        expr_anchor("R2", "R2 and evaluates the right operand when the left is true", g.b_and(B(1, True), B(2, False)), "[1][2]", False),
        expr_anchor("R3", "R3 if expression evaluates only the then branch", g.b_ife(B(9, True), L(1), L(2)), "[9][1]", 1),
        expr_anchor("R3", "R3 if expression evaluates only the else branch", g.b_ife(B(9, False), L(1), L(2)), "[9][2]", 2),
        stmt_anchor("R3", "R3 if statement runs only the chosen arm", g.s_if_stmt(B(1, False), B(2, True), L(3), L(4), L(5)), "[1][2][4] B4\n"),
        stmt_anchor("R3", "R3 elif stops at the first condition that holds", g.s_elif(60, 10), "[60] e=1\n"),
        stmt_anchor("R3", "R3 elif conditions in order", g.s_elif(10, 60), "[10][60] e=2\n"),
        stmt_anchor("R3", "R3 return ends main at once",
                    (g.s_early_return(7, True)[0] + ['    stdio.println(" after")'],
                     lambda out, ev=g.s_early_return(7, True)[1]: (ev(out), out.append(" after\n"))),
                    "[7]"),
        expr_anchor("R4", "R4 match scrutinee once and only the chosen arm", g.b_match(L(2), [L(10), L(11), L(12)], [1, 2]), "[2][11]", 11),
        stmt_anchor("R4", "R4 match statement guard holds", g.s_match_variant(1, L(5), "Circ"), "[5] bigcirc\n"),
        stmt_anchor("R4", "R4 match statement guard fails falls through", g.s_match_variant(1, L(2), "Circ"), "[2] circ=2\n"),
        stmt_anchor("R4", "R4 match or pattern", g.s_match_or(L(1), 0), "[1] lo\n"),
        stmt_anchor("R4", "R4 match struct pattern with guard", g.s_match_struct(1, L(2), L(2)), "[2][2] eq=2\n"),
        stmt_anchor("R4", "R4 guard runs only after its pattern matched", g.s_match_guard_effect(L(3), 0, 11, 12, True), "[3][12] g2\n"),
        stmt_anchor("R4", "R4 guard that fails falls to the next arm", g.s_match_guard_effect(L(0), 0, 11, 12, False), "[0][11][12] g3\n"),
        expr_anchor("R6", "R6 lambda body runs per call", g.b_lam(L(5), L(1)), "[1][5]", 6),
        stmt_anchor("R6", "R6 lambda body runs once per call not at definition", g.s_lam_twice(1, L(5)), "[5][5] l=13\n"),
        stmt_anchor("R7", "R7 while condition before every iteration and once at exit", g.s_while(1, 2), "[0][1][2] w=2\n"),
        stmt_anchor("R7", "R7 while match condition re-evaluated", g.s_while_match(1, 1), "[0][1] wm=1\n"),
        stmt_anchor("R7", "R7 continue re-tests and break leaves", g.s_break_continue(1, 4, 2, 3), "{1} k=3\n"),
        stmt_anchor("R8", "R8 for over a list iterable evaluated once", g.s_for(1, [L(1), L(2), L(3)]), "[1][2][3]<1><2><3> f=6\n"),
        stmt_anchor("R8", "R8 range a to b minus one", g.s_for_range(1, L(1), 3), "[1]<1><2><3> fr=6\n"),
        expr_anchor("R9", "R9 overflow aborts", g.b_bin("+", C(MAX), C(1)), "", None),
        expr_anchor("R9", "R9 floored division minus 7 over 2 is minus 4", g.b_bin("/", g.b_neg(C(7)), C(2)), "", -4),
        expr_anchor("R9", "R9 modulo takes the divisor sign minus 7 mod 3 is 2", g.b_bin("%", g.b_neg(C(7)), C(3)), "", 2),
        expr_anchor("R9", "R9 modulo 7 mod minus 3 is minus 2", g.b_bin("%", C(7), g.b_neg(C(3))), "", -2),
        expr_anchor("R9", "R9 division by zero aborts", g.b_bin("/", C(7), C(0)), "", None),
        stmt_anchor("R9", "R9 multiplication overflow aborts in a statement", g.s_ovf(4611686018427387904, "*", L(2)), "[2]", ABORT),
        expr_anchor("R10", "R10 index out of bounds aborts", g.b_index([L(1), L(2), L(3)], 3), "[1][2][3]", None),
        expr_anchor("R10", "R10 index in bounds", g.b_index([L(1), L(2), L(3)], 1), "[1][2][3]", 2),
        stmt_anchor("R11", "R11 question mark returns early on Err", g.s_try_call(L(3), L(2)), "[3][2][3] err=odd\n"),
        stmt_anchor("R11", "R11 question mark continues on Ok", g.s_try_call(L(2), L(4)), "[2][4][2][4] ok=12\n"),
        expr_anchor("R12", "R12 abort keeps the stdout written before it", g.b_bin("+", g.b_bin("+", L(1), C(MAX)), L(2)), "[1]", None),
        expr_anchor("R13", "R13 less or equal holds on equality", g.b_cmp("<=", L(3), L(3)), "[3][3]", True),
        expr_anchor("R13", "R13 greater or equal holds on equality", g.b_cmp(">=", L(3), L(3)), "[3][3]", True),
        expr_anchor("R13", "R13 less than fails on equality", g.b_cmp("<", L(3), L(3)), "[3][3]", False),
        expr_anchor("R13", "R13 not equal", g.b_cmp("!=", L(3), L(4)), "[3][4]", True),
        expr_anchor("R13", "R13 not negates", g.b_not(B(1, True)), "[1]", False),
        expr_anchor("R14", "R14 list get out of range yields the default", g.b_list([L(1), L(2), L(3)], 3), "[1][2][3]", 0),
        expr_anchor("R14", "R14 list get in range yields the element", g.b_list([L(1), L(2), L(3)], 1), "[1][2][3]", 2),
        expr_anchor("R14", "R14 string length counts characters", g.b_strlen("abc"), "", 3),
        expr_anchor("R14", "R14 empty string length is zero", g.b_strlen(""), "", 0),
    ]
    return A


def check_anchors(g: Gen, anchor_list: Optional[list] = None) -> list:
    """Every anchor through the evaluator; returns the failures as
    ``(anchor, wanted, got)``. Empty means the evaluator agrees with every
    hand-written expectation."""
    fails = []
    for a in (anchors(g) if anchor_list is None else anchor_list):
        got = g.evaluate([a.evaluate])
        want = (a.expected_exit, a.expected_stdout)
        if got != want:
            fails.append((a, want, got))
    return fails


def clauses_without_anchor(anchor_list: list, kinds: dict) -> dict:
    """Clause ids no anchor pins, mapped to the loaded kinds that exercise
    them. A clause none of the loaded kinds exercises is a documented gap of
    the loaded grammar; one that a loaded kind exercises is a hole."""
    anchored = {a.clause for a in anchor_list}
    out = {}
    for c in CLAUSES:
        if c.id not in anchored:
            out[c.id] = sorted(k.name for k in kinds.values() if c.id in k.clauses)
    return out


def default_generator() -> Gen:
    return Gen(random.Random(0))
