"""The public grammar KINDS of instrument (a): each draws its parameters
from the generator's random source and calls one builder, naming the
clauses it exercises. A private extension adds kinds to a copy of this
registry; the public corpora are generated over this one alone.
"""

from __future__ import annotations

import random

from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._rule import BOOL, HEADER, INT, MAIN, STMT, Kind

PUBLIC_KINDS: dict = {}


def _kind(name: str, category: str, *clauses: str):
    def register(fn):
        PUBLIC_KINDS[name] = Kind(name, category, tuple(clauses), fn)
        return fn
    return register


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


def program(rnd: random.Random, family: str, kinds: dict) -> tuple:
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
