"""The evaluator SELF-TEST: one-clause errors planted in the evaluator.

The only check of the rule that needs no executor: the anchor table is a
second, hand-written statement of the rule, and every mutant below must
fail at least one anchor. A mutant that fails none is a hole in the anchor
table (RED). A new clause lands with its anchor and a mutant here.
"""

from __future__ import annotations

from tests.instruments._outcome import ABORT
from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._rule import Abort, Return, chk, idiv, imod


def gm4_untaken_else(g: Gen) -> None:
    """The if-expression evaluates the untaken else too (the lowering
    mutant M4, mirrored in the evaluator)."""
    def b_ife(c, a, b):
        (sc, ec), (sa, ea), (sb, eb) = c, a, b
        return "(if %s then %s else %s)" % (sc, sa, sb), (
            lambda out: (lambda cv: (eb(out), ea(out))[1] if cv else eb(out))(ec(out)))
    g.b_ife = b_ife


def eager_and(g: Gen) -> None:
    def b_and(a, b):
        (sa, ea), (sb, eb) = a, b
        return "(%s and %s)" % (sa, sb), (lambda out: (lambda x, y: x and y)(ea(out), eb(out)))
    g.b_and = b_and


def unbounded_int(g: Gen) -> None:
    def b_bin(op, a, b):
        (sa, ea), (sb, eb) = a, b
        f = {"+": lambda x, y: x + y, "-": lambda x, y: x - y, "*": lambda x, y: x * y, "/": idiv, "%": imod}[op]
        return "(%s %s %s)" % (sa, op, sb), (lambda out: f(ea(out), eb(out)))
    g.b_bin = b_bin


def index_clamp(g: Gen) -> None:
    def b_index(items, i):
        def ev(out):
            vals = [e(out) for _, e in items]
            return vals[i] if i < len(vals) else 0
        return "[%s][%d]" % (", ".join(s for s, _ in items), i), ev
    g.b_index = b_index


def trunc_div(g: Gen) -> None:
    def b_bin(op, a, b):
        (sa, ea), (sb, eb) = a, b

        def tdiv(x, y):
            if y == 0:
                raise Abort("division by zero")
            return chk(int(x / y))

        def tmod(x, y):
            if y == 0:
                raise Abort("division by zero")
            return chk(x - int(x / y) * y)
        f = {"+": lambda x, y: chk(x + y), "-": lambda x, y: chk(x - y), "*": lambda x, y: chk(x * y),
             "/": tdiv, "%": tmod}[op]
        return "(%s %s %s)" % (sa, op, sb), (lambda out: f(ea(out), eb(out)))
    g.b_bin = b_bin


def match_all_arms(g: Gen) -> None:
    def b_match(s, arms, lits):
        ss, es = s
        src = "(match %s { %d -> %s, %d -> %s, _ -> %s })" % (
            ss, lits[0], arms[0][0], lits[1], arms[1][0], arms[2][0])

        def ev(out):
            v = es(out)
            vals = [a[1](out) for a in arms]
            return vals[0] if v == lits[0] else vals[1] if v == lits[1] else vals[2]
        return src, ev
    g.b_match = b_match


def cmp_le_as_lt(g: Gen) -> None:
    orig = g.b_cmp

    def b_cmp(op, a, b):
        src, ev = orig(op, a, b)
        if op == "<=":
            (sa, ea), (sb, eb) = a, b
            return src, (lambda out: ea(out) < eb(out))
        return src, ev
    g.b_cmp = b_cmp


def not_identity(g: Gen) -> None:
    def b_not(a):
        sa, ea = a
        return "(not %s)" % sa, (lambda out: ea(out))
    g.b_not = b_not


def list_get_clamp(g: Gen) -> None:
    def b_list(items, i):
        def ev(out):
            vals = [e(out) for _, e in items]
            return vals[i] if i < len(vals) else vals[-1]
        return "[%s].get(%d).unwrap_or(0)" % (", ".join(s for s, _ in items), i), ev
    g.b_list = b_list


def strlen_plus_one(g: Gen) -> None:
    g.b_strlen = lambda s: ('"%s".length()' % s, (lambda out: len(s) + 1))


def range_inclusive(g: Gen) -> None:
    orig = g.s_for_range

    def s_for_range(v, a, n):
        lines, _ev = orig(v, a, n)
        sa, ea = a

        def ev(out):
            start = ea(out)
            tot = 0
            for x in range(start, start + n + 1):
                out.append("<%d>" % x)
                tot = chk(tot + x)
            out.append(" fr=%d\n" % tot)
        return lines, ev
    g.s_for_range = s_for_range


def break_as_continue(g: Gen) -> None:
    orig = g.s_break_continue

    def s_break_continue(v, lim, skip, stop):
        lines, _ev = orig(v, lim, skip, stop)

        def ev(out):
            k = 0
            while k < lim:
                k += 1
                if k == skip or k == stop:
                    continue
                out.append("{%d}" % k)
            out.append(" k=%d\n" % k)
        return lines, ev
    g.s_break_continue = s_break_continue


def while_condition_not_retested_at_exit(g: Gen) -> None:
    orig = g.s_while

    def s_while(v, nlim):
        lines, _ev = orig(v, nlim)

        def ev(out):
            i = 0
            while i < nlim:
                out.append("[%d]" % i)
                i += 1
            out.append(" w=%d\n" % i)
        return lines, ev
    g.s_while = s_while


def try_continues_on_err(g: Gen) -> None:
    orig = g.s_try_call

    def s_try_call(a, b):
        lines, _ev = orig(a, b)

        def ev(out):
            x = a[1](out)
            y = b[1](out)
            out.append("[%d]" % x)
            out.append("[%d]" % y)
            if x % 2 != 0 or y % 2 != 0:
                out.append(" err=odd\n")
                return
            out.append(" ok=%d\n" % chk((x // 2) * 10 + y // 2))
        return lines, ev
    g.s_try_call = s_try_call


def abort_drops_stdout(g: Gen) -> None:
    orig = g.evaluate

    def evaluate(evs):
        exit, stdout = orig(evs)
        return exit, ("" if exit == ABORT else stdout)
    g.evaluate = evaluate


def guard_before_pattern(g: Gen) -> None:
    orig = g.s_match_guard_effect

    def s_match_guard_effect(s, l0, g1, g2, gtrue):
        lines, _ev = orig(s, l0, g1, g2, gtrue)

        def ev(out):
            val = s[1](out)
            out.append("[%d]" % g1)
            if val == l0 and gtrue:
                out.append(" g1\n")
                return
            out.append("[%d]" % g2)
            if val > 1:
                out.append(" g2\n")
                return
            out.append(" g3\n")
        return lines, ev
    g.s_match_guard_effect = s_match_guard_effect


def return_ignored(g: Gen) -> None:
    orig = g.s_early_return

    def s_early_return(n, b):
        lines, _ev = orig(n, b)
        return lines, (lambda out: out.append("[%d]" % n))
    g.s_early_return = s_early_return


def lambda_body_at_definition(g: Gen) -> None:
    orig = g.s_lam_twice

    def s_lam_twice(v, a):
        lines, _ev = orig(v, a)
        sa, ea = a

        def ev(out):
            body = ea(out)
            out.append(" l=%d\n" % chk(chk(1 + body) + chk(2 + body)))
        return lines, ev
    g.s_lam_twice = s_lam_twice


def struct_fields_in_declaration_order(g: Gen) -> None:
    orig = g.b_struct

    def b_struct(a, b, swapped):
        src, _ev = orig(a, b, swapped)
        (sa, ea), (sb, eb) = a, b
        return src, (lambda out: (lambda xv, yv: chk(xv * 3 + yv))(ea(out), eb(out)))
    g.b_struct = b_struct


MUTANTS = {
    "GM4_UNTAKEN_ELSE": gm4_untaken_else,
    "EAGER_AND": eager_and,
    "UNBOUNDED_INT": unbounded_int,
    "INDEX_CLAMP": index_clamp,
    "TRUNC_DIV": trunc_div,
    "MATCH_ALL_ARMS": match_all_arms,
    "CMP_LE_AS_LT": cmp_le_as_lt,
    "NOT_IDENTITY": not_identity,
    "LIST_GET_CLAMP": list_get_clamp,
    "STRLEN_PLUS_ONE": strlen_plus_one,
    "RANGE_INCLUSIVE": range_inclusive,
    "BREAK_AS_CONTINUE": break_as_continue,
    "WHILE_NOT_RETESTED_AT_EXIT": while_condition_not_retested_at_exit,
    "TRY_CONTINUES_ON_ERR": try_continues_on_err,
    "ABORT_DROPS_STDOUT": abort_drops_stdout,
    "GUARD_BEFORE_PATTERN": guard_before_pattern,
    "RETURN_IGNORED": return_ignored,
    "LAMBDA_BODY_AT_DEFINITION": lambda_body_at_definition,
    "STRUCT_FIELDS_DECLARATION_ORDER": struct_fields_in_declaration_order,
}
