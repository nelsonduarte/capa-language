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

from dataclasses import dataclass
from typing import Callable

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


def fmt(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)
