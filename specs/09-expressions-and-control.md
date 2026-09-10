# 09. Expressions, operators and control flow

> **What this chapter covers.** Expressions and their precedence (the
> parser's recursive-descent chain); `if-then-else` (ternary) and
> `match` as expressions; blocks and the absence of implicit return;
> `let`/`var`; the `for` and `while` loops; `?` propagation; string
> interpolation; and the exact operator semantics (signed
> division/modulo, bitwise, shifts, short-circuit), verified on both
> backends.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10, `python -m capa` importing the checkout under specification.
Primary sources:
[`capa/parser/_expressions.py`](../capa/parser/_expressions.py) (the
precedence chain and the ternary),
[`capa/parser/_statements.py`](../capa/parser/_statements.py)
(`let`/`var`/`for`/`while`/`match`),
[`capa/analyzer/_items.py`](../capa/analyzer/_items.py) (the
return-on-every-path rule), and
[`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py) (floored
division and short-circuit semantics).

Depends on: [04-grammar.md](04-grammar.md).

---

## 1. The precedence chain

Expressions parse by recursive descent, one function per precedence
level ([`capa/parser/_expressions.py`](../capa/parser/_expressions.py)),
weakest-binding first. The normative table is in
[04-grammar.md](04-grammar.md) section 9; condensed here:

| Level | Operators | Associativity |
|---|---|---|
| 1 | `if-then-else` (ternary) | Right |
| 2 | `or` | Left |
| 3 | `and` | Left |
| 4 | `not` (unary) | - |
| 5 | `==` `!=` `<` `<=` `>` `>=` | **Non-associative** |
| 6 | `..` `..=` (range) | **Non-associative** |
| 7 | `\|` (bitwise or) | Left |
| 8 | `^` (bitwise xor) | Left |
| 9 | `&` (bitwise and) | Left |
| 10 | `<<` `>>` | Left |
| 11 | `+` `-` (binary) | Left |
| 12 | `*` `/` `%` | Left |
| 13 | `-` (unary) | Right |
| 14 | `.` `()` `[]` `?` (postfix) | Left |

Practical consequences: the logical connectives bind weaker than the
comparisons (`a < b and c < d` parses as `(a < b) and (c < d)`); the
bitwise operators bind between the comparisons/range and the arithmetic
(stronger than `and`/comparison, weaker than `+`); unary `-` binds
stronger than any binary operator (`-a * b` is `(-a) * b`); postfix
(`.`, call, index, `?`) is the strongest.

Arithmetic precedence and parentheses, on both backends:

```capa
// prec.capa
fun main(stdio: Stdio)
    stdio.println("2+3*4 = ${2 + 3 * 4}")
    stdio.println("(2+3)*4 = ${(2 + 3) * 4}")
```

```
$ python -m capa --run prec.capa
2+3*4 = 14
(2+3)*4 = 20
$ python -m capa --run --wasm prec.capa
2+3*4 = 14
(2+3)*4 = 20
```

### 1.1 Comparisons and ranges do not chain

Levels 5 and 6 are **non-associative**: writing two operators of the
same level in a chain is a syntax error. The comparison check is at
[`capa/parser/_expressions.py`](../capa/parser/_expressions.py) line
218.

A chained comparison, rejected:

```
$ python -m capa --check chain.capa      # body: return 1 < x < 10
chain.capa:2:18: error: comparison operators are non-associative; use parentheses or boolean operators to combine
   2 |     return 1 < x < 10
                        ^
```

A chained range, rejected:

```capa
// rng.capa
fun main(stdio: Stdio)
    let r = 1..5..10
    stdio.println("x")
```

```
$ python -m capa --check rng.capa
rng.capa:3:17: error: expected newline after let binding
   3 |     let r = 1..5..10
                       ^
```

## 2. `if`/`match` as expressions versus statements

This is the central control-flow distinction in Capa.

- `if`/`elif`/`else`, `while` and `for` are **statements**. They
  produce no value and cannot appear in expression position.
- The ternary `if c then a else b` is an **expression** (level 1). It
  requires both `then` and `else`; `then` is the disambiguator between
  the `if` statement (followed by a block) and the `if` expression
  ([`capa/parser/_expressions.py`](../capa/parser/_expressions.py) line
  176).
- `match` is **both**: the same production serves as statement and as
  expression.

An `if` block in expression position is rejected (missing `then`); the
ternary works:

```
$ python -m capa --check ifexpr.capa      # let x = if 3 > 2 <newline> ...
ifexpr.capa:3:21: error: expected 'then' in if-expression; got NEWLINE '\n'
   3 |     let x = if 3 > 2
                           ^
```

```capa
// tern.capa
fun main(stdio: Stdio)
    let x = if 3 > 2 then "big" else "small"
    stdio.println("${x}")
```

```
$ python -m capa --run tern.capa
big
$ python -m capa --run --wasm tern.capa
big
```

Ternaries chain to the right for the "else if" effect:
`if n > 0 then "+" else if n < 0 then "-" else "0"` (see the integrated
example in [04-grammar.md](04-grammar.md) section 11).

`match` as an expression (the value of the chosen arm is the value of
the match):

```capa
// matchexpr.capa
type Shape =
    Circle(Float)
    Rect(Float, Float)

fun area(s: Shape) -> Float
    return match s
        Circle(r) -> 3.14159 * r * r
        Rect(w, h) -> w * h

fun main(stdio: Stdio)
    stdio.println("circle = ${area(Circle(2.0))}")
    stdio.println("rect   = ${area(Rect(3.0, 4.0))}")
```

```
$ python -m capa --run matchexpr.capa
circle = 12.56636
rect   = 12.0
$ python -m capa --run --wasm matchexpr.capa
circle = 12.56636
rect   = 12.0
```

Pattern details, guards and exhaustiveness are in
[07-pattern-matching.md](07-pattern-matching.md).

## 3. Blocks and the absence of implicit return

A block is an indented statement sequence
(`block = NEWLINE INDENT { statement } DEDENT`). Capa has **no**
implicit return of a block's last expression (unlike Rust/OCaml): a
loose tail expression is an `expression_stmt`, not the function's
value. A function with a declared return type requires every path to
end in `return` ([`capa/analyzer/_items.py`](../capa/analyzer/_items.py),
diagnostic at line 456).

The tail expression is not a return:

```
$ python -m capa --check impret.capa      # body: a + b (no return)
impret.capa:2:5: error: function 'add' declares return type but not every path ends in `return`; the function will fall through and return None at runtime
   2 | fun add(a: Int, b: Int) -> Int
           ^
```

To produce a value at a decision point, use the ternary or `match`
(section 2), not an `if` statement.

## 4. `let` and `var`

```ebnf
let_stmt = "let" pattern [ ":" type ] "=" expression NEWLINE
var_stmt = "var" IDENT   [ ":" type ] "=" expression NEWLINE
```

`let` binds an immutable value and admits pattern destructuring
(`let (a, b) = pair`, `let Some(x) = ...` in an exhaustive context).
`var` binds a mutable variable and admits **only** `IDENT` (mutability
only makes sense for a simple variable). Parser `_parse_let_stmt`
([`capa/parser/_statements.py`](../capa/parser/_statements.py) line 82)
and `_parse_var_stmt` (line 96). The type annotation is optional
(inferred from the RHS) except where inference does not reach.

Compound assignment (`=`, `+=`, `-=`, `*=`, `/=`, `%=`) applies to an
lvalue (name, field, or index); only a `var` variable (or a mutable
field/index) is a legitimate target.

## 5. `?`: `Result` propagation

The postfix `?` operator (level 14) over a `Result<T, E>`: on `Ok(v)`
it evaluates to `v`; on `Err(e)` it returns early from the enclosing
function with that `Err(e)`. The enclosing function must therefore
return a `Result` with the same error type.

`?` chaining two fallible operations, on both backends:

```capa
// ctrl.capa
fun checked_div(a: Int, b: Int) -> Result<Int, String>
    if b == 0
        return Err("divide by zero")
    return Ok(a / b)

fun compute(a: Int, b: Int, c: Int) -> Result<Int, String>
    let first = checked_div(a, b)?
    let second = checked_div(first, c)?
    return Ok(second)

fun main(stdio: Stdio)
    let r = match compute(100, 5, 2)
        Ok(v) -> v
        Err(_) -> -1
    stdio.println("r = ${r}")
    let bad = match compute(100, 0, 2)
        Ok(v) -> v
        Err(msg) -> -1
    stdio.println("bad = ${bad}")
```

```
$ python -m capa --run ctrl.capa
r = 10
bad = -1
$ python -m capa --run --wasm ctrl.capa
r = 10
bad = -1
```

In `compute(100, 0, 2)`, the first `?` meets `Err("divide by zero")`
and returns it early; the `Err` arm of the `match` in `main` produces
`-1`. The two backends produce identical output.

## 6. `for` and `while` loops

```ebnf
while_stmt = "while" expression block
for_stmt   = "for" pattern "in" expression block
```

`while` repeats while the condition is true; `for` iterates over an
iterable (a `List`, or a range `a..b`/`a..=b`). `for` binds a pattern
per iteration (destructuring included). Parser `_parse_while_stmt`
([`capa/parser/_statements.py`](../capa/parser/_statements.py) line
136) and `_parse_for_stmt` (line 143). `break` and `continue` control
the loop.

Ranges: `a..b` is **exclusive** (does not include `b`); `a..=b` is
inclusive.

`while`, `for` over a list and `for` over an exclusive range, with
`if`/`elif`/`else`, on both backends:

```capa
// flow.capa
fun classify(n: Int) -> String
    if n < 0
        return "neg"
    elif n == 0
        return "zero"
    else
        return "pos"

fun main(stdio: Stdio)
    for n in [-2, 0, 7]
        stdio.println("${n} -> ${classify(n)}")
    var s = 0
    for i in 0..3
        s += i
    stdio.println("sum 0..3 = ${s}")
    var i = 0
    var acc = 0
    while i < 5
        acc += i
        i += 1
    stdio.println("acc = ${acc}")
```

```
$ python -m capa --run flow.capa
-2 -> neg
0 -> zero
7 -> pos
sum 0..3 = 3
acc = 10
$ python -m capa --run --wasm flow.capa
-2 -> neg
0 -> zero
7 -> pos
sum 0..3 = 3
acc = 10
```

`0..3` sums `0+1+2 = 3` (exclusive range); the `while` sums
`0+1+2+3+4 = 10`. The two backends produce identical output.

## 7. String interpolation

A normal string admits `${ expression }`: the expression is evaluated
and formatted in place (lexis in
[03-lexis-and-layout.md](03-lexis-and-layout.md) section 5.6). The
interpolated value must have a `to_string` method; a composite value
without one (for example a raw `List<Int>`) is refused at analysis for
both backends:

```
$ python -m capa --check nostr.capa      # ${doubled} where doubled: List<Int>
nostr.capa:5:32: error: cannot interpolate a value of type List<Int> in a string: it has no `to_string` method, so neither backend can render it. Use a `match` expression to format it explicitly, or define `fun to_string(self) -> String` for List<Int>.
   5 |     stdio.println("doubled = ${doubled}")
                                      ^

nostr.capa: 1 error
```

## 8. Operator semantics

### 8.1 Integer arithmetic: floored division, modulo takes the divisor's sign

`Int` is signed 64-bit. Integer division `/` **rounds down** (floor,
toward negative infinity), and modulo `%` takes the sign of the
**divisor** (floored semantics, Python style). The Python backend uses
`_capa_idiv` (which floors) and the Wasm backend uses `i64.div_s` plus
a floor correction, deliberately so the two backends agree
([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py) lines 63 to
73). Division by zero and `MIN / -1` trap on both backends.

Division and modulo with negative operands, bitwise and shifts, on
both backends:

```capa
// ops.capa
fun main(stdio: Stdio)
    stdio.println("7/2 = ${7 / 2}")
    stdio.println("-7/2 = ${-7 / 2}")
    stdio.println("7%3 = ${7 % 3}")
    stdio.println("-7%3 = ${-7 % 3}")
    stdio.println("7%-3 = ${7 % -3}")
    stdio.println("6&3 = ${6 & 3}")
    stdio.println("6|1 = ${6 | 1}")
    stdio.println("6^3 = ${6 ^ 3}")
    stdio.println("1<<4 = ${1 << 4}")
    stdio.println("-1>>1 = ${-1 >> 1}")
    stdio.println("2.5*2.0 = ${2.5 * 2.0}")
```

```
$ python -m capa --run ops.capa
7/2 = 3
-7/2 = -4
7%3 = 1
-7%3 = 2
7%-3 = -2
6&3 = 2
6|1 = 7
6^3 = 5
1<<4 = 16
-1>>1 = -1
2.5*2.0 = 5.0
$ python -m capa --run --wasm ops.capa
7/2 = 3
-7/2 = -4
7%3 = 1
-7%3 = 2
7%-3 = -2
6&3 = 2
6|1 = 7
6^3 = 5
1<<4 = 16
-1>>1 = -1
2.5*2.0 = 5.0
```

Points to fix: `-7 / 2 = -4` (floor, not truncation toward zero, which
would give `-3`); `-7 % 3 = 2` and `7 % -3 = -2` (the result inherits
the divisor's sign); `-1 >> 1 = -1` (arithmetic shift, preserves the
sign). The two backends produce identical output, including these
signed corner cases.

### 8.2 Logical operators: `and`, `or`, `not`, with short-circuit

The logical connectives are words (`and`, `or`, `not`), not
`&&`/`||`/`!`. `and` and `or` evaluate with **short-circuit**
([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py) maps them to
the backend's native short-circuit).

Short-circuit demonstrated with observable effects (a side that only
prints if evaluated), on both backends:

```capa
// sc.capa
fun loud(stdio: Stdio, tag: String, v: Bool) -> Bool
    stdio.println("eval ${tag}")
    return v

fun main(stdio: Stdio)
    stdio.println("-- and short-circuits on false --")
    let a = loud(stdio, "A", false) and loud(stdio, "B", true)
    stdio.println("-- or short-circuits on true --")
    let b = loud(stdio, "C", true) or loud(stdio, "D", false)
    stdio.println("a=${a} b=${b}")
```

```
$ python -m capa --run sc.capa
-- and short-circuits on false --
eval A
-- or short-circuits on true --
eval C
a=false b=true
$ python -m capa --run --wasm sc.capa
-- and short-circuits on false --
eval A
-- or short-circuits on true --
eval C
a=false b=true
```

`and` stops at `A` (the left side is `false`, `B` is never evaluated);
`or` stops at `C` (the left side is `true`, `D` is never evaluated).
The two backends produce identical output, including the order and the
absence of the `eval B`/`eval D` lines.

---

## Links

- [04-grammar.md](04-grammar.md): the normative precedence table and
  the expression, statement and pattern productions.
- [03-lexis-and-layout.md](03-lexis-and-layout.md): the operators,
  literals and `${...}` interpolation at the lexical level.
- [07-pattern-matching.md](07-pattern-matching.md): `match`, guards,
  or-patterns and exhaustiveness.
- [08-functions-closures-modules.md](08-functions-closures-modules.md):
  the return-on-every-path rule and lambdas.
- [05-base-and-composite-types.md](05-base-and-composite-types.md):
  `Result`, `Option`, and the equality the comparisons use.
