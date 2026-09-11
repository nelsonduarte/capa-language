# 05. Base types, structs, tuples, sum types

> **What this chapter covers.** The scalar types (`Int`, `Float`,
> `String`, `Char`, `Bool`, `Unit`), their size and arithmetic
> semantics, structs (`type X { ... }`), sum types / variants, tuples,
> the built-in `Option`/`Result` with the `?` operator, the containers
> (`List`/`Map`/`Set`/`Range`), structural equality, and the absence of
> type aliases. Anchored in the real type system and executed on both
> backends.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10, `python -m capa` importing the checkout under specification.
Primary reading sources: [`capa/typesys.py`](../capa/typesys.py),
[`capa/builtins.py`](../capa/builtins.py),
[`capa/runtime/_safety.py`](../capa/runtime/_safety.py), and
[`docs/stdlib.md`](../docs/stdlib.md) (verified against the compiler,
not copied).

Depends on: [04-grammar.md](04-grammar.md).

---

## 1. The five primitives and Unit

The set of primitive names has its source of truth in
[`capa/typesys.py`](../capa/typesys.py) line 133 (`PRIMITIVE_NAMES`),
and each one is a predefined `TyName`:

| Type | Size / domain | Notes |
|---|---|---|
| `Int` | signed 64-bit integer | checked arithmetic (section 2) |
| `Float` | IEEE 754 binary64 | |
| `String` | UTF-8, immutable | indexed by codepoint, not by byte |
| `Char` | one Unicode codepoint | at runtime, a `String` of length 1 |
| `Bool` | `true` / `false` | keywords, not literals (see [03-lexis-and-layout.md](03-lexis-and-layout.md)) |
| `Unit` | `()` | the "empty" type of functions with no return |

`Unit` is not a member of `PRIMITIVE_NAMES`: it is its own singleton in
the type system (`_TyUnitSingleton`, `capa/typesys.py` line 102),
written `()` in both type and expression position. The five primitives
**cannot be redefined** by the programmer; they are seeded as symbols in
the global scope in [`capa/builtins.py`](../capa/builtins.py) line 572
(a fact with direct consequence in
[07-pattern-matching.md](07-pattern-matching.md)).

Declaring and printing a value of each type, on both backends:

```capa
// base.capa
fun main(stdio: Stdio)
    let i: Int = -9223372036854775808
    let big: Int = 9223372036854775807
    let f: Float = 3.5
    let c: Char = 'z'
    let b: Bool = true
    let u: Unit = ()
    stdio.println("i=${i} big=${big}")
    stdio.println("f=${f} c=${c} b=${b}")
    stdio.println("int div=${7 / 2} int mod=${7 % 2}")
    stdio.println("float div=${7.0 / 2.0}")
```

```
$ python -m capa --run base.capa
i=-9223372036854775808 big=9223372036854775807
f=3.5 c=z b=true
int div=3 int mod=1
float div=3.5
$ python -m capa --run --wasm base.capa
i=-9223372036854775808 big=9223372036854775807
f=3.5 c=z b=true
int div=3 int mod=1
float div=3.5
```

The two backends produce identical output. Note that `7 / 2` is `3`
(integer division) and `7.0 / 2.0` is `3.5`: the `/` and `%` operators
are integral over `Int` and floating over `Float`, with no implicit
coercion between the two.

## 2. `Int` arithmetic: checked overflow

`Int` addition, subtraction, multiplication, division and shifts are
checked on both backends: on overflow the program **aborts** instead of
wrapping. The shared oracle is
[`capa/runtime/_safety.py`](../capa/runtime/_safety.py) (`_capa_iadd`
line 53, `_capa_isub` line 67, `_capa_imul` line 77, `_capa_idiv` line
87, plus the shift guards); division additionally catches division by
zero and the `i64::MIN / -1` case. On the Wasm backend the same checks
are emitted as inline overflow-detection bytecode, which is how parity
is kept.

`2^63 - 1` plus 1 aborts on both backends, with the same exit code:

```capa
// ovf.capa
fun main(stdio: Stdio)
    let big: Int = 9223372036854775807
    stdio.println("before")
    stdio.println("${big + 1}")
    stdio.println("after")
```

```
$ python -m capa --run ovf.capa 2>/dev/null; echo "py exit=$?"
before
py exit=1
$ python -m capa --run --wasm ovf.capa 2>/dev/null; echo "wasm exit=$?"
before
wasm exit=1
```

In both cases the `after` line is never printed: the overflow
interrupts. On the Python backend it is an `OverflowError`
(`Int addition overflows signed 64-bit: 9223372036854775807 + 1 = ...`);
on the Wasm backend it is a trap
(`wasm trap: wasm 'unreachable' instruction executed`), which the CLI
turns into exit 1. The error text differs between backends (a readable
Python exception versus a Wasm trap), but the observable effect (abort,
exit 1, next line not executed) is the same.

JUDGEMENT. Checked overflow is a security decision consistent with
Capa's posture: a silently wrapping `Int` is a classic source of
exploitable bugs.

## 3. No implicit numeric coercion

`Float + Int` is a type error; conversion must be explicit (`to_float`,
`to_int`):

```capa
// coerce.capa
fun main(stdio: Stdio)
    let a: Float = 2.0
    let b: Int = 3
    stdio.println("${a + b}")
```

```
$ python -m capa --check coerce.capa
coerce.capa:4:22: error: operator '+': incompatible operand types Float and Int
   4 |     stdio.println("${a + b}")
                            ^
```

## 4. `Char` and `String`: asymmetric compatibility

A `Char` is by definition exactly one codepoint, so it is **always** a
valid `String`: where a `String` is expected, a char literal is
accepted. The relation is asymmetric (`compatible` in
[`capa/typesys.py`](../capa/typesys.py) line 294:
`compatible(String, Char)` is true, `compatible(Char, String)` is
false): a `Char` fits a `String` slot, but an arbitrary (possibly
multi-codepoint) `String` does **not** fit a `Char` slot.

```capa
// charstr.capa
fun main(stdio: Stdio)
    let s: String = 'z'
    stdio.println(s)
```

```
$ python -m capa --run charstr.capa
z
$ python -m capa --run --wasm charstr.capa
z
```

The two backends produce identical output.

## 5. Structs

A struct (record) is declared with `type Name { field: Type, ... }`
(named fields between braces). Fields carry **no visibility modifier**:
`pub` applies only to top-level items (see [04-grammar.md](04-grammar.md)
section 4). It is constructed with `Name { field: value, ... }` and read
with `.field`.

Construction, field access and structural equality (section 9), on both
backends:

```capa
// point.capa
type Point {
    x: Int,
    y: Int
}

fun main(stdio: Stdio)
    let p = Point { x: 1, y: 2 }
    let q = Point { x: 1, y: 2 }
    let r = Point { x: 3, y: 4 }
    stdio.println("p.x=${p.x} p.y=${p.y}")
    stdio.println("p==q: ${p == q}")
    stdio.println("p==r: ${p == r}")
```

```
$ python -m capa --run point.capa
p.x=1 p.y=2
p==q: true
p==r: false
$ python -m capa --run --wasm point.capa
p.x=1 p.y=2
p==q: true
p==r: false
```

The two backends produce identical output. A struct can be generic
(`type Pair<A, B> { first: A, second: B }`), can be marked `linear`
(must-consume, see
[14-linearity-consume-typestates.md](14-linearity-consume-typestates.md)),
and can implement traits (see
[06-generics-and-traits.md](06-generics-and-traits.md)).

## 6. Sum types (variants)

A sum type is declared with `type Name =` followed by a `NEWLINE` and
the variants indented, one per line. A variant is a name (nullary) or a
name with a positional payload (`Circle(Float)`, `Rect(Float, Float)`).
Payloads are **positional**: named payload fields are deferred past 1.0
(see [04-grammar.md](04-grammar.md) section 12). Struct and sum are
syntactically distinct by design (braces versus `=` plus indentation).

A sum type with nullary and payload variants, consumed by `match`, and
structural equality over variants, on both backends:

```capa
// shape.capa
type Shape =
    Circle(Float)
    Rect(Float, Float)
    Dot

fun describe(s: Shape) -> String
    return match s
        Circle(r) -> "circle r=${r}"
        Rect(w, h) -> "rect ${w}x${h}"
        Dot -> "dot"

fun main(stdio: Stdio)
    stdio.println(describe(Circle(2.0)))
    stdio.println(describe(Rect(3.0, 4.0)))
    stdio.println(describe(Dot))
    stdio.println("eq:  ${Circle(2.0) == Circle(2.0)}")
    stdio.println("neq: ${Circle(2.0) == Dot}")
```

```
$ python -m capa --run shape.capa
circle r=2.0
rect 3.0x4.0
dot
eq:  true
neq: false
$ python -m capa --run --wasm shape.capa
circle r=2.0
rect 3.0x4.0
dot
eq:  true
neq: false
```

The two backends produce identical output. `match` over variants and
exhaustiveness are in [07-pattern-matching.md](07-pattern-matching.md).

### 6.1 Reserved variant names

Four variant names are reserved by semantic analysis, because they
collide with the built-in `Option`/`Result` constructors: `Ok`, `Err`,
`Some`, `None`. Redefining one is an error, with a renaming hint (each
offending variant is reported):

```capa
// resv.capa
type Maybe =
    Some(Int)
    None
```

```
$ python -m capa --check resv.capa
resv.capa:3:5: error: variant 'Some' is reserved (collides with the built-in Option::Some constructor). Rename this variant. Common alternatives: Present, Hit, Just, Filled.
   3 |     Some(Int)
           ^

resv.capa:4:5: error: variant 'None' is reserved (collides with the built-in Option::None constructor). Rename this variant. Common alternatives: Empty, Absent, Missing, Null.
   4 |     None
           ^

resv.capa: 2 errors
```

## 7. Tuples

A tuple is a positional, heterogeneous aggregate, written `(a, b, ...)`.
The grammar distinguishes `(x)` (parenthesized expression) from `(x,)`
(one-element tuple) by the comma; `()` is the `Unit` value, not a tuple
(see [04-grammar.md](04-grammar.md) section 9.1). A tuple destructures
by pattern in `let`/`for` (see
[07-pattern-matching.md](07-pattern-matching.md)).

A typed tuple, destructured by `let`, on both backends:

```capa
// tup.capa
fun main(stdio: Stdio)
    let pair: (Int, String) = (7, "hi")
    let (n, msg) = pair
    stdio.println("${n} ${msg}")
```

```
$ python -m capa --run tup.capa
7 hi
$ python -m capa --run --wasm tup.capa
7 hi
```

The two backends produce identical output. Tuples appear as the natural
result of several container methods (`List.enumerate -> List<(Int, T)>`,
`Map.pairs -> List<(K, V)>`, `List.zip`).

## 8. `Option`, `Result` and the `?` operator

`Option<T>` and `Result<T, E>` are built-in sum types
([`docs/stdlib.md`](../docs/stdlib.md), Option/Result sections), with
the shape:

```capa
type Option<T> =
    Some(T)
    None

type Result<T, E> =
    Ok(T)
    Err(E)
```

Their constructors (`Some`/`None`/`Ok`/`Err`) and methods (`unwrap_or`,
`map`, `and_then`, `ok_or`, `map_err`, ...) are available without
import. The `?` operator (postfix, level 14; see
[04-grammar.md](04-grammar.md) section 9) propagates an `Err` early: in
a function returning `Result`, `expr?` evaluates `Ok(v)` to `v`, or
performs an immediate `return Err(e)`.

`Option` with `unwrap_or`, `Result` with `?` chaining failures, on both
backends:

```capa
// optres.capa
fun half(n: Int) -> Option<Int>
    if n % 2 == 0
        return Some(n / 2)
    return None

fun checked(n: Int) -> Result<Int, String>
    if n < 0
        return Err("negative")
    return Ok(n * 10)

fun chain(a: Int, b: Int) -> Result<Int, String>
    let x = checked(a)?
    let y = checked(b)?
    return Ok(x + y)

fun main(stdio: Stdio)
    stdio.println("half(8)=${half(8).unwrap_or(-1)}")
    stdio.println("half(7)=${half(7).unwrap_or(-1)}")
    match chain(2, 3)
        Ok(v) -> stdio.println("chain ok=${v}")
        Err(e) -> stdio.println("chain err=${e}")
    match chain(-1, 3)
        Ok(v) -> stdio.println("chain ok=${v}")
        Err(e) -> stdio.println("chain err=${e}")
```

```
$ python -m capa --run optres.capa
half(8)=4
half(7)=-1
chain ok=50
chain err=negative
$ python -m capa --run --wasm optres.capa
half(8)=4
half(7)=-1
chain ok=50
chain err=negative
```

The two backends produce identical output: in `chain(-1, 3)`, the first
`?` over `checked(-1)` (an `Err`) returns immediately, and the second
`?` is never evaluated.

## 9. Structural equality

The `==` operator is **structural** and by value (sections 5 and 6):
two structs are equal when all fields are equal; two variants are equal
when they are the same variant with equal payloads. There is no
reference/identity equality in 1.0. Equality extends recursively to
composite fields and payloads (structs inside structs, tuples,
containers). Comparisons **do not chain** (`a == b == c` is an error,
see [04-grammar.md](04-grammar.md) section 9).

## 10. Containers: `List`, `Map`, `Set`, `Range`

The four container constructors are generic and built-in. The
exhaustive method reference is [`docs/stdlib.md`](../docs/stdlib.md);
this section fixes the model and executed examples.

- **`List<T>`**: homogeneous mutable list. Literal `[a, b, c]`; `push`
  mutates; `xs[i]` indexes, and an out-of-bounds index aborts the
  program on both backends (exit 1; `get(i) -> Option<T>` is the safe
  path). Cross-statement inference: `let xs = []` fixes `T` at the
  first `push`.
- **`Map<K, V>`**: hash map, built with `new_map()` under a mandatory
  type annotation. `get(k) -> Option<V>`, `set(k, v)` mutates. (Scope
  note: on the Wasm backend the Map is currently a linear array,
  `get`/`set` are O(N); the semantics, insertion order and in-place
  overwrite, are identical on both backends. See the
  [`docs/stdlib.md`](../docs/stdlib.md) performance note.)
- **`Set<T>`**: insertion-ordered set, built with `new_set()`.
  `add`/`remove` mutate; `union`/`intersection`/`difference` return a
  fresh set.
- **`Range<Int>`**: `a..b` (exclusive) and `a..=b` (inclusive) produce
  an iterable of `Int`, consumable directly in a `for` on both
  backends. Both endpoints must be `Int` (`Float` endpoints are
  deliberately rejected). A `Range` is **not** a `List`: it is not
  indexable and does not coerce; it carries a small subset of the
  `List` API, with `to_list()` as the way across (see
  [`docs/stdlib.md`](../docs/stdlib.md)).

`List` with `push`/`map`/`fold`, `Map` with `set`/`get`, `Set` with
deduplication, on both backends:

```capa
// cont.capa
fun main(stdio: Stdio)
    var xs = [1, 2, 3]
    xs.push(4)
    let doubled = xs.map(fun (x: Int) -> Int => x * 2)
    stdio.println("len=${xs.length()} sum=${xs.fold(0, fun (a: Int, x: Int) -> Int => a + x)}")
    stdio.println("first=${doubled.first().unwrap_or(-1)}")
    let m: Map<String, Int> = new_map()
    m.set("a", 1)
    m.set("b", 2)
    stdio.println("m[a]=${m.get("a").unwrap_or(0)} has_c=${m.contains_key("c")}")
    let s: Set<Int> = new_set()
    s.add(5)
    s.add(5)
    s.add(6)
    stdio.println("set len=${s.length()} has5=${s.contains(5)}")
```

```
$ python -m capa --run cont.capa
len=4 sum=10
first=2
m[a]=1 has_c=false
set len=2 has5=true
$ python -m capa --run --wasm cont.capa
len=4 sum=10
first=2
m[a]=1 has_c=false
set len=2 has5=true
```

The two backends produce identical output, including the `Set`
deduplication (two `add(5)` give length 2, not 3).

### 10.1 Removal, ordering and string-splitting methods

The container and string surface includes `List.pop`, `List.sorted`,
`List.min`, `List.max`, `Map.remove`, `Map.filter`, `String.lines`,
`String.split_once` and `String.find_index`. Their decided semantics,
each point verified by the run below:

- **`List.pop() -> Option<T>` and `Map.remove(k) -> Option<V>` MUTATE
  the receiver** and return the removed value; `None` for the empty
  list / absent key. The removal is visible through every alias, like
  `push`. **`Set.remove` returns `()`** (signature at
  [`capa/builtins.py`](../capa/builtins.py) line 317): the caller
  supplied the value itself, so there is no new information to return.
  The design axis: return what the caller does not already hold.
- **`sorted()` (fresh copy, ascending, stable), `min()` and `max()` are
  admitted only for element types the ordering operators accept**:
  `Int`, `Float`, `String`, and `Char` (via `String` compatibility).
  The predicate consults the SAME `ORDERED_TYPES` set the operators use
  ([`capa/typesys.py`](../capa/typesys.py) line 148, with
  `is_ordered_element` at line 151), so the methods cannot diverge from
  the `<` operator. `min`/`max` on an empty list return `None`, like
  `first`/`last`/`get`.
- **The `Float` order the compiler supplies is TOTAL**: `NaN` sorts
  after every number and the non-`NaN` elements stay ascending,
  byte-identical on the three execution paths (measured below).
  `sorted_by` orders by a user-supplied comparator instead; backend
  behaviour under user comparators is
  [24-backend-parity.md](24-backend-parity.md)'s subject.
- **`lines()`** strips the terminators (`\r\n`, `\n`, lone `\r`;
  `\r\n` tested first) and produces no phantom trailing empty element;
  **`split_once(sep)`** cuts at the FIRST occurrence and returns `None`
  when `sep` does not occur; **`find_index(pred)`** returns the
  codepoint index (never a byte offset) of the first character
  satisfying the predicate.

A program exercising all nine, run on the three execution paths
(`--run`, `--run --ir`, `--run --wasm`) with output compared by `cmp`:

```capa
// methods9.capa
fun show(xs: List<Int>) -> String
    return xs.fold("", fun (acc: String, x: Int) -> String => acc + "${x}|")

fun main(stdio: Stdio)
    var xs = [3, 1, 2]
    let p = xs.pop()
    stdio.println("pop=${p.unwrap_or(0 - 1)} after=${show(xs)}")
    let ys = [3, 1, 2]
    stdio.println("sorted=${show(ys.sorted())} original=${show(ys)}")
    stdio.println("min=${ys.min().unwrap_or(0 - 1)} max=${ys.max().unwrap_or(0 - 1)}")
    let empty: List<Int> = []
    stdio.println("empty_min_none=${empty.min().is_none()} empty_pop_none=${empty.pop().is_none()}")
    var m: Map<String, Int> = new_map()
    m.set("a", 1)
    m.set("b", 2)
    let r = m.remove("a")
    stdio.println("m_remove=${r.unwrap_or(0 - 1)} left=${m.length()} absent_none=${m.remove("zz").is_none()}")
    let f = m.filter(fun (k: String, v: Int) -> Bool => v > 1)
    stdio.println("m_filter=${f.length()}")
    let lf = "\n"
    let text = "a" + "\r\n" + "b" + lf + "c" + lf
    let ls = text.lines()
    stdio.println("lines=${ls.length()} l0=${ls.get(0).unwrap_or("?")} l1=${ls.get(1).unwrap_or("?")} l2=${ls.get(2).unwrap_or("?")}")
    match "k=v=w".split_once("=")
        Some(pair) ->
            let (before, rest) = pair
            stdio.println("split_once=${before}/${rest}")
        None -> stdio.println("split_once=none")
    stdio.println("split_once_absent_none=${"abc".split_once("|").is_none()}")
    stdio.println("find_index=${"hello".find_index(fun (c: String) -> Bool => c == "l").unwrap_or(0 - 1)}")
```

```
$ python -m capa --run methods9.capa
pop=2 after=3|1|
sorted=1|2|3| original=3|1|2|
min=1 max=3
empty_min_none=true empty_pop_none=true
m_remove=1 left=1 absent_none=true
m_filter=1
lines=3 l0=a l1=b l2=c
split_once=k/v=w
split_once_absent_none=true
find_index=2
```

The three paths (`--run`, `--run --ir`, `--run --wasm`) produced this
output byte-identically (`cmp` true between the three, exit 0 on all
three). Note `split_once=k/v=w`: the cut is at the FIRST occurrence
(`split("=")` would give three parts); `find_index=2` is the codepoint
index; and `sorted` leaves the receiver `original=3|1|2|` intact (fresh
copy).

An element type outside the ordered set is refused at `--check`, with
the same text on the Wasm path:

```capa
// ordbool.capa
fun main(stdio: Stdio)
    let xs = [true, false]
    let s = xs.sorted()
    stdio.println("${s.length()}")
```

```
$ python -m capa --check ordbool.capa
ordbool.capa:4:13: error: method 'sorted': List<Bool> has no order the compiler can supply; Bool is not accepted by the ordering operators either. Use sorted_by with your own comparator to order it.
   4 |     let s = xs.sorted()
                   ^

ordbool.capa: 1 error
```

The total `Float` order with a `NaN` (obtained without a literal: a
`Float` multiplied past the largest finite value is `inf`, and
`inf - inf` is `NaN`), identical on the three paths:

```
$ python -m capa --run nan_total.capa    # [2.0, nan, 3.0, 1.0, 4.0]
sorted=1.0|2.0|3.0|4.0|nan|
min=1.0
max_self_eq=false
```

(`max_self_eq=false` because `NaN != NaN`: `max()` returned the `NaN`
itself, the last element of the total order.)

Scope note. On the Wasm backend, `Map.filter` requires the receiver's
type to be known at the binding (annotate
`let m: Map<String, Int> = new_map()`); when it is not, `--wasm` refuses
loudly instead of guessing, while the same program still runs on the
Python backend ([`docs/stdlib.md`](../docs/stdlib.md), Map table). The
exhaustive reference remains [`docs/stdlib.md`](../docs/stdlib.md),
verified against [`capa/builtins.py`](../capa/builtins.py).

A container **cannot** carry a built-in capability: a capability flows
only as a bare top-level value (a direct parameter), never inside a
`List`/`Set`/`Map`/tuple. The exact rejection is in
[06-generics-and-traits.md](06-generics-and-traits.md) section 6 and in
[02-authority-in-types.md](02-authority-in-types.md).

## 11. No type aliases

Capa has **no** type aliases in 1.0. The form `type Name = OtherType`
does not declare an alias: `=` always starts a sum type, and the parser
requires a `NEWLINE` next (the variants indented on the following
lines). A scalar alias on the same line is therefore a parse error:

```capa
// alias.capa
type Id = Int
```

```
$ python -m capa --check alias.capa
alias.capa:2:11: error: expected newline after '=' in sum type; got IDENT 'Int'
   2 | type Id = Int
                 ^
```

A "new name" for an existing type is obtained, when desired, with a
one-field struct (`type Id { value: Int }`) or a one-variant sum type
with a payload, not with a transparent alias. The grammar in
[04-grammar.md](04-grammar.md) has no type-alias production.

---

## Links

- [04-grammar.md](04-grammar.md): the syntactic productions for
  `type_decl`, tuples, and container literals.
- [06-generics-and-traits.md](06-generics-and-traits.md): generic
  structs and sum types, traits, and why capabilities cannot be type
  arguments.
- [07-pattern-matching.md](07-pattern-matching.md): `match`,
  exhaustiveness and destructuring of these composite types.
- [09-expressions-and-control.md](09-expressions-and-control.md): the
  arithmetic and comparison operators of section 2.
- [`docs/stdlib.md`](../docs/stdlib.md): the exhaustive method
  reference for `String`/`List`/`Map`/`Set`/`Option`/`Result`.
