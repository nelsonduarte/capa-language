# 07. Pattern matching and destructuring

> **What this chapter covers.** `match` (statement and expression),
> the pattern forms (literal, wildcard, binding, tuple, variant,
> struct), or-patterns and guards, the exhaustiveness the analyzer
> requires, destructuring in `let` and `for`, and the type check of a
> struct pattern against its scrutinee (concrete structs, primitives,
> rigid type parameters, trait-typed scrutinees).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification. Primary sources:
[`capa/parser/_patterns.py`](../capa/parser/_patterns.py) (syntax),
[`capa/analyzer/_patterns.py`](../capa/analyzer/_patterns.py)
(binding and type check), [`capa/builtins.py`](../capa/builtins.py)
(primitives seeded as struct symbols).

Depends on: [05-base-and-composite-types.md](05-base-and-composite-types.md).

---

## 1. `match`: statement and expression

`match` is the same production used as statement and as expression
([04-grammar.md](04-grammar.md) section 8). An arm is
`pattern [ "if" guard ] "->" ( expression | block )`. There are two
forms: the indented one (multi-line, block bodies) and the inline
`{ p -> e, ... }` for single-line expression position.

`match` as an expression (inside a `return`), with literals, an
or-pattern and guards, run on both backends:

```capa
// lit.capa
fun classify(n: Int) -> String
    return match n
        0 -> "zero"
        1 | 2 | 3 -> "small"
        _ if n < 0 -> "negative"
        _ -> "big"

fun main(stdio: Stdio)
    for x in [-5, 0, 2, 99]
        stdio.println("${x} -> ${classify(x)}")
```

```
$ python -m capa --run lit.capa
-5 -> negative
0 -> zero
2 -> small
99 -> big
$ python -m capa --run --wasm lit.capa
-5 -> negative
0 -> zero
2 -> small
99 -> big
```

The two backends produce identical output. Arms are tested in order;
the first that matches (and whose guard, if any, is true) wins.

## 2. The pattern forms

Source: [`capa/parser/_patterns.py`](../capa/parser/_patterns.py);
grammar in [04-grammar.md](04-grammar.md) section 10.

| Form | Syntax | Binds names? | Notes |
|---|---|---|---|
| Literal | `0`, `3.5`, `"esc"`, `'a'`, `true` | no | equality with the scrutinee |
| Wildcard | `_` | no | matches everything, binds nothing |
| Binding | `x` (IDENT) | yes (`x`) | matches everything, binds the value to `x` |
| Tuple | `(p1, p2, ...)` | the sub-patterns | fixed arity |
| Variant | `Ctor` or `Ctor(p1, ...)` | the sub-patterns | over a sum type |
| Struct | `Name { field, field: p }` | the fields / sub-patterns | see section 6 |

A `field_pattern` is `IDENT [ ":" pattern ]`: `Person { name, age }`
binds `name` and `age` directly (shorthand), while
`Person { name: n }` binds the `name` field to the name `n`, or to a
sub-pattern. Patterns nest: `Click(Point { x, y })` matches a `Click`
variant whose payload is a `Point`, binding `x` and `y`.

Nested patterns (a variant containing a struct), a guard over a
binding, and struct destructuring in a `for`, on both backends:

```capa
// pm.capa
type Point {
    x: Int,
    y: Int
}

type Event =
    Click(Point)
    Key(String)
    Quit

fun handle(e: Event) -> String
    return match e
        Click(Point { x, y }) -> "click ${x},${y}"
        Key(k) if k == "esc" -> "escape"
        Key(k) -> "key ${k}"
        Quit -> "quit"

fun main(stdio: Stdio)
    let pts = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]
    for Point { x, y } in pts
        stdio.println("pt ${x},${y}")
    let events = [Click(Point { x: 5, y: 6 }), Key("esc"), Key("a"), Quit]
    for e in events
        stdio.println(handle(e))
```

```
$ python -m capa --run pm.capa
pt 1,2
pt 3,4
click 5,6
escape
key a
quit
$ python -m capa --run --wasm pm.capa
pt 1,2
pt 3,4
click 5,6
escape
key a
quit
```

The two backends produce identical output. Note `Key(k) if k == "esc"`
followed by `Key(k)`: the guarded arm comes first, and the second
`Key` catches the rest.

## 3. Or-patterns and guards

An or-pattern (`A | B | C -> body`) is valid only at the match-arm
level ([04-grammar.md](04-grammar.md) section 10). The analyzer
requires each alternative to bind exactly the same set of names, with
compatible types (so `1 | 2 | 3` above, which binds nothing, is
valid; `Some(x) | None` would not be, because `None` does not bind
`x`; the rejection is measured in [04-grammar.md](04-grammar.md)
section 10). A guard (`if expr`) is a boolean condition evaluated
after the pattern matches; when false, the `match` moves to the next
arm.

## 4. Exhaustiveness

A `match` over a sum type must be exhaustive: cover every variant, or
close with `_`. A non-exhaustive `match` is an error, and the
diagnostic names the missing variants:

```capa
// exh.capa
type Color =
    Red
    Green
    Blue

fun name(c: Color) -> String
    return match c
        Red -> "red"
        Green -> "green"
```

```
$ python -m capa --check exh.capa
exh.capa:8:12: error: non-exhaustive match on 'Color': missing variants Blue (add '_ -> ...' to handle remaining cases)
   8 |     return match c
                  ^
```

## 5. Destructuring in `let` and `for`

Patterns are used with uniform syntax in `let`, `for` and `match`.
`let (a, b) = pair` destructures a tuple;
`let Person { name, age } = p` destructures a struct;
`for Point { x, y } in pts` destructures each element of the
iterable. (`var` admits only an `IDENT`, see
[04-grammar.md](04-grammar.md) section 8.)

```capa
// sd.capa
type Person {
    name: String,
    age: Int
}

fun main(stdio: Stdio)
    let p = Person { name: "Ana", age: 30 }
    let Person { name, age } = p
    stdio.println("${name} is ${age}")
```

```
$ python -m capa --run sd.capa
Ana is 30
$ python -m capa --run --wasm sd.capa
Ana is 30
```

The two backends produce identical output.

## 6. The type check of a struct pattern against its scrutinee

A struct-destructuring binder binds each field with the type it has
in the PATTERN's struct. If the pattern could name a different struct
than the value's, the scrutinee's fields would be relabelled under the
other struct's types, which is both a type error and an IFC
laundering channel (a public-twin pattern over a `@secret` value).
The analyzer therefore checks the pattern's struct name against the
scrutinee's static type
([`capa/analyzer/_patterns.py`](../capa/analyzer/_patterns.py)). The
measured behaviour, case by case:

### 6.1 Wrong concrete struct: rejected at `--check`

Destructuring a `Person` with a `Point` pattern:

```capa
// sdwrong.capa (main body)
    let p = Person { name: "Ana", age: 30 }
    let Point { x, y } = p
```

```
$ python -m capa --check sdwrong.capa
sdwrong.capa:12:9: error: destructuring pattern names 'Point', but the value has type Person
  12 |     let Point { x, y } = p
               ^
```

### 6.2 Primitive scrutinee: rejected at `--check`

A struct pattern over an `Int` (and likewise `String`, `Bool`) is
rejected at `--check` with the same diagnostic; the five primitives
are seeded as struct-kind symbols
([`capa/builtins.py`](../capa/builtins.py) line 572), so the
struct-mismatch guard recognizes them:

```capa
// sdprim.capa (main body)
    let n = 5
    let Person { name, age } = n
```

```
$ python -m capa --check sdprim.capa
sdprim.capa:8:9: error: destructuring pattern names 'Person', but the value has type Int
   8 |     let Person { name, age } = n
               ^
```

### 6.3 Rigid type-parameter scrutinee: rejected as an unprovable downcast

Destructuring a value whose static type is a RIGID type parameter is
a downcast the compiler cannot justify by parametricity, and the
binder refuses it (closed in 1.32.0; advisory
[`docs/advisories/2026-08-22-ifc-rigid-destructure-launder.md`](../docs/advisories/2026-08-22-ifc-rigid-destructure-launder.md),
GHSA-7pf3-h2cq-52wm):

```capa
// rigid.capa
type PublicTwin {
    v: String
}

fun peek<T>(t: T) -> String
    let PublicTwin { v } = t
    return v
```

```
$ python -m capa --check rigid.capa
rigid.capa:7:9: error: destructuring pattern names 'PublicTwin', but the value has generic type T: a value of a generic type parameter cannot be destructured as a concrete struct because the compiler cannot prove it has that type
   7 |     let PublicTwin { v } = t
               ^
```

A FLEXIBLE inference placeholder is excluded from the refusal, so the
for-destructure of an empty list stays legal (advisory, face 3).

### 6.4 Trait-typed scrutinee: fields lifted to the label join over implementors

A struct pattern over a TRAIT-typed scrutinee is a downcast that is
legitimate in general, so the binder accepts it; each bound field is
lifted to the JOIN of the declared labels of the same-named field
across all of the trait's concrete implementors, a sound upper bound
with no runtime tag. A public-twin downcast of a value whose sibling
implementor has a `@secret` field therefore surfaces at the sink:
a WARNING at the default tier, a HARD ERROR under `@strict_ifc`.
Measured on both tiers with two implementors (`SecretBox` with
`v: @secret String`, `PublicTwin` with `v: String`) and a
`fun peek(c: Carrier, ...)` doing `let PublicTwin { v } = c`:

```
$ python -m capa --check traitjoin.capa
traitjoin.capa:23:19: warning: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
traitjoin.capa: ok (7 items, 10 expressions typed, 5 bindings)

$ python -m capa --check traitjoin_strict.capa   # same, with @strict_ifc on peek
traitjoin_strict.capa:24:19: error: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. ...
traitjoin_strict.capa: 1 error
```

The Wasm backend refuses the trait-destructure class loudly at
emission (measured:
`capa: --wasm: FieldAccess on receiver of type 'Carrier': no struct
layout known. ...`), so no Wasm artefact is produced for it; the form
is supported on the Python backend under the IFC tiers above.

---

## Links

- [05-base-and-composite-types.md](05-base-and-composite-types.md):
  the records and sum types these patterns consume.
- [04-grammar.md](04-grammar.md): the grammar of `match`, patterns,
  and `let`/`for` destructuring.
- [06-generics-and-traits.md](06-generics-and-traits.md): generic
  field types in destructuring, and traits as types.
- [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md) and
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md): the
  label model behind the laundering checks of section 6, and the
  warn-versus-strict tiers.
