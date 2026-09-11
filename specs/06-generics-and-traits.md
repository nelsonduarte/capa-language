# 06. Generics, traits, impl, monomorphisation

> **What this chapter covers.** Type parameters on types and
> functions; generic instantiation (inference, and why the explicit
> form `f<T>(...)` does not parse in expression position); traits
> (declaration, `impl`, and traits used as a type, Capa's limited
> polymorphism mechanism, since `<T: Trait>` bounds are deferred); the
> monomorphisation the backends use; and how generics interact with
> capabilities (a capability is never a type argument). Verified
> examples of a generic struct, a trait with two impls, and
> instantiation by inference.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification. Primary sources:
[`capa/analyzer/_dispatch.py`](../capa/analyzer/_dispatch.py)
(inference and dispatch),
[`capa/analyzer/_discipline.py`](../capa/analyzer/_discipline.py)
(the capability-in-type-param barrier),
[`capa/ir/_monomorphise/`](../capa/ir/_monomorphise/__init__.py) (the
monomorphisation pass),
[`capa/ir/_emit_wasm/_traits.py`](../capa/ir/_emit_wasm/_traits.py)
(dynamic dispatch on Wasm), and
[`docs/reference.md`](../docs/reference.md) section 2.4.

Depends on: [05-base-and-composite-types.md](05-base-and-composite-types.md).

---

## 1. Type parameters on types and functions

Types and functions take type parameters delimited by `< >`
(`generic_params` in [04-grammar.md](04-grammar.md) section 3). A type
parameter is fully parametric: in 1.0 **there are no bounds**
(`<T: Trait>` is deferred, section 4), so a generic function's body
can only do to a `T` what any type supports (pass it, store it,
return it, compare it with `==`).

A generic struct `Pair<A, B>` and a generic function `swap<A, B>`,
run on both backends:

```capa
// gen.capa
type Pair<A, B> {
    first: A,
    second: B
}

fun swap<A, B>(p: Pair<A, B>) -> Pair<B, A>
    return Pair { first: p.second, second: p.first }

fun main(stdio: Stdio)
    let p = Pair { first: 1, second: "one" }
    let q = swap(p)
    stdio.println("p: ${p.first} ${p.second}")
    stdio.println("q: ${q.first} ${q.second}")
```

```
$ python -m capa --run gen.capa
p: 1 one
q: one 1
$ python -m capa --run --wasm gen.capa
p: 1 one
q: one 1
```

The two backends produce identical output. Here `Pair<Int, String>` is
inferred from the literal, and `swap` produces `Pair<String, Int>`.

## 2. Generic instantiation: by inference, not explicit at the call site

The type arguments of a generic call are **inferred** from the value
arguments. The caller almost never needs (nor can, in expression
position) write the type arguments.

```capa
// geninst.capa
fun first<T>(xs: List<T>) -> Option<T>
    return xs.first()

fun log_first<T>(xs: List<T>, stdio: Stdio, label: String)
    match first(xs)
        Some(v) -> stdio.println("${label}: got one")
        None -> stdio.println("${label}: empty")

fun main(stdio: Stdio)
    let a = first([1, 2, 3])
    stdio.println("inferred: ${a.unwrap_or(-1)}")
    log_first([10, 20], stdio, "ints")
    log_first(["a"], stdio, "strs")
```

```
$ python -m capa --run geninst.capa
inferred: 1
ints: got one
strs: got one
$ python -m capa --run --wasm geninst.capa
inferred: 1
ints: got one
strs: got one
```

The two backends produce identical output. `first` is called with a
`List<Int>` and with a `List<String>`, and `T` resolves at each call
site.

Explicit type arguments do NOT parse in expression position: there,
`<` and `>` are comparison operators, so `first<Int>([1,2,3])` reads
as the comparison chain `first < Int > (...)`, which is rejected
(comparisons do not chain), exactly as
[`docs/reference.md`](../docs/reference.md) section 2.4 documents:

```capa
// badinst.capa (main body)
    let a = first<Int>([1, 2, 3])
```

```
$ python -m capa --check badinst.capa
badinst.capa:6:22: error: comparison operators are non-associative; use parentheses or boolean operators to combine
   6 |     let a = first<Int>([1, 2, 3])
                            ^
```

Explicit `< >` type arguments are valid in **type position**
(`List<Int>`, `Pair<A, B>`, `Option<T>`) and in type-parameter
declarations (`fun first<T>(...)`), but **not** at an
expression-position call site. The turbofish `::<T>` is a deferred
form ([04-grammar.md](04-grammar.md) section 12).

## 3. Traits: declaration and `impl`

A `trait` declares a set of method signatures
([04-grammar.md](04-grammar.md) section 5). A type implements the
trait with an `impl Trait for Type` block, which provides a body for
each method (there are no default trait bodies in 1.0). The first
parameter of an instance method is `self`.

A `Shape` trait with two methods, two impls (`Circle`, `Square`), run
on both backends:

```capa
// trait.capa
trait Shape
    fun area(self) -> Float
    fun name(self) -> String

type Circle {
    r: Float
}

type Square {
    side: Float
}

impl Shape for Circle
    fun area(self) -> Float
        return 3.14159 * self.r * self.r
    fun name(self) -> String
        return "circle"

impl Shape for Square
    fun area(self) -> Float
        return self.side * self.side
    fun name(self) -> String
        return "square"

fun report(s: Shape, stdio: Stdio)
    stdio.println("${s.name()} area=${s.area()}")

fun main(stdio: Stdio)
    let shapes: List<Shape> = [Circle { r: 1.0 }, Square { side: 2.0 }]
    for s in shapes
        report(s, stdio)
```

```
$ python -m capa --run trait.capa
circle area=3.14159
square area=4.0
$ python -m capa --run --wasm trait.capa
circle area=3.14159
square area=4.0
```

The two backends produce identical output.

## 4. Traits as a type: Capa's limited polymorphism

Section 3 uses `Shape` **as a type** (`fun report(s: Shape, ...)`,
`List<Shape>`). This is Capa's limited polymorphism mechanism: instead
of a bounded type parameter (`<T: Shape>`, which does not exist), the
trait itself is written as the type, and dispatch is **dynamic** to
the concrete impl.

Bounds on type parameters are a deferred form; the syntax is rejected
in the parser:

```capa
// bound.capa
trait Named
    fun name(self) -> String

fun greet<T: Named>(x: T) -> String
    return "hi ${x.name()}"
```

```
$ python -m capa --check bound.capa
bound.capa:5:12: error: expected '>' to close type parameter list; got COLON ':'
   5 | fun greet<T: Named>(x: T) -> String
                  ^
```

JUDGEMENT. The practical consequence: where other languages write
`fun f<T: Trait>(x: T)`, in Capa one writes `fun f(x: Trait)`. The
difference is operational (dynamic per-type dispatch at runtime, not
per-instance monomorphisation), but the usage effect is the same. On
the Wasm backend, a trait with multiple impls compiles to a
trait value that is a single `i32` pointer to the struct, with a
type-id at a uniform offset of each participating struct and a
dispatch chain to the concrete method
([`capa/ir/_emit_wasm/_traits.py`](../capa/ir/_emit_wasm/_traits.py),
and the canonical example
[`examples/wasm/multi_impl_dispatch.capa`](../examples/wasm/multi_impl_dispatch.capa)).
On the Python backend dispatch is native method dispatch. The output
is byte-identical (section 3).

## 5. Monomorphisation (for the Wasm backend)

JUDGEMENT with a reading anchor. The lowerer leaves generic functions
ungeneralised: `fun first<T>(...)` reaches the IR with
`type_params=["T"]` and a body whose types still mention `T`. The
Python backend tolerates this (duck typing), but the Wasm backend
needs a concrete layout. The
[`capa/ir/_monomorphise/`](../capa/ir/_monomorphise/__init__.py) pass
walks the IR and, for each call to a generic function whose
substitution is inferable from the argument types, synthesizes a
specialized clone (mangled name, `T` replaced by the concrete type)
and rewrites the call to the clone. After the pass, the module has no
generic functions and no type-variable calls, and the Wasm backend
emits normally. Clone names sanitise every type token for the WAT
identifier charset, including state-qualified typestates
(`Sock[Open]` becomes the `_St_` token; measured in
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)
section 6).

The examples of sections 1 to 3 (generic struct, free generic
function with inference, trait with two impls) all run on the Wasm
backend with output identical to Python, which empirically confirms
monomorphisation of generic structs and free generic functions, and
dynamic trait dispatch.

Scope note. The `_monomorphise` docstring's "Scope (v1)" lists generic
`impl<T>` methods as out of scope; `impl<T>` blocks are a deferred
form ([04-grammar.md](04-grammar.md) section 12), and a program using
a generic form outside the covered scope receives the loud
"no Wasm encoding" class of error from the backend, not a wrong
result.

## 6. Generics and capabilities: a capability is never a type argument

This is the contact point between generics and the authority model of
[02-authority-in-types.md](02-authority-in-types.md). A built-in
capability **only flows as a bare top-level value** (a direct
parameter named in the type). It cannot be substituted into a generic
type parameter, because that would hide the authority flow from the
signature. The analyzer refuses it in two places: substituting an
argument in a generic call, and a return type instantiating to a
capability ([`capa/analyzer/_discipline.py`](../capa/analyzer/_discipline.py)
line 638).

Passing `Stdio` to a generic `identity<T>`:

```capa
// capgen.capa
fun identity<T>(x: T) -> T
    return x

fun main(stdio: Stdio)
    let s = identity(stdio)
    s.println("hi")
```

```
$ python -m capa --check capgen.capa
capgen.capa:6:22: error: call to identity: argument 1 substitutes capability 'Stdio' into a generic type parameter; the function's signature does not declare it as a capability flow (capabilities must appear by name in the signature)
   6 |     let s = identity(stdio)
                            ^

capgen.capa:6:13: error: call to identity: return type substitutes capability 'Stdio' into a generic type parameter; the function's signature does not declare it as a capability flow (capabilities must appear by name in the signature)
   6 |     let s = identity(stdio)
                   ^

capgen.capa: 2 errors
```

Two barriers fire: the argument and the return would instantiate `T`
to `Stdio`. The message is precise about the cause: "capabilities must
appear by name in the signature". The same holds for a capability
stored in a generic struct field (`Box { value: stdio }`): there the
general "container of capabilities" and "capability in a let binding"
rules of [05-base-and-composite-types.md](05-base-and-composite-types.md)
section 10 and [02-authority-in-types.md](02-authority-in-types.md)
section 3 also fire.

JUDGEMENT. The correct way for a generic function to exercise
authority is to receive the capability **by name** in a dedicated
parameter, alongside the generic:
`fun log_first<T>(xs: List<T>, stdio: Stdio, label: String)` (section
2) does so, and the `Stdio` stays visible in the signature. A trait
method (or user-defined capability) can declare the capability atoms
it exercises with a `uses [...]` clause
([04-grammar.md](04-grammar.md) section 5), covered in
[13-user-defined-capabilities.md](13-user-defined-capabilities.md).

---

## Links

- [05-base-and-composite-types.md](05-base-and-composite-types.md):
  the records and sum types that become generic here.
- [02-authority-in-types.md](02-authority-in-types.md): why a
  capability is never a type argument (section 6).
- [07-pattern-matching.md](07-pattern-matching.md): the `match` that
  consumes generic `Option`/`Result` variants.
- [13-user-defined-capabilities.md](13-user-defined-capabilities.md):
  capabilities defined as traits, and the `uses` clause.
- [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  monomorphisation and trait dispatch in the Wasm emitter.
