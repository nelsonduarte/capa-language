# Capa Language Reference

Full specification of the syntax and semantics of the Capa language
(current version). For a guided introduction, see `tutorial.md`. For
the built-in APIs, see `stdlib.md`.

---

## 1. Lexical structure

### 1.1. Encoding

UTF-8 is required. Identifiers may contain any Unicode letter, digits,
and `_`, but must start with a letter or `_`.

### 1.2. Comments

```capa
// Line comment (runs to the end of the line)
/* Block comment - may be /* nested */ unlike C/Java */
/// Doc line comment - attaches to the next declaration
/** Doc block comment - same attachment, Javadoc-style */
```

Block comments nest (in the Rust/Swift tradition rather than the
C/Java one). Doc comments (`///` and `/**`) are preserved by the
lexer and consumed by the documentation generator
(`capa --doc`); they attach to the immediately following
declaration.

### 1.3. Indentation

Capa is **indentation-sensitive**, à la Python. Implicit
`INDENT`/`DEDENT`/`NEWLINE` tokens are produced by the lexer:

- Leading whitespace on a line defines its indentation level
- Increase → `INDENT`
- Decrease → `DEDENT`
- End of line → `NEWLINE`
- Inside `(`, `[`, `{`, `NEWLINE` is suppressed (implicit line
  continuation)

### 1.4. Implicit continuation by leading dot

For multi-line method chaining, a line beginning with `.` is treated
as a continuation of the previous line:

```capa
let r = xs
    .filter(...)
    .map(...)
    .fold(...)
```

### 1.5. Keywords

```
fun pub let var if then elif else match while for in
break continue return import const type trait impl
capability true false and or not consume borrow
```

### 1.6. Literals

| Type | Examples |
|---|---|
| Integer | `42`, `-7`, `0`, `1_000_000` |
| Float | `3.14`, `2.0`, `1e10` |
| String | `"hello"`, `"a\nb"`, `"x = ${x}"` |
| Char | `'a'`, `'\n'` |
| Bool | `true`, `false` |
| List | `[1, 2, 3]`, `[]` |
| Tuple | `(1, "a")`, `(x,)`, `()` |

### 1.7. Interpolated strings

`${expr}` inside a string literal is parsed as a Capa expression:

```capa
let n = 7
"value = ${n * 2}"  // "value = 14"
"len = ${xs.length()}"
```

`$$` is the literal-`$` escape. Nested string literals inside
interpolation are not supported.

---

## 2. Type system

### 2.1. Primitive types

`Int`, `Float`, `String`, `Bool`, `Char`, `Unit`. See `stdlib.md` for
details.

### 2.2. Compound types

| Construct | Syntax |
|---|---|
| List | `List<T>` |
| Tuple | `(T1, T2, ..., Tn)` |
| Function | `Fun(T1, T2) -> Ret` |
| Map | `Map<K, V>` |
| Set | `Set<T>` |

### 2.3. User-defined types

Structs:

```capa
type Person { name: String, age: Int }
```

Sum types (nominal variants):

```capa
type Shape =
    Circle(Float)
    Rectangle(Float, Float)
    Square(Float)
```

Variants may have zero or more payloads. Variants without a payload
(`type X = A`) are *constants*, used without `()`.

### 2.4. Generics

Functions and types can take type parameters delimited by `<>`:

```capa
fun first<T>(xs: List<T>) -> Option<T>
    return xs.first()

type Pair<A, B> { first: A, second: B }
```

Type arguments at a call site are always inferred, never written:
call it as `first([1,2,3])`. There is no syntax for supplying them
explicitly. `<>` opens a type-argument list only in type position;
in expression position `<` is the comparison operator, so
`first<Int>([1,2,3])` parses as a chain of comparisons and is
rejected with `comparison operators are non-associative; use
parentheses or boolean operators to combine`. The Rust turbofish
`first::<Int>(...)` is not accepted either. It is listed among the
deferred features in [`Capa-EBNF.md`](../Capa-EBNF.md) section 1.5.

### 2.5. Cross-statement inference

`let xs = []` produces `List<TyVar>`. The first use pins the type
parameter:

```capa
let xs = []
xs.push(42)        // OK, infers List<Int>
xs.push("oops")    // error: expects Int, got String
```

`TyVar` sharing propagates through aliases (`let ys = xs`) and into
calls to typed functions (`process(xs)` where
`process: List<Int> -> ...`).

### 2.6. Compatibility

`compatible(expected, actual)` is structural with exceptions:
- `TyUnknown` (an untyped expression) is compatible with any type
- `TyVar` (inference placeholder) is compatible with any type

---

## 3. Statements

### 3.1. Bindings

```capa
let name = "Ana"               // immutable, type inferred
let age: Int = 30              // immutable, explicit type
var counter = 0                // mutable
counter = counter + 1          // assignment (only for var)
```

Pattern matching in bindings:

```capa
let (a, b) = pair()            // tuple destructuring
let Person { name, age } = p   // struct destructuring
```

### 3.2. Control flow

```capa
// if-statement
if cond
    body1
elif cond2
    body2
else
    body3

// while
while cond
    body

// for
for x in iter
    body

// match (statement)
match scrutinee
    pat1 -> body1
    pat2 -> body2

// match (expression, multi-line)
let r = match scrutinee
    pat1 -> expr1
    pat2 -> expr2

// match (expression, inline single-line)
let r = match scrutinee { pat1 -> expr1, pat2 -> expr2 }

// break / continue (only inside loops)
break
continue

// return
return                  // returns ()
return expr             // returns a value
```

### 3.3. Expressions as statements

Any expression can be a statement (value discarded):

```capa
stdio.println("hello")      // call with side effect
xs.push(42)                 // mutation
1 + 2                       // value discarded (valid but useless)
```

---

## 4. Expressions

### 4.1. Operators

In decreasing precedence:

| Operator | Description |
|---|---|
| `()` `[]` `.` | Call, index, field access |
| `not` `-` | Unary |
| `*` `/` `%` | Multiplicative |
| `+` `-` | Additive |
| `<` `<=` `>` `>=` `==` `!=` | Comparison |
| `and` | Short-circuit conjunction |
| `or` | Short-circuit disjunction |
| `?` | Try (Err propagation) |

### 4.2. `if` as an expression

```capa
let cat = if cond then e1 else e2
```

The `then` keyword is the discriminator: without it, `if` is a
statement. Only the ternary form is an expression; block-form
`if`/`elif`/`else` always produces `()`.

When the branches need intermediate `let` bindings, use the
block-as-expression form of `match` instead (see §4.3):

```capa
let watchlist = match opts.watchlist_path.is_empty()
    true  -> default_watchlist()
    false ->
        let loaded = load_watchlist(read_fs, opts.watchlist_path)?
        log.info("loaded ${loaded.length()} prefixes")
        loaded
```

### 4.3. `match` as an expression

`match` is the same production whether used as a statement or as an
expression, the value is consumed in expression position and
discarded in statement position. Two surface forms exist:

```capa
// Multi-line (indented arms, expression OR block body)
let r = match scrutinee
    pat1 -> expr1
    pat2 -> expr2

// Inline (single-line, comma-separated, expression body only)
let r = match scrutinee { pat1 -> expr1, pat2 -> expr2 }
```

Both forms accept guards and or-patterns. All arms must produce
compatible types.

A block-body arm (multiple statements under a `pattern ->` line)
produces a value when its final statement is a bare expression
(block-as-expression, à la Rust):

```capa
let n = match key
    "fast" -> 1
    "slow" ->
        let base = compute()
        base * 2
```

If the block's final statement is not an expression (it ends in a
`let`, `var`, assignment, `return`, etc.), the arm produces
`()`; in that case, mixing it with a value-producing arm is a
type error and the match must be used in statement position.

The inline form's `{ ... }` opens immediately after the scrutinee.
This collides syntactically with the struct-literal heuristic, to
force a struct literal as the scrutinee, wrap it in parentheses:

```capa
match (Point { x: 1.0, y: 2.0 })
    Point { x, y } -> stdio.println("${x}, ${y}")
```

### 4.4. Lambdas

```capa
fun (x: Int) -> Int => x * 2                    // single-expression
fun (x: Int) -> Int =>                          // block body
    let y = x * 2
    return y + 1
fun () -> Int => 42                             // no params
fun (a: Int, b: Int) -> Int => a + b            // multiple params
```

Lambdas capture the lexical environment. If a single-line lambda
contains a nested `match`, the transpiler automatically promotes it
to a nested function.

**Type inference.** When a lambda is passed to a higher-order
function whose signature fixes its shape (a parameter typed
`Fun(...) -> ...`, such as `map` / `filter` / `fold` / `find` /
`find_index` / `flat_map`), the parameter types and the return type
may be omitted; the compiler infers them from the expected type:

```capa
let xs = [1, 2, 3, 4, 5]
let doubled = xs.map(fun (x) => x * 2)               // x: Int, -> Int
let evens   = xs.filter(fun (x) => x % 2 == 0)       // x: Int, -> Bool
let total   = xs.fold(0, fun (acc, x) => acc + x)    // acc, x: Int
let r       = apply(fun (x) => x * 3, 4)             // user-defined HOF
```

Annotations may be mixed: `fun (acc, x: Int) => acc + x` infers `acc`
and keeps the explicit `x: Int`. A fully annotated lambda is always
accepted and lowers to identical code. Inference is a pure front-end
step: the inferred annotations are written back into the program
before lowering, so an inferred lambda produces byte-identical output
on both backends as the same lambda written out by hand.

Inference needs a context that determines the shape. A lambda with an
untyped parameter that is *not* passed to a higher-order function
(for example `let f = fun (x) => x + 1`) has nothing to infer from and
is a clear error asking for an annotation; write `fun (x: Int) -> Int
=> x + 1` instead. A missing **return** type alone is always inferred
from the body, with or without a higher-order context.

### 4.5. The `?` operator

Propagates `Err` in functions that return `Result`:

```capa
fun read_two(fs: Fs) -> Result<(String, String), IoError>
    let a = fs.read("a")?      // if Err, returns immediately
    let b = fs.read("b")?
    return Ok((a, b))
```

---

## 5. Pattern matching

### 5.1. Available patterns

| Pattern | Syntax | Matches |
|---|---|---|
| Wildcard | `_` | Any value |
| Identifier | `x` | Binds to `x` |
| Literal | `42`, `"x"`, `true` | Equality |
| Variant without payload | `None` | Singleton variant |
| Variant with payload | `Some(x)`, `Ok(v)` | Match + bind |
| Struct | `Person { name, age }` | Match + bind fields |
| Tuple | `(a, b)`, `(x, _, z)` | Tuple of the same arity |
| Or-pattern | `a \| b \| c` | Any alternative |

### 5.2. Or-patterns with bindings

Each alternative can bind variables, provided all of them bind the
same set of names with compatible types:

```capa
match op
    Add(n) | Sub(n) | Mul(n) -> n   // n is Int in all
```

### 5.3. Guards

```capa
match n
    x if x > 0 -> "positive"
    x if x < 0 -> "negative"
    _ -> "zero"
```

### 5.4. Exhaustiveness

The checker requires full coverage:
- Sum types: every variant, or a catch-all `_`
- `Bool`: both `true` and `false`, or a catch-all
- Or-patterns count each alternative toward the count

```capa
type Color = Red | Green | Blue

match c
    Red -> "r"
    Green -> "g"
    // error: missing variant Blue
```

### 5.5. Type-parameter substitution

`match m.get(k)` where `m: Map<String, Int>` infers `Some(n)` with
`n: Int`, not `n: T`. The owner's type parameters are substituted by
the scrutinee's type arguments.

---

## 6. Capabilities

### 6.1. What they are

Capabilities are primitive types representing access to system
resources (`Stdio`, `Fs`, `Env`, `Clock`, `Random`, `Net`, `Db`,
`Proc`, `Serve`, `Unsafe`). They are only accessible via function
parameters, there are no global instances. `Serve` and `Unsafe` run
on the Python backend only; `capa --wasm` rejects a program whose
signatures reach either (see [`stdlib.md`](stdlib.md)).

### 6.2. The capability discipline (three layers)

**Structural**: capabilities cannot appear in struct fields,
variant payloads, function return types, constants, `let`/`var`
bindings, generic args, or tuples. They only flow through
parameters. (Exception: a struct that `impl`s a user-defined
capability *may* hold built-in caps as fields - the
"cap-bearing struct" relaxation.)

**Flow**:
- *No aliasing*: the same capability cannot occupy two argument slots
  in a single call
- *Mandatory use*: capability parameters must be used (or prefixed
  with `_` to silence the warning)

**Linear**: the `consume` keyword indicates ownership
transfer:

```capa
fun close(consume f: File)
    // f cannot be used after this call
```

"Consumed" variables are tracked across fork/merge in `if`/`elif`/
`else` and `match`. In loops, the analysis uses dry-run + redo to
discover consumes in the first iteration.

### 6.3. Capability in the signature

```capa
fun main(stdio: Stdio, fs: Fs)            // multiple
fun pure(x: Int) -> Int                   // no capabilities (pure)
fun with_consume(consume cap: MyCap)      // ownership transfer
```

### 6.4. Information-flow control

Capabilities control *which* effects a function may exercise;
information-flow control constrains *where* data may flow. A
two-point security lattice (`@public`, the default, below `@secret`)
attaches to type expressions on parameters, bindings, return types,
and struct fields:

```capa
fun handle(token: @secret String, _net: Net) -> Int
    return 0
```

**Propagation**. A value's label is the join of the labels that flow
into it: binary and unary operators, string interpolation
(`"${secret}"` is secret), field reads (inherit the receiver's
label), indexing, the `?` operator, and function results (a call with
a secret argument returns secret). A `match` / `let` destructure of a
secret scrutinee taints the bound names; aggregate literals (struct /
list / tuple) carry the join of their element labels; a for-loop
variable inherits the iterable's label; and a secret pushed / added /
set into a mutable `List` / `Set` / `Map` taints the container.

**Sources and sinks**. `env.get(...)` is secret-by-default (its
result is `@secret` with no annotation), and it is the *only* secret
source: no other built-in method produces `@secret` data without an
annotation. The public sinks are `Stdio.print` / `println` /
`eprintln`, `Net.get` / `post`, `Fs.write`, `Db.exec` / `query`, and
`Serve.send` (the payload argument only, not the connection id, which
the runtime issued rather than the program). A `@secret` value
reaching a sink-position argument is an information-flow violation: a
warning by default, a hard error inside a function annotated
`@strict_ifc()` (which also turns on implicit-flow checking, where a
sink inside a branch guarded by a secret condition is reported).

`Serve.recv(...)` is the one inbound *source*, and it is `@public`.
**This lattice models confidentiality, not integrity or taint.**
`@public` on an inbound request asserts only "this is not a secret
whose disclosure the analysis must prevent". It asserts **nothing**
about the data being trustworthy, well-formed, or safe to act on, and
an inbound request is attacker-controlled: validate it as you would
in any language. Labelling it `@secret` would encode an integrity
property in a confidentiality lattice, whose immediate effect is that
echoing a request back to the client that sent it, the normal case
for a server, would be reported as a violation. Integrity / taint
tracking would be a second lattice, not a relabelling of this one.
See [`stdlib.md`](stdlib.md) under `Serve`.

**Declassification**. `declassify(value, reason: "...")` is the
single auditable secret-to-public bridge. It is identity at runtime
and relabels its result `@public`; the `reason` must be a named
string literal so the manifest can record it. Declassifying a value
that is not `@secret` is reported as a no-op warning and is excluded
from the SBOM record. Every *genuine* `@secret -> @public` call site
is recorded in the SBOM as `declassifications` per function and
`declassification_sites` in the summary. A `declassify` written
outside any function body, in a top-level `const` initializer, is
recorded too, under `module_declassifications`; the summary count is
the module-wide total across both. Identity, not the name, decides:
a user-defined function called `declassify` is an ordinary function
and produces no record (nor any relabelling, so a secret routed
through it still reports as a leak).

```capa
fun leak(env: Env, stdio: Stdio)
    match env.get("API_KEY")
        Some(key) -> stdio.println(key)        // violation: secret to a public sink
        None -> stdio.println("no key")

fun ok(env: Env, stdio: Stdio)
    match env.get("API_KEY")
        Some(key) -> stdio.println(declassify(mask(key), reason: "logged masked"))
        None -> stdio.println("no key")
```

The analysis is cross-function: it builds modular per-function
summaries (which parameters reach a public sink, and which writes a
parameter or `self` field) so that a secret reaching a public sink
inside a callee, or stored into a parameter / `self` field by a
callee, is caught at the call site, including through dynamic trait /
capability dispatch. No explicit `@secret` parameter is required for
the flow to be tracked. Struct labels are per-field: reading a public
field of a struct that also holds a secret is no longer over-tainted;
lists, tuples, and maps remain whole-aggregate. Under `@strict_ifc`
the analyzer additionally enforces implicit flows, secrets that
influence control through `if` / `while` / `match` guards and the
assignments they govern; the default (warn) tier stays focused on
explicit data flows.

`declassify` is the audited downgrade. The model is backed by a
machine-checked Agda noninterference proof (termination-insensitive,
Theorems 3 and 4 including delimited release) over the `lambda_if`
core calculus, and a differential fidelity harness gives evidence
that the analyzer matches the model. The Python analyzer itself is
not machine-verified: the model-vs-implementation gap is argued
informally and cross-checked by that harness, not closed by proof.

### 6.5. Constant-time functions

The `@constant_time()` function attribute requires that no `@secret`
value influences the function's execution time (the CWE-208 side
channel). Built on the same security labels, the analyzer rejects three
things inside a constant-time function:

- **Control flow on a secret**: an `if` / `elif` / `while` /
  `if`-expression condition or a `match` scrutinee whose label is
  `@secret`. The branch taken (and so the time spent) would reveal the
  secret.
- **Memory access indexed by a secret**: `xs[secret]`,
  `list.get(secret)`, `map.get(secret)`, `map.contains_key(secret)`,
  `set.contains(secret)`, and `str.char_at(secret)`. A data-dependent
  access leaks the secret through cache timing (the classic
  table-lookup attack).
- **Variable-time arithmetic on a secret**: `/` and `%` when either
  operand is `@secret`. Division and modulo run on the CPU's
  variable-latency divider (integer `idiv`, float `divsd`), so their
  timing depends on the operand values.

Add / subtract / multiply on secrets (fixed-latency) and branches on
public data remain legal, so a branchless constant-time implementation
type-checks:

```capa
@constant_time()
fun ct_select(flag: Bool, a: @secret Int, b: @secret Int) -> Int
    if flag                 // ok: flag is public
        return a
    return b

@constant_time()
fun leaky(a: @secret Int, b: @secret Int) -> Bool
    if a == b               // error: branch on a secret
        return true
    return false
```

The guarantee is surfaced in the manifest as a per-function
`constant_time` boolean.

### 6.6. Typestate (protocols)

A `typestate` declares the named states of a protocol:

```capa
typestate Socket
    Created
    Connected
    Closed
```

A typestate may declare shared fields in a brace block (`typestate
Socket { fd: Int }`), the data a value carries across all its states
(like a struct; capability-typed fields are rejected). A value of a
typestate carries its current state in the type, written `Name[State]`,
and is linear (it must be consumed or transitioned before it leaves
scope, like a `linear type`). Because the state is
part of the type, `Socket[Created]` and `Socket[Connected]` are
distinct types and the ordinary type checker enforces the protocol. A
transition is a function that consumes a value in one state and returns
it in another; an operation only valid in a given state takes that
state:

```capa
fun connect(consume s: Socket[Created]) -> Socket[Connected]
fun send(s: Socket[Connected], data: String)
fun close(consume s: Socket[Connected])

// send(s, "hi") on a Socket[Created] is a compile-time type error;
// using s after connect(s) is a linearity error (it was consumed).
```

A `[State]` index is only valid on a typestate, and the state must be
one the typestate declares.

A value is constructed with `Name[State] { fields }` (the braces are
empty for a fieldless typestate) and transitioned with `become(value,
State)`, which consumes the value in its current state and yields it
re-typed to the new one (preserving its fields):

```capa
fun open_door(consume d: Door[Closed]) -> Door[Open]
    return become(d, Open)

fun main(_s: Stdio)
    let d = Door[Closed] {}
    let d = open_door(d)        // d is now Door[Open]
    walk_through(d)             // requires Door[Open]
```

Because the value is linear, a constructed typestate that is never
consumed (transitioned to a terminal operation or passed to a `consume`
parameter) is a compile-time error, so a protocol cannot be silently
abandoned mid-way. The manifest records each declared protocol and its
states under `typestates` (and a `protocol_states` count in the
summary). Typestate runs on both the Python and Wasm backends with
identical behaviour (a typestate lowers as a state-indexed struct).

Operations can be free functions that take the value in a specific
state, or methods declared in an `impl Type[State]` block (callable
only when the receiver is in that state). A transition method consumes
`self` and returns the new state:

```capa
impl Door[Closed]
    fun open_it(consume self) -> Door[Open]
        return become(self, Open)

impl Door[Open]
    fun walk(self) -> Int       // only callable on a Door[Open]
        return self.id

// d.walk() on a Door[Closed] is a compile-time error.
```

---

## 7. Imports

```capa
import util                     // sibling: ./util.capa
import sinks.csv_sink           // nested: ./sinks/csv_sink.capa
import capa_log.log             // package dep: <vendor_or_path>/capa_log/log.capa
import util as U                // alias the module name
import util (greet, Table)      // selective: bring only these
import util (greet as hi)       // selective with rename
```

Only items marked `pub` in the target module are visible to
the importer. After `import util`, every `pub` name from
`util.capa` is reachable directly (`greet(...)`), or by
qualified call (`util.greet(...)`). With `import util as U`,
qualified calls take the alias: `U.greet(...)`.

### 7.1. Selective import (and renaming)

`import foo (a, b as c)` brings **only** the listed `pub`
symbols into scope: `a` under its own name, `b` under the alias
`c`. Every other `pub` item of `foo` stays hidden. This is the
hygienic form, and the way to resolve a symbol collision between
two dependencies that export the same `pub` name:

```capa
import capa_csv (parse as csv_parse)
import capa_cli (parse as cli_parse)

fun main(stdio: Stdio)
    stdio.println(csv_parse("a,b"))
    stdio.println(cli_parse("--flag"))
```

Only one side needs a rename; the other may keep the bare name:

```capa
import capa_csv (parse)              // used as parse(...)
import capa_cli (parse as cli_parse) // used as cli_parse(...)
```

Selectors work for functions, types, consts, and capabilities.
Selecting a `pub` sum type (unrenamed) brings its variants along.
A selector that names a symbol the target does not declare, or
declares without `pub`, is a load-time error
(`module 'foo' has no public symbol 'X'`). Renaming a sum type's
**variants** is not yet supported; select the type unrenamed when
you need its constructors.

### 7.2. Module resolution order

When the loader resolves `import x.y`, it tries each of the
following search paths in order, and uses the first hit:

1. The directory a `capa.toml` binds to the leading name: the
   directory of a `path = "..."` dependency called `x`, or the
   project root itself when `[package].name` is `x` (so a
   repository that *is* the package resolves its own modules).
2. The directory of the importing `.capa` file
   (sibling and nested-subdir imports work without any setup).
3. Every directory in the `CAPA_PATH` environment variable.
4. `./vendor/` when `capa.toml` declares at least one git
   dependency (populated by `capa install`).
5. The parent of every `path = "..."` entry in `capa.toml`.
6. `./libraries/` - conventional fallback for projects that
   vendor by hand.
7. The directory of the root file passed to `capa --run`.

Each entry is deduplicated; a missing directory is silently
skipped. The directory containing the project root is **not** a
search path: an import no dependency declares fails closed rather
than resolving against an unverified sibling checkout. See
[`packages.md`](packages.md) for the package manager's role in
resolution.

### 7.3. Visibility

- `pub fun`, `pub type`, `pub const`, `pub capability`: visible
  to importers.
- Unprefixed declarations: module-private. An importer who
  tries to call them gets `unresolved name 'foo'`.

For Python interop, use the typed builtins `py_import(unsafe, name)`
and `py_invoke(unsafe, callable, args)`, both require the `Unsafe`
capability. See `stdlib.md`.

---

## 8. The main program

The entry point is a function called `main` that may take one or
more capabilities as parameters. The capabilities are instantiated
by the runtime at boot:

```capa
fun main(stdio: Stdio, fs: Fs, env: Env)
    let argv = env.args()
    stdio.println("received ${argv.length()} arguments")
```

`main`'s return value is ignored by the bootstrap: the process
exits 0 when `main` runs to completion, regardless of what it
returns.

### 8.1. Aborting: the `panic` builtin

`panic(message: String)` terminates the program immediately. It is
**not** an exception: there is no stack unwinding and no catch.
The contract is identical on every backend:

- `panic: <message>` is written to stderr (one line);
- nothing is written to stdout;
- the process exits non-zero (exit 1 on the Python backend; the
  Wasm and Component Model backends trap, which the CLI and
  `capa test` translate to exit 1).

```capa
fun withdraw(balance: Int, amount: Int) -> Int
    if amount > balance
        panic("withdraw of ${amount} exceeds balance ${balance}")
    return balance - amount
```

`panic` is declared as returning `Unit` (Capa has no bottom /
`Never` type), so it cannot yet be used where a value of another
type is expected; control never actually continues past the call.
It is the recommended way for a test program to fail (see
[`testing.md`](testing.md)). Because the message goes to stderr,
`panic` is a **public sink** for information-flow purposes: passing
a `@secret` value warns by default and is a hard error under
`@strict_ifc()`, exactly like `stdio.eprintln` (route deliberate
disclosures through `declassify`).

---

## 9. Differences from Python

Capa transpiles to Python 3.10+, but the semantics differ:

| Capa | Python |
|---|---|
| Capabilities required for I/O | Globals such as `print`, `open` |
| Types checked at compile time | Duck typing |
| Exhaustive `match` checked | `match` at runtime, no exhaustiveness |
| Or-patterns with consistent bindings | Or-patterns without bindings |
| `let x: List<Int> = []` valid | Python equivalent has no checks |
| Mutation only with `var` or `consume` | Everything mutable |

---

## 10. Known limitations

- String literals do not support multi-line (use `\n` for line breaks).
- Nested string literals inside interpolation
  (`"x ${"inner"} y"`) are not supported; bind the inner value
  to a `let` first.
- Errors inside interpolation report positions starting from
  the file start; the offset has not yet been wired to the
  position inside the `${ ... }` expression.
- The module system is intentionally small: `import`,
  optional `as` alias, `pub` visibility. No re-exports, no
  star imports, no transitive dependency resolution at the
  language level (the package manager handles transitive
  fetch via `capa.toml` and `capa install`; see
  [`packages.md`](packages.md)).
- No asynchronous IO operations.
- `if`/`match` in block-body lambdas needs `=>` before the
  indented block.
