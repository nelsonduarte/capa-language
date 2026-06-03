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
capability true false and or not consume
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

Local inference: the caller rarely needs to supply explicit args.
`first<Int>([1,2,3])` is equivalent to `first([1,2,3])`.

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
resources (`Stdio`, `Fs`, `Env`, `Clock`, `Random`, `Unsafe`). They
are only accessible via function parameters, there are no global
instances.

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
result is `@secret` with no annotation). The public sinks are
`Stdio.print` / `println` / `eprintln`, `Net.get` / `post`,
`Fs.write`, and `Db.exec` / `query`. A `@secret` value reaching a
sink-position argument is an information-flow violation: a warning by
default, a hard error inside a function annotated `@strict_ifc()`
(which also turns on implicit-flow checking, where a sink inside a
branch guarded by a secret condition is reported).

**Declassification**. `declassify(value, reason: "...")` is the
single auditable secret-to-public bridge. It is identity at runtime
and relabels its result `@public`; the `reason` must be a named
string literal so the manifest can record it. Declassifying a value
that is not `@secret` is reported as a no-op warning. Every call site
is recorded in the SBOM as `declassifications` per function and
`declassification_sites` in the summary.

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

The analysis is intra-procedural by design (a secret crossing a
function boundary needs an explicit `@secret` parameter, the
explicit-flow model) and whole-aggregate in granularity (per-field
precision is future work).

### 6.5. Constant-time functions

The `@constant_time()` function attribute requires that no `@secret`
value influences the function's execution time (the CWE-208 side
channel). Built on the same security labels, the analyzer rejects two
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

Arithmetic on secrets and branches on public data remain legal, so a
branchless constant-time implementation type-checks:

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
`constant_time` boolean. Variable-time arithmetic (e.g. division by a
secret) is not yet modelled.

### 6.6. Typestate (protocols)

A `typestate` declares the named states of a protocol:

```capa
typestate Socket
    Created
    Connected
    Closed
```

A value of a typestate carries its current state in the type, written
`Name[State]`, and is linear (it must be consumed or transitioned
before it leaves scope, like a `linear type`). Because the state is
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

A value is constructed with `Name[State] {}` (v1 typestates carry no
fields, so the braces are empty) and transitioned with `become(value,
State)`, which consumes the value in its current state and yields it
re-typed to the new one:

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
identical behaviour (a v1 typestate carries no data, so it lowers as a
zero-field struct / i32 token). State-specific receiver methods and
typestate fields are follow-ups.

---

## 7. Imports

```capa
import util                     // sibling: ./util.capa
import sinks.csv_sink           // nested: ./sinks/csv_sink.capa
import capa_log.log             // package dep: <vendor_or_path>/capa_log/log.capa
import util as U                // alias the module name
```

Only items marked `pub` in the target module are visible to
the importer. After `import util`, every `pub` name from
`util.capa` is reachable directly (`greet(...)`), or by
qualified call (`util.greet(...)`). With `import util as U`,
qualified calls take the alias: `U.greet(...)`.

### 7.1. Module resolution order

When the loader resolves `import x.y`, it tries each of the
following search paths in order, and uses the first hit:

1. The directory of the importing `.capa` file
   (sibling and nested-subdir imports work without any setup).
2. Every directory in the `CAPA_PATH` environment variable.
3. `./vendor/` when `capa.toml` declares at least one git
   dependency (populated by `capa install`).
4. The parent of every `path = "..."` entry in `capa.toml`.
5. `./libraries/` - conventional fallback for projects that
   vendor by hand.
6. The directory of the root file passed to `capa --run`.

Each entry is deduplicated; a missing directory is silently
skipped. See [`packages.md`](packages.md) for the package
manager's role in resolution.

### 7.2. Visibility

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

If `main` returns `Result<(), E>`, an `Err` causes a non-zero exit
code.

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
