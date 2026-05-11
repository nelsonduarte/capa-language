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
```

There are no block comments.

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
fun let var if then elif else match while for in
break continue return import const type trait impl
true false and or not consume
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
(`type X = A`) are *constants* — used without `()`.

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

// match (expression, inline)
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

The `then` keyword is the discriminator — without it, `if` is a
statement.

### 4.3. `match` as an expression

Multi-line or inline. Each arm of the match evaluates to a value; all
arms must have compatible types.

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
are only accessible via function parameters — there are no global
instances.

### 6.2. The capability discipline (3 layers)

**Structural (v1)**: capabilities cannot appear in struct fields,
variant payloads, function return types, constants, `let`/`var`
bindings, generic args, or tuples. They only flow through parameters.

**Flow (v2)**:
- *No aliasing*: the same capability cannot occupy two argument slots
  in a single call
- *Mandatory use*: capability parameters must be used (or prefixed
  with `_` to silence the warning)

**Linearity (v3)**: the `consume` keyword indicates ownership
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

---

## 7. Imports

```capa
import std.fmt                       // the whole module
import std.collections.HashMap       // a specific type
import "./local.capa" as utils       // local file with alias
```

In v1, top-level `import` is **rejected by the analyzer**. The module
system is reserved for a future version; for now, all useful code
comes from the global standard library.

For Python interop, use the typed builtins `py_import(unsafe, name)`
and `py_invoke(unsafe, callable, args)` — both require the `Unsafe`
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

- String literals do not support multi-line (use `\n` for line breaks)
- Nested string literals inside interpolation (`"x ${"inner"} y"`) are
  not supported
- Errors inside interpolation report positions starting from the file
  start
- Basic module system (only `import`)
- No asynchronous IO operations
- `if/match` in block-body lambdas needs `=>` before the indented block
