# Capa

[![tests](https://github.com/nelsonduarte/capa/actions/workflows/tests.yml/badge.svg)](https://github.com/nelsonduarte/capa/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: >=3.10](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](pyproject.toml)

A complete front-end for the **Capa** programming language: lexer, parser,
semantic analyzer, Python transpiler and runtime, all hand-written in
Python.

**For the first time, Capa programs run.**

```bash
$ python -m capa --run examples/grades.capa
=== Roster ===
  Ana: 17.5 (Excellent)
  Bruno: 13.0 (Pass)
  Carla: 8.5 (Fail)
  Diogo: 15.5 (Good)
  Eva: 11.0 (Pass)
  Filipe: 19.0 (Excellent)

Statistics:
  Average: 14.083333333333334
  Passed:  5
  Failed:  1
```

## Project layout

```
Capa/
├── capa/                  # Python package implementing the compiler
│   ├── __init__.py        # public package exports
│   ├── __main__.py        # enables `python -m capa ...`
│   ├── cli.py             # command-line utility
│   ├── tokens.py          # TokenKind, Token, Pos, KEYWORDS
│   ├── errors.py          # LexerError with pedagogical formatting
│   ├── lexer.py           # the lexer implementation
│   ├── capa_ast.py        # AST nodes + dump pretty-printer
│   ├── parser.py          # recursive-descent parser
│   ├── typesys.py         # internal type representation
│   ├── analyzer.py        # name resolution + type checking + capabilities
│   ├── transpiler.py      # codegen for Python 3.10+
│   └── runtime/
│       └── __init__.py    # Result, Option, Stdio, Fs, ..., Unsafe, py_import
├── tests/                 # 378 unit + end-to-end tests
│   ├── test_lexer.py
│   ├── test_parser.py
│   ├── test_analyzer.py
│   └── test_transpiler.py # transpile and execute Capa programs
├── examples/              # 18 .capa files demonstrating the language
│   ├── hello.capa         # hello world
│   ├── basics.capa        # several constructs
│   ├── tasks.capa         # canonical EBNF example
│   ├── grades.capa        # non-trivial program (~110 lines)
│   ├── io.capa            # exercises Result and the ? operator
│   ├── python_interop.capa# Python boundary under the Unsafe capability
│   └── errors.capa        # test fixture with semantic errors
├── docs/                  # tutorial, reference, stdlib, getting-started
├── Capa-EBNF.md           # formal grammar of the language
├── Capa-WhitePaper.md     # technical rationale + roadmap
├── pyproject.toml         # package metadata
├── LICENSE                # MIT
└── README.md
```

**Note on module names:** `capa_ast.py` (instead of `ast.py`) and
`typesys.py` (instead of `types.py`) avoid colliding with Python stdlib
modules — collisions that cause subtle circular-import errors when the
package is invoked via `python -m capa`.

## Full pipeline

```
.capa
  ↓ Lexer            tokens with significant indentation
  ↓ Parser           AST
  ↓ Analyzer         name resolution + types
  ↓ Transpiler       Python 3.10+ code
  ↓ Runtime imports  Result, Stdio, Fs, ...
  ↓ python execute   Capa program running
```

## Installation

From the project root (`Capa/`):

```bash
pip install -e .          # or just use `python -m capa` directly
```

## CLI

```bash
# Tokenize
python -m capa examples/hello.capa

# Parse (AST)
python -m capa --parse examples/tasks.capa

# Analyze (lex + parse + semantic check)
python -m capa --check examples/io.capa

# Transpile to Python (prints to stdout)
python -m capa --transpile examples/grades.capa

# Run the Capa program (transpile + execute)
python -m capa --run examples/grades.capa
```

## Programmatic use

```python
from capa import Lexer, Parser, analyze, transpile

source = open("program.capa", encoding="utf-8").read()
tokens = Lexer(source, filename="program.capa").lex()
module = Parser(tokens, source=source, filename="program.capa").parse_module()

result = analyze(module, source=source, filename="program.capa")
if not result.ok:
    for e in result.errors:
        print(e.format())
else:
    code = transpile(module, filename="program.capa")
    print(code)
```

## Tests

```bash
python -m unittest discover tests
```

**378 tests** (lexer + parser + analyzer + transpiler), with 17 that
actually *execute* Capa programs and check stdout — the only honest way
to test a transpiler.

## Capa → Python mapping

| Capa                                | Generated Python                  |
|-------------------------------------|-----------------------------------|
| `fun f(x: T) -> R`                  | `def f(x):` (no annotations)      |
| `let x = e` / `var x = e`           | `x = e`                           |
| `if/while/for`                      | the same                          |
| `match`                             | `match/case` (Python 3.10+)       |
| `type T { ... }` (struct)           | `@dataclass class T:`             |
| `type T = A \| B(P)` (sum)          | classes + alias `T = A \| B`      |
| `trait T`                           | `class _Trait_T:` (informative)   |
| `impl T`                            | methods attached to `T`           |
| `obj.meth(x)`                       | `obj.meth(x)`                     |
| `Some(x)` / `Ok(x)` / `Err(e)`      | the same (runtime classes)        |
| `e?` (try)                          | `_capa_try(e)` + `@_capa_wrap` decorator |
| `"hi ${name}"`                      | `f"hi {name}"`                    |

## Known limitations (v1)

### Language

- **`match` is a statement, not an expression**. Each arm with an
  expression body is evaluated as a statement (side effect or discard).
  To return a value from each arm, use a block + `return`. This tension
  is acknowledged and may lead to making `match` an expression in a
  future version.
- **`if`/`while`/`for` are also statements**.
- **Range expressions** (`a..b`, `a..=b`) are not implemented.

### Lexer / Parser

- String interpolation is recognised but not recursively tokenised in
  the lexer; the transpiler handles it afterwards. It works for simple
  cases (`${ident}`, `${a.b}`, `${a + b}`) but the content between
  `${...}` is interpreted as direct Python code, not pure Capa.
- Raw strings (`r"..."`) are not supported.

### Analyzer

- **Capability discipline** (three layers):

  *Structural layer (v1):* capabilities (`Stdio`, `Fs`, `Net`, `Env`,
  `Proc`, `Clock`, `Random`, `Db`, `Unsafe`) can only appear in function
  parameters. The analyzer rejects:
  * capabilities as struct fields
  * capabilities as variant payloads
  * capabilities as function return types
  * capabilities as constant types
  * capabilities bound in local `let`/`var`
  * capabilities inside generic types (`List<Stdio>`, `Option<Fs>`...)
    or tuples

  *Flow layer (v2):*
  * **Non-aliasing in calls**: the same capability cannot appear as
    multiple arguments of the same call, nor simultaneously as receiver
    and argument. `f(stdio, stdio)` is an error.
  * **Must-use**: a capability declared as a parameter must be used at
    least once in the function body. Convention: prefix the name with
    `_` to silence the warning (idiomatic in Rust and Haskell).

  *Linear layer (v3) — `consume` keyword:*
  * **Optional move semantics**: marking a parameter as
    `consume cap: Cap` indicates the function consumes (takes
    ownership of) the passed capability. After the call, the caller
    can no longer use that capability.
  * **Flow analysis with fork/merge**: in `if/elif/else` and `match`,
    we snapshot the consumed set before each branch and take a
    conservative union after — if *any* branch consumes, the cap is
    considered consumed from that point on. This is the rule used by
    Rust, and prevents use after potential consume.
  * **Loops with dry-run + redo**: for `while` and `for`, we perform a
    silent pass over the body to discover which caps will be consumed;
    we then pre-mark those caps as consumed and do the real pass. This
    catches "consume in iteration 1, use in iteration 2" — the
    linearity failure we used to miss in loops.
  * By default, parameters are *borrows*: the caller can keep using
    the cap. Typical pattern: several borrows followed by a final
    consume.

  Together, the three layers give full linearity for common usage:
  capabilities cannot be duplicated structurally, no aliasing per
  call, must-use, and consume is strictly verified with flow analysis
  including branches and loops.

- **Local generic inference**. The checker infers type arguments in
  three contexts:
  * **Variant constructors with a payload**: `Ok(42)` produces
    `Result<Int, ?>`, `Some("hi")` produces `Option<String>`. Type
    params not inferable from the payload (like `E` in `Result<T, E>`)
    remain `TyUnknown`.
  * **Function calls on generic functions**: given
    `fun first<T>(xs: List<T>) -> T`, the call `first([1, 2, 3])`
    infers `T = Int` and returns `Int`.
  * **Generic struct literals**: `Pair { first: 1, second: "x" }`
    produces `Pair<Int, String>` if `Pair<A, B>` was declared.

  Inference is local (each call is an isolated problem, no
  let-polymorphic generalisation). It is implemented via simple
  unification with substitutions, no constraint-set solving. Good
  enough for common cases; where inference fails, it returns
  `TyUnknown`, which is compatible with anything.

- **Closures (lambdas) v2**. Syntax: `fun (params) -> Ret => body`,
  where `body` is either a single expression OR an indented block:

  ```capa
  // Single-expression
  let double = fun (x: Int) -> Int => x * 2

  // Block-body with explicit return
  let log = fun (x: Int) -> Int =>
      stdio.println("got ${x}")
      return x * 10
  ```

  Function types as annotations: `Fun(Int, Int) -> Int`. Enables
  higher-order functions:

  ```capa
  fun apply(f: Fun(Int) -> Int, x: Int) -> Int
      return f(x)

  fun compose(f: Fun(Int) -> Int, g: Fun(Int) -> Int) -> Fun(Int) -> Int
      return fun (x: Int) -> Int => g(f(x))
  ```

  *Linearity in closures*:
  * **Captures are borrows**: a closure can capture a capability from
    the enclosing scope and use it for borrows (calls that do not
    consume).
  * **Captures cannot be consumed**: trying to consume a captured cap
    is rejected, because the closure can be invoked multiple times
    but the cap can only be consumed once. This is the distinction
    between `Fn` and `FnOnce` in Rust, resolved by capture analysis.
    The rule also applies to block-body lambdas.
  * **Capabilities as parameters of the closure itself can be
    consumed**: each invocation receives its own, without sharing.

  *Current limitations*:
  * Block-body in deep expression context (e.g. inside `(...)`) may
    fail parsing due to NEWLINE/INDENT in parens.
  * No let-polymorphic generalisation.

- **Standard library: builtin methods on `List<T>`**. `length`, `push`,
  `contains`, `map`, `filter`, `fold`, fully verified by the checker.
  Polymorphic types: `map<U>(Fun(T) -> U) -> List<U>` (T from the
  receiver), `filter(Fun(T) -> Bool) -> List<T>`,
  `fold<U>(U, Fun(U,T) -> U) -> U`.

  ```capa
  let xs = [1, 2, 3, 4, 5]
  let evens = xs.filter(fun (x: Int) -> Bool => x % 2 == 0)
  let doubled = xs.map(fun (x: Int) -> Int => x * 2)
  let total = xs.fold(0, fun (acc: Int, x: Int) -> Int => acc + x)
  ```

- **Multi-line method chaining**. When a line starts with `.`, the
  lexer suppresses the NEWLINE/INDENT, allowing idiomatic chaining:

  ```capa
  let total = xs
      .filter(fun (x: Int) -> Bool => x > 0)
      .map(fun (x: Int) -> Int => x * x)
      .fold(0, fun (acc: Int, x: Int) -> Int => acc + x)
  ```

  `//` comments between chain steps are tolerated. It also works with
  multi-line field access. List literals are transpiled to
  `CapaList(...)`, a subclass of Python's `list`.

- **Standard library: builtin methods on `String`**. `length`, `trim`,
  `to_upper`, `to_lower`, `contains`, `starts_with`, `ends_with`,
  `split`, `replace`, fully verified by the checker. Types:
  * `length() -> Int`, `to_upper() -> String`, `trim() -> String`
  * `contains(s: String) -> Bool`, `starts_with(s: String) -> Bool`
  * `split(sep: String) -> List<String>`, `replace(old: String, new: String) -> String`

  ```capa
  let normalised = "  Hello World  ".trim().to_lower()
  let parts = "one,two,three".split(",")
  ```

  Implementation: the transpiler does **type-aware dispatch** — it
  receives the type mapping from the analyzer and, for receivers of
  type `String`, maps Capa methods (`length`, `to_upper`, etc.) to
  their Python equivalents (`len`, `.upper()`, etc.). For user-defined
  types and `List<T>` (whose methods have the same names), it emits
  direct Python method calls.

- **Interpolated strings as real expressions**. `"${expr}"` is parsed
  into `InterpolatedString(parts: list[str | Expr])` with each
  `${...}` as a full Capa expression. Type-checking works inside
  interpolations; method calls in interpolations dispatch correctly:
  `"${s.length()}"` emits `f"{len(s)}"`. `$$` is the escape for `$`.

- **Standard library: `Map<K, V>` and `Set<T>`**. Data structures with
  builtin methods verified by the checker.

  *Map*: `length`, `get` (returns `Option<V>`), `set`, `contains_key`,
  `keys` (returns `List<K>`), `values` (returns `List<V>`).

  *Set*: `length`, `add`, `remove`, `contains`, `to_list`.

  Construction: builtin functions `new_map()` and `new_set()` return
  empty instances. To pin the type params, annotate the `let`:

  ```capa
  let counts: Map<String, Int> = new_map()
  counts.set("ana", 30)
  match counts.get("ana")
      Some(n) -> stdio.println("age = ${n}")
      None -> stdio.println("not found")

  let unique: Set<String> = new_set()
  unique.add("a")
  unique.add("b")
  unique.add("a")  // ignored, sets are unique
  ```

  Implementation: Map uses a Python `dict`, Set uses a Python `set`.
  The transpiler does type-aware dispatch: `m.get(k)` → a ternary
  expression `Some(m[k]) if k in m else None_`.

- **Typed capabilities (`Stdio`, `Fs`, `Env`, `Clock`, `Random`)**:
  all methods have precise types in the checker, instead of the old
  permissive `TyUnknown` fallback.

  | Capability | Methods | Return |
  |----------|-------------------------------------------|---------------------------|
  | `Stdio`  | `print`, `println`, `eprintln(s: String)` | `()`                      |
  | `Stdio`  | `read_line()`                             | `Result<String, IoError>` |
  | `Fs`     | `read(p: String)`                         | `Result<String, IoError>` |
  | `Fs`     | `write(p: String, c: String)`             | `Result<(), IoError>`     |
  | `Fs`     | `exists(p: String)`                       | `Bool`                    |
  | `Env`    | `get(name: String)`                       | `Option<String>`          |
  | `Env`    | `args()`                                  | `List<String>`            |
  | `Clock`  | `now_secs()`, `now_monotonic()`           | `Float`                   |
  | `Clock`  | `sleep(seconds: Float)`                   | `()`                      |
  | `Random` | `int_range(low: Int, high: Int)`          | `Int`                     |
  | `Random` | `float_unit()`                            | `Float`                   |

  Consequence: `clock.sleep(1)` is now an error (expects Float).
  `fs.read(42)` is an error (expects String). And
  `match fs.exists(p) Ok(_) -> ...` is an error because `exists`
  returns `Bool`, not `Result`.

  Extraction helpers on `JsonValue`: `is_null() -> Bool`,
  `as_bool() -> Option<Bool>`, `as_num() -> Option<Float>`,
  `as_string() -> Option<String>`,
  `as_array() -> Option<List<JsonValue>>`,
  `as_object() -> Option<Map<String, JsonValue>>`. Each returns `None`
  if the variant does not match, eliminating boilerplate matches.

  Methods on `Option<T>`: `is_some() -> Bool`, `is_none() -> Bool`,
  `unwrap_or(default: T) -> T`, `map<U>(Fun(T) -> U) -> Option<U>`,
  `and_then<U>(Fun(T) -> Option<U>) -> Option<U>`,
  `ok_or<E>(err: E) -> Result<T, E>`.

  Same on `Result<T, E>`: `is_ok`, `is_err`, `unwrap_or`,
  `map<U>(Fun(T) -> U) -> Result<U, E>`,
  `and_then<U>(Fun(T) -> Result<U, E>) -> Result<U, E>`,
  `map_err<F>(Fun(E) -> F) -> Result<T, F>`.

  Together they enable idiomatic functional code without chained
  matches:

  ```capa
  let n = parse_int(s).map(fun (x: Int) -> Int => x * 2).unwrap_or(0)

  // ok_or converts Option into Result
  let r: Result<Int, String> = parse_int(s).ok_or("invalid input")

  // map_err converts the error type
  let r2 = fs.read(p).map_err(fun (e: IoError) -> Int => 1)
  ```

- **`if`-expression (ternary)**: `if cond then e1 else e2` as an inline
  expression. The `then` keyword is required in this form — without
  `then`, `if` is interpreted as a statement in the appropriate
  context.

  ```capa
  let cat = if n > 0 then "+" else if n < 0 then "-" else "0"

  // Useful in single-line closures
  let abs_xs = xs.map(fun (x: Int) -> Int => if x < 0 then 0 - x else x)

  // And in monadic pipelines
  let par = parse_int(s).and_then(fun (x: Int) -> Option<Int> =>
      if x > 0 then Some(x * 2) else None
  )
  ```

  The condition must be `Bool`, the branches must have compatible
  types. Precise errors: `if 42 then "a" else "b"` →
  `condition must be Bool, got Int`.

- **Collection helpers**:
  - `List<T>`: `is_empty() -> Bool`, `first() -> Option<T>`,
    `last() -> Option<T>`, `get(i: Int) -> Option<T>` (safe access)
  - `String`: `is_empty() -> Bool`
  - `Map<K, V>`: `is_empty() -> Bool`
  - `Set<T>`: `is_empty() -> Bool`

- **JSON in the standard library**. A built-in `JsonValue` type with 6
  recursive variants: `JNull`, `JBool(Bool)`, `JNum(Float)`,
  `JStr(String)`, `JArr(List<JsonValue>)`,
  `JObj(Map<String, JsonValue>)`. Functions
  `parse_json(s: String) -> Result<JsonValue, String>` and
  `to_json(v: JsonValue) -> String`.

  ```capa
  match parse_json(input)
      Err(msg) -> stdio.eprintln("error: ${msg}")
      Ok(config) -> match config
          JObj(m) -> match m.get("name")
              Some(JStr(name)) -> stdio.println("name: ${name}")
              _ -> stdio.println("name missing")
          _ -> stdio.println("not an object")

  // Build and serialise
  let resp: Map<String, JsonValue> = new_map()
  resp.set("status", JStr("ok"))
  resp.set("count", JNum(42.0))
  let s = to_json(JObj(resp))
  ```

  Exhaustiveness works naturally — `match j: JsonValue` requires
  coverage of all 6 variants or a catch-all `_`.

- **Builtin conversion functions**:
  - `parse_int(s: String) -> Option<Int>` — returns `None` on invalid input
  - `parse_float(s: String) -> Option<Float>` — same for floats

  Idiomatic interactive program:
  ```capa
  fun ask(stdio: Stdio, prompt: String) -> Option<String>
      stdio.print(prompt)
      return match stdio.read_line()
          Ok(line) -> Some(line.trim())
          Err(_) -> None

  fun main(stdio: Stdio)
      match ask(stdio, "Age: ")
          Some(s) -> match parse_int(s)
              Some(n) -> stdio.println("You are ${n}.")
              None -> stdio.println("Invalid age.")
          None -> stdio.println("EOF.")
  ```

- **Pattern matching with type-param substitution**. `match m.get(k)`
  where `m: Map<String, Int>` infers `Some(n)` with `n: Int`, not
  `n: T`. Substitution of owner type params by the scrutinee's
  concrete type args is applied automatically.

- **Advanced pattern matching**:

  *Tuples*: deconstruction in `let`, `var`, `for`, and `match`:
  ```capa
  let (name, age) = person()
  match pair
      (1, s) -> stdio.println(s)
      (n, _) -> stdio.println("${n}")
  ```
  Nested patterns: `(Some(n), label)` matches a tuple whose first
  element is `Some(...)`. The pattern's arity is checked against the
  scrutinee's type.

  *String literals in match*: `"help" -> ...`, `"quit" -> ...` —
  useful for command dispatchers.

  *Or-patterns*: `A | B -> ...` matches if *any* alternative matches.
  Useful for arms that share a body:
  ```capa
  match cmd
      "h" | "help" | "?" -> stdio.println("...")
      "q" | "quit" | "exit" -> stdio.println("goodbye")
      _ -> stdio.println("unknown")

  match c
      Red | Yellow -> "warm"
      Blue | Green -> "cold"
  ```
  Each alternative in an or-pattern counts toward exhaustiveness
  checking.

  *Or-patterns with bindings*: each alternative may bind variables,
  as long as all of them bind the same set of names with compatible
  types:
  ```capa
  type Op =
      Add(Int)
      Sub(Int)
      Mul(Int)

  fun value(o: Op) -> Int
      return match o
          Add(n) | Sub(n) | Mul(n) -> n  // n: Int in all
  ```
  Inconsistencies are caught: `Add(n) | NoOp` → error because `NoOp`
  does not bind `n`. `AsInt(x) | AsStr(x)` → error because `x` has
  `Int` in one and `String` in the other.

- **Cross-statement inference**: types are refined by later uses via
  shared TyVar. `let xs = []` produces `List<TyVar(_t)>`. The first
  `xs.push(42)` pins `_t = Int`, and later uses are checked against
  `List<Int>`:

  ```capa
  let xs = []
  xs.push(42)        // OK, infers Int
  xs.push("oops")    // error: expects Int, got String

  let ys = xs        // shares the same TyVar
  ys.push("oops")    // also an error: it's already List<Int>
  ```

  Works transitively — passing `xs` to a function that expects
  `List<Int>` without an intermediate annotation also works.

- **Index** on `List<T>[i]` returns `T`. Other indexable types (Map,
  etc.) still return `TyUnknown`.

- **Real method dispatch**. Methods defined in `impl` blocks are
  registered on the target type's Symbol. Calls `obj.method(args)`
  are checked:
  * The method must exist on the receiver's type
  * Arity must match
  * Argument types must be compatible (with type-param substitution
    from the type: `c.put(x)` on a `Box<Int>` expects `x: Int`)
  * `Self` in the return type is resolved to the receiver's type
  * Additional inference applies to the method's type params

  Exception: capabilities (`Stdio`, `Fs`, etc.) have no impls in Capa
  code — their methods are still typed as `TyUnknown` and resolved at
  runtime against the Python runtime implementation.

- **Match exhaustiveness** for sum types and `Bool`:
  * **Sum types**: every variant must be covered by some arm without
    a guard. A wildcard (`_`) or a simple binding (`other`) without a
    guard acts as a catch-all. Guarded arms do not count toward
    coverage because the guard may fail.
  * **Bool**: requires coverage of `true` and `false` (or `_`).
    Messages like `non-exhaustive match on Bool: missing false`.
  * For non-sum types with high cardinality (Int, structs with
    heterogeneous fields), the checker does not yet require
    exhaustiveness — intractable for Int (2^64 values) and
    irrelevant for structs.

### Transpiler

- The output is readable Python but not idiomatic — it mirrors the
  Capa structure closely.
- The `?` operator uses an internal exception for propagation. It
  works and is correct, but is not as efficient as the expanded
  imperative version.

## Real bugs caught by the system itself

During development, **the transpiler + runtime caught bugs in the
design and in canonical examples** that the checker had not been able
to catch:

1. `match` as a statement with expression arms silently discards the
   value — `tasks.capa` produced `None` instead of strings. Detected
   by running the program.
2. Builtin variants (`Ok`, `Err`, `Some`) were not marked as having a
   payload in the analyzer — `Ok(n)` gave a checking error. Fixed.
3. Builtin generic types had no `type_params` — `Result` appeared
   without args, incompatible with `Result<Int, IoError>`. Fixed.
4. Functions that use `?` need a decorator that catches the internal
   exception; without it, `Err` propagates to the top of the program.
   We added an AST detector that applies the decorator automatically.

This was exactly the reason to build the transpiler before linearity —
running real code is the harshest test of a design.

- **Full trait verification**. When you declare an `impl Trait for
  Type`, the checker verifies:
  * **Presence of every method** declared in the trait
  * **Signature compatibility**: every implemented method must have
    the same arity, parameter types, and return type. `Self` in the
    trait signature is resolved to the concrete impl type.
  * **Extra methods** (helpers) are allowed.

## What's next

In decreasing order of impact:

1. **Interactive REPL** or watch mode for quick experimentation.
2. **Match-as-expression in one line** with inline syntax (e.g.,
   `{ }` delimiters à la Rust).
3. **More aggressive cross-statement inference**: combine with
   `let xs = []` followed by iteration over a concrete type.
4. **Complete documentation** (language reference, tutorial,
   examples).
5. Phase 4 of the original roadmap: native LLVM backend.
