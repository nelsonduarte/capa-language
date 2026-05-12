# Capa Tutorial

This tutorial introduces the Capa language progressively, starting from
"hello world" and building up to advanced features such as capabilities,
generics, and pattern matching. Each section is self-contained; the
snippets can be saved into a `.capa` file and run with
`python -m capa --run`.

---

## Chapter 1: First steps

### Hello world

Every Capa program starts in a `main` function that takes the
*capabilities* (system resources) it needs. To print, we use the
`Stdio` capability:

```capa
fun main(stdio: Stdio)
    stdio.println("Hello, world!")
```

Save it as `hello.capa` and run:

```bash
python -m capa --run hello.capa
```

The difference between Capa and "traditional" languages is this: `stdio`
is not a magical global, it is a **parameter**, and Capa guarantees
that only functions which receive it can perform I/O.

### Variables

```capa
fun main(stdio: Stdio)
    let name = "Ana"
    let age = 30
    stdio.println("${name} is ${age} years old")
```

`let` declares an immutable variable. For a mutable one, use `var`:

```capa
fun main(stdio: Stdio)
    var counter = 0
    counter = counter + 1
    counter = counter + 1
    stdio.println("counter = ${counter}")
```

### Basic types

Capa has local inference, you rarely need to declare types:

| Type | Example |
|---|---|
| `Int` | `42`, `-7`, `0` |
| `Float` | `3.14`, `2.0` |
| `String` | `"hello"` |
| `Bool` | `true`, `false` |
| `Char` | `'a'`, `'X'` |
| `Unit` | `()` (the "empty" value) |

Interpolated strings use `${expr}`:

```capa
let x = 7
let s = "value: ${x * 2}"
```

### Arithmetic and comparisons

```capa
let total = 1 + 2
let product = 3 * 4
let rem = 10 % 3
let smaller = total < product
let equal = total == 3
```

Operators: `+`, `-`, `*`, `/`, `%`, `==`, `!=`, `<`, `<=`, `>`, `>=`,
`and`, `or`, `not`.

---

## Chapter 2: Control flow

### `if` / `elif` / `else`

Statement form (no value):

```capa
fun classify(n: Int, stdio: Stdio)
    if n > 0
        stdio.println("positive")
    elif n < 0
        stdio.println("negative")
    else
        stdio.println("zero")
```

Expression form (produces a value):

```capa
let cat = if n > 0 then "+" else if n < 0 then "-" else "0"
```

The form `if cond then e1 else e2` yields a value; `if cond:` followed
by an indented block is a statement.

### `while` and `for`

```capa
fun main(stdio: Stdio)
    var i = 0
    while i < 5
        stdio.println("i = ${i}")
        i = i + 1

    let xs = [10, 20, 30]
    for x in xs
        stdio.println("x = ${x}")
```

### `match`

`match` is the fundamental primitive for deconstructing values:

```capa
fun describe(n: Int) -> String
    return match n
        0 -> "zero"
        1 -> "one"
        _ -> "other"
```

`match` works as a statement *and* as an expression. The same syntax
in both positions; in expression position the value flows out:

```capa
// Multi-line: indented arms, expression OR block body
let label = match n
    0 -> "zero"
    1 -> "one"
    _ -> "other"

// Inline: comma-separated single-expression arms, body in braces
let label = match n { 0 -> "zero", 1 -> "one", _ -> "other" }
```

`_` is the wildcard that matches any value. Or-patterns (`A | B`)
allow grouping cases at the arm level:

```capa
let r = match cmd { "h" | "help" | "?" -> "help", _ -> "other" }
```

Each alternative of an or-pattern must bind the same set of names (so
`Add(n) | Sub(n)` works, `Add(n) | NoOp` does not).

---

## Chapter 3: Functions

```capa
fun double(x: Int) -> Int
    return x * 2

fun max_of(a: Int, b: Int) -> Int
    if a > b
        return a
    return b

fun greet(name: String, stdio: Stdio)
    stdio.println("hi ${name}")
```

For generic functions, use `<T>`:

```capa
fun first<T>(xs: List<T>) -> Option<T>
    return xs.first()
```

### Closures (lambdas)

Syntax `fun (params) -> Ret => body`:

```capa
let double = fun (x: Int) -> Int => x * 2
let n = double(7)  // 14

// In functional pipelines
let evens = [1, 2, 3, 4, 5].filter(fun (x: Int) -> Bool => x % 2 == 0)
```

Block body with multiple statements:

```capa
let f = fun (x: Int) -> Int =>
    let y = x * 2
    return y + 1
```

---

## Chapter 4: Collections

### `List<T>`

```capa
let xs = [1, 2, 3, 4, 5]

xs.length()       // 5
xs.is_empty()     // false
xs.first()        // Some(1)
xs.last()         // Some(5)
xs.get(2)         // Some(3), safe indexed access
xs.contains(3)    // true

xs.push(6)        // mutation if var
xs.map(fun (x: Int) -> Int => x * 2)
xs.filter(fun (x: Int) -> Bool => x > 2)
xs.fold(0, fun (a: Int, x: Int) -> Int => a + x)
```

Multi-line chaining works naturally:

```capa
let total = xs
    .filter(fun (x: Int) -> Bool => x > 0)
    .map(fun (x: Int) -> Int => x * x)
    .fold(0, fun (a: Int, x: Int) -> Int => a + x)
```

### `Map<K, V>` and `Set<T>`

```capa
let m: Map<String, Int> = new_map()
m.set("ana", 30)
m.set("bruno", 25)

m.length()              // 2
m.contains_key("ana")   // true
m.get("ana")            // Some(30)
m.get("dora")           // None

let s: Set<Int> = new_set()
s.add(1)
s.add(2)
s.add(1)   // duplicate, ignored
s.length() // 2
```

### `String`

```capa
let s = "  Hello, World  "

s.length()                    // 17
s.trim()                      // "Hello, World"
s.to_upper()                  // "  HELLO, WORLD  "
s.to_lower()                  // "  hello, world  "
s.contains("World")           // true
s.starts_with("  H")          // true
s.split(",")                  // ["  Hello", " World  "]
s.replace("World", "Capa")    // "  Hello, Capa  "
```

---

## Chapter 5: User-defined types

### Structs

```capa
type Person { name: String, age: Int }

fun main(stdio: Stdio)
    let p = Person { name: "Ana", age: 30 }
    stdio.println("${p.name} is ${p.age} years old")
```

### Sum types

```capa
type Color =
    Red
    Green
    Blue
    RGB(Int, Int, Int)

fun name(c: Color) -> String
    return match c
        Red -> "red"
        Green -> "green"
        Blue -> "blue"
        RGB(r, g, b) -> "rgb(${r}, ${g}, ${b})"
```

`Option<T>` and `Result<T, E>` are built-in:

```capa
fun divide(a: Int, b: Int) -> Result<Int, String>
    if b == 0
        return Err("division by zero")
    return Ok(a / b)

fun main(stdio: Stdio)
    match divide(10, 2)
        Ok(n) -> stdio.println("result = ${n}")
        Err(msg) -> stdio.println("error: ${msg}")
```

### Functional combinators

`Option` and `Result` expose a rich API:

```capa
let n = parse_int(s)
    .map(fun (x: Int) -> Int => x * 2)
    .unwrap_or(0)

let r = parse_int(s).ok_or("invalid input")
```

| Method | On `Option<T>` | On `Result<T, E>` |
|---|---|---|
| `is_some` / `is_none` | ✓ |, |
| `is_ok` / `is_err` |, | ✓ |
| `unwrap_or(default)` | ✓ | ✓ |
| `map<U>(fn: T → U)` | `Option<U>` | `Result<U, E>` |
| `and_then<U>(fn: T → ...)` | `Option<U>` | `Result<U, E>` |
| `ok_or<E>(err)` | → `Result<T, E>` |, |
| `map_err<F>(fn: E → F)` |, | `Result<T, F>` |

---

## Chapter 6: Capabilities

Capa's distinctive feature: I/O and system resources are only
accessible via *capabilities*, values explicitly passed as parameters.

```capa
fun main(stdio: Stdio, fs: Fs)
    match fs.read("/tmp/data.txt")
        Ok(content) -> stdio.println(content)
        Err(_) -> stdio.eprintln("error")
```

Available capabilities:

| Capability | What it grants access to |
|---|---|
| `Stdio` | stdin/stdout/stderr |
| `Fs` | filesystem |
| `Env` | environment variables, args |
| `Clock` | time, sleep |
| `Random` | random numbers |
| `Unsafe` | crossing the Python boundary |

### Why capabilities?

A function without capability parameters **cannot** perform I/O:

```capa
fun pure(x: Int) -> Int
    return x * 2
    // Cannot call stdio.println, it has no stdio
```

This makes code auditable: to know what a function does, you only need
to look at its signature. "Pure" functions are obvious.

### Linearity

Capabilities are *linear*, each one can only be passed to one
function at a time (unless you use `consume` to indicate ownership
transfer):

```capa
fun both(a: Stdio, b: Stdio)  // Error: aliasing
    a.println("a")
    b.println("b")
```

---

## Chapter 7: Interactive I/O

A program that asks the user for input, validates it, and responds:

```capa
fun ask(stdio: Stdio, prompt: String) -> Option<String>
    stdio.print(prompt)
    return match stdio.read_line()
        Ok(line) -> Some(line.trim())
        Err(_) -> None

fun main(stdio: Stdio)
    let name = match ask(stdio, "What's your name? ")
        Some(s) -> s
        None -> "anonymous"

    match ask(stdio, "Age? ")
        Some(s) -> match parse_int(s)
            Some(n) -> stdio.println("${name}, you are ${n} years old.")
            None -> stdio.println("Invalid age.")
        None -> stdio.println("EOF.")
```

Observe: `stdio.read_line()` returns `Result<String, IoError>`, forcing
the caller to handle EOF/errors explicitly.

---

## Chapter 8: JSON

The built-in `JsonValue` type for reading and producing JSON:

```capa
fun main(stdio: Stdio)
    let input = "{\"name\": \"Ana\", \"age\": 30}"

    match parse_json(input)
        Err(msg) -> stdio.eprintln("error: ${msg}")
        Ok(j) ->
            // as_X helpers that avoid pattern-match boilerplate
            match j.as_object()
                Some(m) -> match m.get("name")
                    Some(v) -> match v.as_string()
                        Some(name) -> stdio.println("name: ${name}")
                        None -> stdio.println("name is not a string")
                    None -> stdio.println("no 'name'")
                None -> stdio.println("not an object")

    // Produce JSON
    let resp: Map<String, JsonValue> = new_map()
    resp.set("status", JStr("ok"))
    resp.set("count", JNum(42.0))
    stdio.println(to_json(JObj(resp)))
```

---

## Chapter 9: Traits

Traits enable ad-hoc polymorphism, multiple types can implement the
same set of methods:

```capa
trait Greetable
    fun greet(self) -> String

type Person { name: String }
type Robot  { id: Int }

impl Greetable for Person
    fun greet(self) -> String
        return "hi ${self.name}"

impl Greetable for Robot
    fun greet(self) -> String
        return "BEEP BOOP unit ${self.id}"

fun main(stdio: Stdio)
    let p = Person { name: "Ana" }
    let r = Robot { id: 7 }
    stdio.println(p.greet())
    stdio.println(r.greet())
```

---

## Chapter 10: Where to go next

- **Reference** (`docs/reference.md`): full syntax and semantics
  specification
- **Standard library** (`docs/stdlib.md`): detailed listing of every
  built-in API
- **Examples** (`examples/`): 18 working programs covering every
  feature

Happy hacking!
