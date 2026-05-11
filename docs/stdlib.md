# Standard Library Reference

Documents every built-in function, type, and method available in any
Capa program — no imports required.

---

## Primitive types

| Type | Size/Range | Notes |
|---|---|---|
| `Int` | 64-bit signed | Arithmetic does not check for overflow |
| `Float` | 64-bit IEEE 754 | |
| `String` | UTF-8 | Immutable |
| `Bool` | `true` / `false` | |
| `Char` | Unicode code point | At runtime, a str of length 1 |
| `Unit` | `()` | "Empty" type for functions with no return value |

### `String` — methods

| Method | Type | Description |
|---|---|---|
| `length()` | `Int` | Number of characters |
| `is_empty()` | `Bool` | True if the string is empty |
| `to_upper()` | `String` | Convert to upper case |
| `to_lower()` | `String` | Convert to lower case |
| `trim()` | `String` | Strip leading/trailing whitespace |
| `contains(sub: String)` | `Bool` | Substring is present |
| `starts_with(s: String)` | `Bool` | |
| `ends_with(s: String)` | `Bool` | |
| `split(sep: String)` | `List<String>` | Split by separator |
| `replace(old: String, new: String)` | `String` | Replace every occurrence |

---

## `List<T>`

Mutable homogeneous list. Construct with the literal `[a, b, c]` or by
`push` on a `let`/`var`. Cross-statement inference: `let xs = []`
infers the type from the first `push`.

| Method | Type | Description |
|---|---|---|
| `length()` | `Int` | Number of elements |
| `is_empty()` | `Bool` | |
| `push(x: T)` | `()` | Append at the end (mutation) |
| `contains(x: T)` | `Bool` | |
| `first()` | `Option<T>` | First element or `None` |
| `last()` | `Option<T>` | Last element or `None` |
| `get(i: Int)` | `Option<T>` | Safe indexed access |
| `map<U>(f: Fun(T) -> U)` | `List<U>` | Transform each element |
| `filter(p: Fun(T) -> Bool)` | `List<T>` | Keep elements that match |
| `fold<U>(init: U, f: Fun(U, T) -> U)` | `U` | Reduce to a single value |

Index access: `xs[i]` (no bounds checking — use `get(i)` for safe access).

---

## `Map<K, V>`

Hash map. Construct via `new_map()` with a required type annotation.

| Method | Type | Description |
|---|---|---|
| `length()` | `Int` | |
| `is_empty()` | `Bool` | |
| `get(k: K)` | `Option<V>` | Returns the value if the key exists |
| `set(k: K, v: V)` | `()` | Insert/update (mutation) |
| `contains_key(k: K)` | `Bool` | |
| `keys()` | `List<K>` | |
| `values()` | `List<V>` | |

```capa
let m: Map<String, Int> = new_map()
m.set("a", 1)
match m.get("a")
    Some(n) -> stdio.println("a = ${n}")
    None -> stdio.println("not found")
```

---

## `Set<T>`

Set of unique elements. Construct via `new_set()` with a type annotation.

| Method | Type | Description |
|---|---|---|
| `length()` | `Int` | |
| `is_empty()` | `Bool` | |
| `add(x: T)` | `()` | Add (no-op if duplicate) |
| `remove(x: T)` | `()` | Remove (no-op if absent) |
| `contains(x: T)` | `Bool` | |
| `to_list()` | `List<T>` | Convert to a list |

---

## `Option<T>`

Built-in sum type:

```capa
type Option<T> =
    Some(T)
    None
```

| Method | Type | Description |
|---|---|---|
| `is_some()` | `Bool` | |
| `is_none()` | `Bool` | |
| `unwrap_or(default: T)` | `T` | Return value or default |
| `map<U>(f: Fun(T) -> U)` | `Option<U>` | Transform if `Some` |
| `and_then<U>(f: Fun(T) -> Option<U>)` | `Option<U>` | Monadic bind |
| `ok_or<E>(err: E)` | `Result<T, E>` | Convert to a `Result` |

---

## `Result<T, E>`

Built-in sum type for error handling:

```capa
type Result<T, E> =
    Ok(T)
    Err(E)
```

| Method | Type | Description |
|---|---|---|
| `is_ok()` | `Bool` | |
| `is_err()` | `Bool` | |
| `unwrap_or(default: T)` | `T` | Return value or default |
| `map<U>(f: Fun(T) -> U)` | `Result<U, E>` | Transform the success value |
| `and_then<U>(f: Fun(T) -> Result<U, E>)` | `Result<U, E>` | Monadic bind |
| `map_err<F>(f: Fun(E) -> F)` | `Result<T, F>` | Transform only the error |

The `?` operator: automatically propagates `Err` in functions that
return `Result`:

```capa
fun read_and_process(fs: Fs) -> Result<Int, IoError>
    let content = fs.read("x.txt")?  // if Err, returns immediately
    return Ok(content.length())
```

---

## `JsonValue`

Built-in sum type for JSON representation:

```capa
type JsonValue =
    JNull
    JBool(Bool)
    JNum(Float)
    JStr(String)
    JArr(List<JsonValue>)
    JObj(Map<String, JsonValue>)
```

### Extraction methods

| Method | Type | Description |
|---|---|---|
| `is_null()` | `Bool` | |
| `as_bool()` | `Option<Bool>` | `Some(b)` if `JBool(b)` |
| `as_num()` | `Option<Float>` | `Some(n)` if `JNum(n)` |
| `as_string()` | `Option<String>` | `Some(s)` if `JStr(s)` |
| `as_array()` | `Option<List<JsonValue>>` | `Some(xs)` if `JArr(xs)` |
| `as_object()` | `Option<Map<String, JsonValue>>` | `Some(m)` if `JObj(m)` |

### Top-level functions

| Function | Type |
|---|---|
| `parse_json(s: String)` | `Result<JsonValue, String>` |
| `to_json(j: JsonValue)` | `String` |

---

## Built-in conversion functions

| Function | Type | Notes |
|---|---|---|
| `parse_int(s: String)` | `Option<Int>` | Returns `None` on invalid input |
| `parse_float(s: String)` | `Option<Float>` | Same for floats |
| `to_float(i: Int)` | `Float` | Total — every Int has an exact Float representation |
| `to_int(f: Float)` | `Int` | Truncates toward zero |
| `new_map()` | `Map<?, ?>` | Requires `let` annotation to pin the types |
| `new_set()` | `Set<?>` | Same |

Capa has **no implicit numeric coercion** — `Float + Int` is a type
error. Use `to_float` / `to_int` at the call site to make the
conversion explicit:

```capa
fun avg(sum: Float, count: Int) -> Float
    return sum / to_float(count)
```

---

## Python interoperability

The two functions below cross the Capa/Python trust boundary. Both
require the `Unsafe` capability as the first argument.

| Function | Type |
|---|---|
| `py_import(unsafe: Unsafe, name: String)` | dynamic (untyped) |
| `py_invoke(unsafe: Unsafe, callable: ?, args: List<?>)` | dynamic (untyped) |

```capa
fun square_root(unsafe: Unsafe, x: Float) -> Float
    let math = py_import(unsafe, "math")
    return py_invoke(unsafe, math.sqrt, [x])
```

---

## Capabilities

### `Stdio`

| Method | Type | Description |
|---|---|---|
| `print(s: String)` | `()` | No newline |
| `println(s: String)` | `()` | With newline |
| `eprintln(s: String)` | `()` | To stderr |
| `read_line()` | `Result<String, IoError>` | Read a line without `\n` |

### `Fs`

| Method | Type | Description |
|---|---|---|
| `read(p: String)` | `Result<String, IoError>` | Read the entire file |
| `write(p: String, c: String)` | `Result<(), IoError>` | Write (overwrites) |
| `exists(p: String)` | `Bool` | Check whether the path exists |

### `Env`

| Method | Type | Description |
|---|---|---|
| `get(name: String)` | `Option<String>` | Environment variable |
| `args()` | `List<String>` | Command-line arguments |

### `Clock`

| Method | Type | Description |
|---|---|---|
| `now_secs()` | `Float` | Unix time in seconds |
| `now_monotonic()` | `Float` | Monotonic time |
| `sleep(seconds: Float)` | `()` | Pause execution |

### `Random`

| Method | Type | Description |
|---|---|---|
| `int_range(low: Int, high: Int)` | `Int` | Integer in [low, high) |
| `float_unit()` | `Float` | Float in [0, 1) |

### `Net`

| Method | Type | Description |
|---|---|---|
| `restrict_to(host: String)` | `Net` | Attenuate: return a fresh `Net` whose authority is the **intersection** of the current allowed-host set with `{host}`. Monotonic — restrictions only narrow. |
| `allows(host: String)` | `Bool` | Query the current restriction set; performs no I/O. |
| `get(url: String)` | `Result<String, IoError>` | Real HTTP GET (via `urllib.request`). Returns `Err` immediately if the URL's host is outside the current restriction set, *before* any system call. |

A `Net` received from `main` is unrestricted; restrictions accumulate
through `restrict_to`. The result of `restrict_to` is a fresh
capability instance and is bindable in a `let`/`var` — Capa relaxes
the "no capabilities in locals" rule specifically for method-call
results (which are necessarily fresh, not aliases of an existing
capability).

```capa
fun fetch(net: Net) -> Result<String, IoError>
    return net.get("https://api.example.com/users")

fun main(net: Net, stdio: Stdio)
    let api = net.restrict_to("api.example.com")
    match fetch(api)
        Ok(body) -> stdio.println(body)
        Err(e)   -> stdio.eprintln("${e}")
```

See `examples/net_attenuation.capa` for a fuller demonstration,
including the monotonic-narrowing property (chaining two disjoint
restrictions yields a `Net` that allows nothing).

### `Unsafe`

Marker capability for crossing the Python boundary. Has no methods —
its only role is to gate `py_import` and `py_invoke` (see "Python
interoperability" above).

### User-defined capabilities

Libraries can declare their own capabilities with the `capability`
keyword. The declaration registers the name in the capability
discipline; any type that implements the capability becomes a valid
implementor.

```capa
capability SendEmail
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>

type SmtpMailer {
    server: String,
    net: Net          // built-in cap as a field — allowed because
                      // SmtpMailer implements a user-defined cap
}

impl SendEmail for SmtpMailer
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>
        // delegate to self.net under the hood
        return Ok(())

// Factory that consumes the underlying built-in cap and produces the
// higher-level capability. Allowed return type even though SmtpMailer
// carries authority.
fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer
    return SmtpMailer { server: server, net: net.restrict_to(server) }

// Caller side: receive the capability by parameter (subtyping accepts
// SmtpMailer where SendEmail is expected because of the impl).
fun send_welcome(mailer: SendEmail, to: String) -> Result<Unit, IoError>
    return mailer.send(to, "Welcome", "Hello!")
```

The discipline still applies: a `let dup = mailer` (plain identifier
alias of a cap-bearing value) is rejected; only call/method-call RHSs
produce fresh capability instances that can be bound. See
`examples/user_capabilities.capa` for a complete example.

---

## The `IoError` type

Opaque type representing I/O errors. Available as a type parameter in
`Result<T, IoError>` and in pattern matching:

```capa
match fs.read("x.txt")
    Ok(content) -> stdio.println(content)
    Err(e) -> stdio.eprintln("error: ${e}")
```

`IoError`'s string representation is human-readable, but its internal
contents are private.
