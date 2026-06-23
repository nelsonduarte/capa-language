# Standard Library Reference

Documents every built-in function, type, and method available in any
Capa program, no imports required.

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

### `String`, methods

| Method | Type | Description |
|---|---|---|
| `length()` | `Int` | Number of characters |
| `is_empty()` | `Bool` | True if the string is empty |
| `to_upper()` | `String` | Convert to upper case (ASCII-only; see below) |
| `to_lower()` | `String` | Convert to lower case (ASCII-only; see below) |
| `trim()` | `String` | Strip whitespace at both ends |
| `trim_start()` | `String` | Strip leading whitespace only |
| `trim_end()` | `String` | Strip trailing whitespace only |
| `contains(sub: String)` | `Bool` | Substring is present |
| `starts_with(s: String)` | `Bool` | |
| `ends_with(s: String)` | `Bool` | |
| `split(sep: String)` | `List<String>` | Split by separator |
| `replace(old: String, new: String)` | `String` | Replace every occurrence |
| `char_at(i: Int)` | `Option<String>` | The single character (a one-codepoint `String`) at code-point index `i`, or `None` if `i` is negative or `>= length()`. |
| `substring(start: Int, end: Int)` | `String` | The slice over the half-open code-point range `[start, end)`. Aborts the program if `start < 0`, `end < 0`, `start > end`, or `end > length()`; it never clamps or silently returns a shorter slice. `substring(i, i)` is the empty string. |
| `index_of(sub: String)` | `Option<Int>` | `Some(i)` with the code-point index of the first occurrence of `sub`, or `None` if `sub` is absent. The empty needle matches at index `0`. |
| `bytes()` | `List<Int>` | The string's UTF-8 bytes, each element in `0..255`. `length()` counts code points; `bytes().length()` counts bytes (`"é".length()` is `1`, `"é".bytes().length()` is `2`). The inverse direction (bytes to string) is not part of the surface. |

Indexing for `char_at`, `substring`, and `index_of` is by Unicode
code point, not byte, and is identical on the Python and Wasm
backends (`"abcé".char_at(3)` is `Some("é")`, `"abcé".substring(0, 4)`
is `"abcé"`).

`to_upper()` and `to_lower()` are **ASCII-only by design**: only the
26 Latin letters fold (`A`-`Z` <-> `a`-`z`); every other code point
passes through untouched, identically on the Python and Wasm backends.
`"café".to_upper()` is `"CAFé"` (the `é` is unchanged), and a string
with no ASCII letters (Greek, Cyrillic, an emoji) is returned as-is.
This is deliberate: full Unicode case folding is locale- and
script-dependent, costs a large mapping table, and is out of scope for
the built-in methods. A program that needs Unicode case folding can
reach for a host helper via `py_import`.

`bytes()` is the public door to a string's encoded form, for hashing,
base64, and other byte-level libraries. For well-formed text the
result is exactly the canonical UTF-8 encoding. A string may also hold
an unpaired surrogate code point (for example from a JSON `\uD800`
escape, which Capa keeps rather than rejecting); Capa stores such a
code point in its 3-byte WTF-8 form internally, and `bytes()` returns
those WTF-8 bytes. This keeps `bytes()` byte-identical on both backends
in every case, well-formed or not.

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
| `find(p: Fun(T) -> Bool)` | `Option<T>` | First element matching `p` |
| `find_index(p: Fun(T) -> Bool)` | `Option<Int>` | Index of first element matching `p` |
| `sorted_by(cmp: Fun(T, T) -> Int)` | `List<T>` | Fresh sorted copy. `cmp(a, b)` returns negative / 0 / positive as in C's `qsort`. Stable. |

Index access: `xs[i]` (no bounds checking, use `get(i)` for safe access).

### Range expressions

`a..b` (exclusive of `b`) and `a..=b` (inclusive) produce a
`List<Int>` materialised from the half-open / closed integer range.
Both endpoints must be `Int`. Float endpoints are deliberately
excluded.

```capa
for i in 0..10            // 0, 1, 2, ..., 9
    stdio.println("${i}")

for i in 1..=5            // 1, 2, 3, 4, 5
    stdio.println("${i}")

let n = 4
let xs = (n - 1)..(n * 2) // 3..8, arithmetic endpoints

// A Range is a lazy iterable, NOT a List: it does not carry the
// List method API (`map` / `filter` / `fold` / ...). Build a List
// explicitly when you need it:
let evens = [0, 2, 4, 6, 8].filter(fun (x: Int) -> Bool => x % 2 == 0)
```

Ranges are first-class iterables in `for` loops on **both** the
Python and Wasm backends; the loop consumes a range directly
without materialising it.

`Range<T>` also has a small query surface - `length() -> Int`,
`contains(x: T) -> Bool`, `is_empty() -> Bool`, and
`to_list() -> List<T>` - implemented on **both** the Python and
Wasm backends. They operate against the half-open `[start, stop)`
interval (`stop = end + 1` for the inclusive `a..=b` form,
`stop = end` for the exclusive `a..b` form), matching Python's
`range(start, stop)`.

Range precedence sits between addition and comparison, so
`1+2..5+3` parses as `(1+2)..(5+3)` and `a..b == c..d` as
`(a..b) == (c..d)`. Range itself is non-associative, `a..b..c` is
a syntax error.

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
| `pairs()` | `List<(K, V)>` | Key/value pairs as tuples; destructure with `let (k, v) = pair` |

```capa
let m: Map<String, Int> = new_map()
m.set("a", 1)
match m.get("a")
    Some(n) -> stdio.println("a = ${n}")
    None -> stdio.println("not found")
```

> **Performance note (Wasm backend).** The Python backend uses a native
> dict, so `get` / `set` / `contains_key` are O(1). The Wasm backend
> currently stores a Map as a linear array of key/value pairs, so those
> operations are O(N) and building a Map of N keys is O(N^2). This is
> imperceptible for small Maps (tens to hundreds of keys) and only
> matters for a single Map holding thousands of keys. The semantics
> (insertion order, overwrite in place) are identical on both backends;
> the structural fix (an O(1) hash map) is planned for the future
> native backend rather than the Wasm runtime.

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
| `or_else(f: Fun() -> Option<T>)` | `Option<T>` | The receiver if `Some`, otherwise the result of `f()` |
| `filter(p: Fun(T) -> Bool)` | `Option<T>` | The receiver if `Some(x)` and `p(x)`, otherwise `None` |

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
| `or_else<F>(f: Fun(E) -> Result<T, F>)` | `Result<T, F>` | The receiver if `Ok`, otherwise `f(err)` |
| `ok()` | `Option<T>` | `Some(v)` if `Ok(v)`, otherwise `None` |
| `err()` | `Option<E>` | `Some(e)` if `Err(e)`, otherwise `None` |

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
| `as_number()` | `Option<Float>` | Alias of `as_num()` |
| `as_int()` | `Option<Int>` | `Some(i)` if `JNum(n)` and `n` is integral |
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
| `parse_int(s: String)` | `Option<Int>` | Surrounding ASCII whitespace, optional sign, decimal digits only; range `[-2^63, 2^63)`. No `_` separators or `0x`/`0b`/`0o` bases. `None` otherwise |
| `parse_float(s: String)` | `Option<Float>` | Same for floats |
| `to_float(i: Int)` | `Float` | Total, every Int has an exact Float representation |
| `to_int(f: Float)` | `Int` | Truncates toward zero |
| `new_map()` | `Map<?, ?>` | Requires `let` annotation to pin the types |
| `new_set()` | `Set<?>` | Same |

Capa has **no implicit numeric coercion**, `Float + Int` is a type
error. Use `to_float` / `to_int` at the call site to make the
conversion explicit:

```capa
fun avg(sum: Float, count: Int) -> Float
    return sum / to_float(count)
```

---

## Aborting: `panic`

| Function | Type | Notes |
|---|---|---|
| `panic(message: String)` | `Unit` (never returns) | Aborts the program: `panic: <message>` to stderr, non-zero exit |

`panic` terminates the program immediately on every backend (exit 1
on Python; a trap on Wasm / Component Model, which the CLI
translates to exit 1). No unwinding, no catch. It requires no
capability, but its message goes to stderr, so the information-flow
checker treats it as a public sink like `stdio.eprintln`. See
[`reference.md`](reference.md) section 8.1 and
[`testing.md`](testing.md) for the testing idiom it enables.

---

## Declassification: `declassify`

| Function | Type | Notes |
|---|---|---|
| `declassify<T>(value: T, reason: "...")` | `T` | The single auditable `@secret` -> `@public` bridge |

`declassify` returns its first argument unchanged at runtime, it is
the identity on the value. What it changes is the static
**information-flow label**: the result is `@public` by construction,
regardless of the value's incoming label. It is the one sanctioned way
to let a `@secret` value reach a public sink (`stdio.println`,
`net.post`, `fs.write`, `panic`, ...) without tripping the
information-flow checker.

The call shape is deliberately rigid so the SBOM can record a
meaningful audit trail:

- exactly two arguments;
- the first is the value (positional);
- the second is a `reason:` **named** argument that must be a plain
  string literal (not an interpolation or a computed value), so it can
  be recorded verbatim.

A `declassify` of a value that is *not* `@secret` is a no-op: it is
flagged as a warning (a dead security annotation is dangerous noise in
a regulated SBOM) and it is *excluded* from the manifest's
`declassifications` list and the `declassification_sites` count, which
record only genuine `@secret -> @public` disclosures.

```capa
fun main(env: Env, stdio: Stdio)
    match env.get("API_KEY")              // env.get yields @secret data
        Some(k) -> stdio.println(declassify(k, reason: "echo for demo"))
        None    -> stdio.println("no key")
```

Every call site is recorded in the capability manifest. Each function
that contains one carries a `declassifications` list of
`{reason, value, pos}` entries (the reason verbatim, the
source-stringified value, and the `line:col` position), and the
manifest `summary` exposes a program-wide `declassification_sites`
count, the regulator-facing record of every point where the program
deliberately lets secret data cross to public. See
[`reference.md`](reference.md) for the information-flow model and
[`cra.md`](cra.md) for the SBOM surface.

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
| `is_dir(p: String)` | `Bool` | True if `p` exists and is a directory |
| `mkdir(p: String)` | `Result<(), IoError>` | Create directory, including missing parents. Idempotent: re-creating an existing directory is `Ok`. |
| `list_dir(p: String)` | `Result<List<String>, IoError>` | Entry names (basenames), alphabetically sorted. |
| `restrict_to(prefix: String)` | `Fs` | Attenuate: a fresh `Fs` allowing only paths under `prefix`. Monotonic. |
| `allows(path: String)` | `Bool` | Test whether the current `Fs` would permit `path`. |

`is_dir`, `exists`, and `allows` all use the same fail-closed-as-
absent convention: a denied path reports `false`, indistinguishable
from a path that does not exist. The cap therefore does not leak
the existence of paths outside its allowed set.

Both the stored allowed prefixes and the queried paths are passed
through `os.path.realpath` (resolves `..` / `.` segments and
follows symlinks) before comparison; the containment check is
path-aware, not string-prefix. Traversal patterns
(`data/../etc/passwd`) and symlinks pointing outside the prefix
are both denied.

The data operations `read` and `write` additionally verify the
opened *handle*, closing the symlink-swap TOCTOU race between
`allows()` and the underlying `open()`: after opening, the OS is
asked for the symlink-resolved path of the open file descriptor
(Linux `/proc/self/fd`,
macOS `fcntl F_GETPATH`, Windows `GetFinalPathNameByHandle`) and
that path is re-checked against the allowed prefixes before any
byte is read or written. `write` opens without truncating and
truncates only after the handle passes, so a symlink swapped
mid-race can never destroy or alter data outside the prefixes; a
denied operation returns the same deny error as the up-front
check. `O_NOFOLLOW` is applied to the final path component where
the platform supports it, as defence in depth. Unrestricted `Fs`
instances skip the verification. Both backends are covered: the
Wasm host shims route file IO through the same guarded open
helpers.

What remains open: the query/metadata operations (`exists`,
`is_dir`, `list_dir`, `mkdir`) still check-then-act, so a race
can change what they observe or where `mkdir` creates a
directory; on a platform with none of the three handle-path
mechanisms, `read`/`write` fall back to the up-front check
alone; a denied `write` may leave behind an *empty* file when
the swapped target did not previously exist (pre-existing data is
never touched); and hard links are not distinguished: a hard
link created inside a prefix to an out-of-prefix file passes
both the up-front check and the handle check, because the OS
reports the link's own in-prefix name for both (realpath does
not resolve hard links either, so this is a containment limit
the prefix check always had, not a regression). A possible
future hardening is to refuse multi-link files (`st_nlink > 1`)
on restricted capabilities, at the cost of denying legitimately
multi-link files.

### `Env`

| Method | Type | Description |
|---|---|---|
| `get(name: String)` | `Option<String>` | Environment variable, or `None` if unset **or denied** |
| `args()` | `List<String>` | Command-line arguments (not gated) |
| `restrict_to_keys(keys: List<String>)` | `Env` | Attenuate: a fresh `Env` whose authority is the **intersection** of the current allowed-key set with `keys`. Monotonic, restrictions only narrow. |
| `allows(name: String)` | `Bool` | Test whether the current `Env` would permit reading `name`; performs no I/O. |

A fresh `Env` from `main` is unrestricted and reads the host's entire
environment verbatim, including secrets. A denied variable is
indistinguishable from an unset one: `get` returns `None`, so the cap
does not leak the existence of variables outside its allowed set; use
`allows(name)` to distinguish denied from absent. On Windows the key
set is matched case-insensitively (both the allow-list and the lookup
key are upper-cased) so `restrict_to_keys(["path"])` means the same
thing on Windows and Linux.

### `Clock`

| Method | Type | Description |
|---|---|---|
| `now_secs()` | `Float` | Unix time in seconds (not gated) |
| `now_monotonic()` | `Float` | Monotonic time (not gated) |
| `sleep(seconds: Float)` | `()` | Pause execution; a silent no-op on a denied `Clock` |
| `restrict_to_after(t: Float)` | `Clock` | Attenuate: a fresh `Clock` whose `not-before` threshold (Unix seconds) is raised to `max(current, t)`. Monotonic, the threshold only rises. |
| `allows()` | `Bool` | True once wall-clock time has reached the threshold (`true` on an unrestricted `Clock`); performs no I/O. |

Reading the current time (`now_secs`, `now_monotonic`) is a pure query
and is never gated. Only the action method `sleep` is gated: on a
denied `Clock` (threshold still in the future) it becomes a silent
no-op, the same fail-closed convention as `Fs.exists` and `Env.get`.

### `Random`

| Method | Type | Description |
|---|---|---|
| `int_range(low: Int, high: Int)` | `Int` | Integer in [low, high) |
| `float_unit()` | `Float` | Float in [0, 1) |
| `with_seed(seed: Int)` | `Random` | A fresh `Random` whose sequence is a deterministic function of `seed`. |

`Random` has no denied state: a seeded `Random` still generates
numbers, just reproducibly, so the narrowing is over the *space of
possible sequences*, not over the *authority to generate*. Chained
`with_seed` calls re-seed via fresh instances and the last seed wins;
the manifest records every call in source order so an auditor sees an
RNG was made deterministic before being handed onward. The PRNG is
SplitMix64 on both backends, so a seeded `Random` produces a
byte-identical sequence on Python and Wasm.

> **Not cryptographically secure.** `Random` (SplitMix64) is a fast,
> reproducible PRNG for simulation, sampling, jitter, and test data.
> Do **not** use it for tokens, API keys, passwords, session IDs,
> nonces, salts, or any value whose security depends on
> unpredictability: its output is predictable and, when seeded, fully
> reproducible. Use a dedicated cryptographic source for those.

### `Net`

| Method | Type | Description |
|---|---|---|
| `restrict_to(host: String)` | `Net` | Attenuate: return a fresh `Net` whose authority is the **intersection** of the current allowed-host set with `{host}`. Monotonic, restrictions only narrow. |
| `allows(host: String)` | `Bool` | Query the current restriction set; performs no I/O. |
| `get(url: String)` | `Result<String, IoError>` | Real HTTP GET (via `urllib.request`). Returns `Err` immediately if the URL's host is outside the current restriction set, *before* any system call. |
| `post(url: String, body: String)` | `Result<String, IoError>` | Real HTTP POST: sends `body` as a UTF-8 byte string with Content-Type `application/octet-stream` and returns the response body. Same host attenuation gate as `get`, enforced *before* any system call. |

A `Net` received from `main` is unrestricted; restrictions accumulate
through `restrict_to`. The result of `restrict_to` is a fresh
capability instance and is bindable in a `let`/`var`, Capa relaxes
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

### `Db`

SQLite-backed database access, with first-class path-prefix
attenuation that mirrors `Fs`. Storage is SQLite via the stdlib
`sqlite3`; each call opens a fresh connection, runs, and closes, so
the cap is stateless from the program's point of view, and both
backends agree on outcomes for the same on-disk file.

| Method | Type | Description |
|---|---|---|
| `restrict_to(path: String)` | `Db` | Attenuate: a fresh `Db` whose authority is the **intersection** of the current allowed-prefix set with `{path}`. Monotonic, restrictions only narrow. |
| `allows(path: String)` | `Bool` | Test whether the current `Db` would permit `path`; performs no I/O. |
| `exec(path: String, sql: String)` | `Result<(), IoError>` | Run DDL / DML against the SQLite file at `path`. Multiple statements separated by `;` are supported (via SQLite's `executescript`). |
| `query(path: String, sql: String)` | `Result<String, IoError>` | Run a `SELECT` and return the rows as a JSON-encoded `[[col, col, ...], ...]` string. Parse it with `parse_json`. |

Attenuation **canonicalises** both the queried path and the stored
prefixes through `realpath` before a boundary-aware containment check,
exactly as `Fs` does: `..` / `.` segments and symlinks are resolved so
a path is admitted only when its true on-disk target lies inside an
allowed prefix. `db.restrict_to("/var/data")` admits `/var/data` and
`/var/data/app.db`, rejects `/var/data_evil/secrets.db` (boundary
lookalike), and rejects `/var/data/../escaped.db` (a `..` traversal
that escapes the prefix on disk). The same rule runs in the Python
runtime and the Wasm hosts (the privileged ops enforce it host-side
via the receiver cap's `allows`).

`query` returns a single cross-backend wire shape: a JSON array of
rows, each row a JSON array of strings (one per selected column).
Every value is stringified, and a SQL `NULL` becomes the JSON string
`"null"` (so a consumer can disambiguate on the exact bytes). The
caller parses with `parse_json` and projects / re-casts columns
explicitly:

```capa
fun main(db: Db, stdio: Stdio)
    let d = db.restrict_to("/var/app")
    match d.query("/var/app/users.db", "SELECT id, name FROM users")
        Ok(rows) -> match parse_json(rows)
            Ok(j) -> stdio.println("rows: ${rows}")
            Err(e) -> stdio.eprintln("bad json: ${e}")
        Err(e) -> stdio.eprintln("${e}")
```

`ATTACH DATABASE` / `DETACH DATABASE` are denied at SQLite's parser
level (via a `set_authorizer` callback on every connection), so a
`Db` scoped to one prefix cannot open a second file outside it from
inside SQL; the statement fails with `not authorized`, surfaced as an
`Err(IoError(...))`. Every other operation (CREATE / SELECT / INSERT /
UPDATE / DELETE / DROP / transactions) stays allowed. Both backends
install the same authorizer.

### `Proc`

Sandboxed subprocess execution, with first-class command-identity
attenuation. Execution is `subprocess.run(argv, capture_output=True,
timeout=30, shell=False)`; `shell=False` is always enforced, so
`proc.exec("rm -rf /", "[]")` passes `"rm -rf /"` as `argv[0]` and
fails with a spawn error rather than invoking a shell. The cap is
stateless: each `exec` spawns a fresh child and waits for it (30s
timeout).

| Method | Type | Description |
|---|---|---|
| `restrict_to(cmd_prefix: String)` | `Proc` | Attenuate: a fresh `Proc` whose authority is the **intersection** of the current allowed-prefix set with `{cmd_prefix}`. Monotonic, restrictions only narrow. |
| `allows(cmd: String)` | `Bool` | Test whether the current `Proc` would permit running `cmd`; performs no I/O. |
| `exec(cmd: String, args_json: String)` | `Result<String, IoError>` | Run `cmd`. `args_json` is a JSON-encoded array of strings consumed as the argv tail. Returns `Ok(stdout)` on a zero exit; `Err` on non-zero exit, timeout, malformed argv JSON, or denial. |

Attenuation fixes the binary's **identity**, not merely its basename,
so a binary an attacker plants in their own directory and invokes by
absolute path cannot impersonate a permitted command:

- A **bare-name** restriction (no path separator, e.g.
  `restrict_to("git")`) admits only **bare-name** commands: the
  command's basename must equal the prefix, or start with `prefix + "-"`
  (a plugin). `restrict_to("git")` admits `git` and `git-lfs` but
  rejects `gitlab` (a prefix lookalike) **and** rejects `/attacker/git`
  (an absolute path with the same basename) -- otherwise any planted
  `git` would defeat the sandbox. Resolving a bare name to a binary is
  left to the OS `PATH` lookup, which the deploying environment
  controls.
- A **path** restriction (contains a separator, e.g.
  `restrict_to("/usr/bin/git")`) gates on the resolved, normalised
  path: the command's normalised path must equal the restriction's
  normalised path exactly. `restrict_to("/usr/bin/git")` admits
  `/usr/bin/git` (and `/usr/bin/../bin/git`, which normalises to the
  same path) but not `/attacker/git` and not the bare name `git`.

The same rule runs in the Python runtime, the core Wasm host, and the
Component Model host, so `allows(cmd)` returns the same `Bool` on
every backend.

`exec` passes `args_json` as the argv tail, so
`proc.exec("git", "[\"status\", \"--short\"]")` runs
`git status --short`. The wire shape (a `Result<String, IoError>`
carrying captured stdout) reuses the same materialiser as `Fs.read`
and `Db.query`:

```capa
fun main(proc: Proc, stdio: Stdio)
    let git = proc.restrict_to("git")
    match git.exec("git", "[\"status\", \"--short\"]")
        Ok(out) -> stdio.println(out)
        Err(e)  -> stdio.eprintln("${e}")
```

### `Unsafe`

Marker capability for crossing the Python boundary. Has no methods -
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
    net: Net          // built-in cap as a field, allowed because
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
