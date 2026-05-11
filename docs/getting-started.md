# Getting Started with Capa

A 5-minute guide to writing your first Capa program.

## 1. Prerequisites

- Python 3.10 or later (`python3 --version` to check)
- Nothing else to install — Capa transpiles to Python and the package
  bundles everything

## 2. Verify it works

From the project root:

```bash
python -m capa --run examples/hello.capa
```

Expected output: `Hello, world!`

## 3. Two ways to start

### Path A — A `.capa` file

Create `my_first.capa`:

```capa
fun main(stdio: Stdio)
    stdio.println("Hello!")
    let xs = [1, 2, 3, 4, 5]
    let total = xs.fold(0, fun (a: Int, x: Int) -> Int => a + x)
    stdio.println("total = ${total}")
```

Run it:

```bash
python -m capa --run my_first.capa
```

### Path B — Tutorial

For a progressive 10-chapter introduction to the language, open
`docs/tutorial.md`.

> An interactive REPL is planned for a future version. For now,
> `.capa` files are the only execution mode.

## 4. CLI flags

| Flag | What it does |
|---|---|
| `--run file.capa` | Compile and execute |
| `--check file.capa` | Type-check only (do not run) |
| `--transpile file.capa` | Print the generated Python code |
| `--parse file.capa` | Print the AST (for debugging) |
| `--no-color` | Disable ANSI colors in the output |
| `--stdin` | Read from stdin instead of a file |

## 5. Minimum program structure

```capa
fun main(stdio: Stdio)
    // your code here
```

The `stdio` parameter is a *capability* — only functions that receive
it can perform I/O. Other available capabilities: `fs` (filesystem),
`env` (environment variables), `clock` (time), `random` (random
numbers).

## 6. A recommended first "real" program

```capa
fun classify(n: Int) -> String
    return match n
        0 -> "zero"
        n if n > 0 -> "positive"
        _ -> "negative"

fun main(stdio: Stdio)
    let nums = [-3, 0, 7, -1, 42]
    for n in nums
        stdio.println("${n}: ${classify(n)}")
```

Output:
```
-3: negative
0: zero
7: positive
-1: negative
42: positive
```

## 7. Where to learn more

- **`docs/tutorial.md`** — guided 10-chapter tutorial
- **`docs/reference.md`** — full language specification
- **`docs/stdlib.md`** — standard library reference
- **`examples/`** — 18 real programs to inspect (`hello`, `tasks`,
  `grades`, `generics`, `closures`, `io`, `patterns`, `interactive`,
  `json`, `python_interop`, and the `stdlib_*` files that show each
  API)

## 8. When something goes wrong

| Symptom | Likely cause |
|---|---|
| `expected top-level declaration` | You forgot the surrounding `fun main(stdio: Stdio)` around your statements |
| `capability parameter not used` | You declared `stdio: Stdio` but didn't use it — prefix with `_stdio` or remove it |
| `expects Bool, got Int` | You wrote `if 1 then ...` instead of `if x > 0 then ...` |
| `non-exhaustive match` | A `match` on a sum type is missing cases — add `_ -> ...` |

Errors are reported with precise positions and explanatory messages.
