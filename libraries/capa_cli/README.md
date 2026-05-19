# capa-cli

A pure-Capa command-line argument parser. No capabilities, no
Python boundary, no Unsafe: parsing is a `(ArgSchema,
List<String>) -> Result<ParsedArgs, ArgError>` function. The
caller does whatever it wants with the parsed result, including
printing help via `Stdio`.

## Status

v0.1 (seed library). Covers the four shapes a 90% CLI needs
(positionals, flags, long/short options) plus `--help`. Out of
scope for v1: subcommands, bundled short flags (`-vab`), the
`--` separator, repeated options as lists.

## Quick start

```capa
import capa_cli.parser

fun main(stdio: Stdio)
    let schema = ArgSchema {
        program: "greet",
        summary: "say hello, optionally loudly",
        positionals: [
            Positional { name: "name", help: "who to greet" }
        ],
        flags: [
            Flag { long: "shout", short: "s", help: "ALL CAPS" }
        ],
        options: [
            Opt { long: "output", short: "o",
                  help: "where to write", required: false }
        ]
    }

    // In a real program, replace this with env.args() minus
    // argv[0]; see "Wiring real argv" below.
    let args: List<String> = ["alice", "--shout"]

    match parse(schema, args)
        Ok(parsed) ->
            stdio.println("hello, ${parsed.positionals.get(\"name\")}")
        Err(HelpRequested)    -> stdio.println(format_help(schema))
        Err(Missing(name))    -> stdio.eprintln("missing: ${name}")
        Err(Unknown(arg))     -> stdio.eprintln("unknown: ${arg}")
        Err(NeedsValue(name)) -> stdio.eprintln("needs value: ${name}")
```

The full runnable example is [`example.capa`](./example.capa);
it walks four scenarios (success, defaults, `--help`, missing
positional) using hardcoded args so the smoke output is
deterministic.

## API surface

### Schema (from `capa_cli.parser`)

- `pub type Positional { name: String, help: String }`
- `pub type Flag { long: String, short: String, help: String }`
  &nbsp;&nbsp;`short = ""` means no short form.
- `pub type Opt { long, short, help: String, required: Bool }`
- `pub type ArgSchema { program, summary: String, positionals,
  flags, options: List<...> }`

### Result

- `pub type ParsedArgs { positionals, flags, options: Map<String, ...> }`
- `pub type ArgError = Missing(String) | Unknown(String) |
  NeedsValue(String) | HelpRequested`

### Functions

- `pub fun parse(schema, args) -> Result<ParsedArgs, ArgError>`
- `pub fun format_help(schema) -> String`

## Parsing rules

The parser walks args left to right. For each token:

1. `--help` or `-h` short-circuits with `Err(HelpRequested)`.
2. Starts with `--`:
   - `--name=value`: inline-equals option.
   - `--name`: flag if `name` is a declared flag, otherwise
     option (consumes the next arg as its value).
3. Starts with `-` and is at least two characters:
   - One-letter short: flag if declared, else option (consumes
     the next arg as its value).
4. Otherwise: positional, assigned to the next undeclared slot
   in declaration order.

Validation runs after the walk:
- Every required positional must have been supplied.
- Every option with `required: true` must have been supplied.

Flag defaults: every declared flag is initialised to `false`,
so `parsed.flags.get(name)` always returns `Some(_)`. Options
that were not supplied are simply absent from the `options`
map; check with `match parsed.options.get(name)`.

## Wiring real argv

Capa's runtime exposes the program's arguments via
`Env.args()`, which returns a `List<String>` corresponding to
`sys.argv[1:]` on the Python side. Drop the program name if
your invocation includes it, then pass to `parse`:

```capa
fun drop_first(xs: List<String>) -> List<String>
    if xs.is_empty()
        return xs
    var rest: List<String> = []
    var i = 1
    while i < xs.length()
        match xs.get(i)
            Some(a) -> rest.push(a)
            None    -> ()
        i = i + 1
    return rest

fun main(stdio: Stdio, env: Env)
    let args = drop_first(env.args())
    // ... parse(schema, args)
```

The `example.capa` ships with hardcoded args because
`capa --run path/to/file.capa` does not forward additional args
to the program; the compiled binary or transpiled `.py` file is
the way to exercise the real argv path.

## Audit claim

A program using capa-cli declares only the capabilities its
*application logic* needs. `parse` and `format_help` themselves
have no capabilities; the example's signatures, from
`capa --manifest`:

```
parse:       []
format_help: []
describe:    ['Stdio']
run_one:     ['Stdio']
main:        ['Stdio']
```

Zero Unsafe, zero Net, zero Fs. The parser is pure code.
