# Capa Language, VSCode extension

Syntax highlighting for the [Capa programming language](https://github.com/nelsonduarte/capa-language), a capability-centric language with a pythonic surface, built around the idea that the authorities a function holds (network, filesystem, environment, ...) must be visible in its signature.

This extension provides TextMate-based highlighting and a bundled client for the Capa language server, which adds diagnostics, hover, go-to-definition, find-references, rename, formatting, document and workspace symbols, semantic tokens, completion, signature help, inlay hints, folding, code actions, and code lenses. See [Language server](#language-server) below for the runtime requirements.

## What it highlights

- Keywords by category: declarations (`fun`, `type`, `typestate`, `linear`, `trait`, `impl`, `capability`, ...), control flow (`if`, `then`, `elif`, `else`, `match`, `while`, `for`, `become`, ...), storage modifiers (`let`, `var`, `pub`, `consume`), logical operators (`and`, `or`, `not`).
- Attributes and security labels (`@security(...)`, `@strict_ifc`, `@constant_time`, and the information-flow labels `@secret` / `@public`), highlighted as attributes.
- Built-in primitive types (`Int`, `Float`, `String`, `Bool`, `Char`, `Unit`).
- Built-in capabilities (`Stdio`, `Fs`, `Net`, `Env`, `Clock`, `Random`, `Proc`, `Db`, `Unsafe`), highlighted distinctly from regular user types.
- Built-in generic types (`List`, `Option`, `Result`, `Map`, `Set`, `Fun`, `JsonValue`, `IoError`).
- Built-in variant constructors (`Some`, `None`, `Ok`, `Err`, and the `JsonValue` variants).
- Built-in functions (`parse_int`, `parse_float`, `to_int`, `to_float`, `new_map`, `new_set`, `parse_json`, `to_json`, `py_import`, `py_invoke`, `declassify`).
- Integer (decimal, hex, octal, binary), float, and string literals, with proper handling of `${...}` interpolation (the interpolated expression is highlighted recursively).
- Range operators `..` and `..=`, the lambda body separator `=>`, the return-type / match-arm arrow `->`, the result-propagation operator `?`, and the or-pattern separator `|`.
- Reserved-for-future-use keywords (`async`, `await`, `yield`, `defer`, `where`, `mut`) are flagged with the `invalid.deprecated.reserved` scope so themes can render them as a warning.

## Snippets

The extension ships a set of code snippets for common Capa constructs.
Type a prefix and press Tab to expand a skeleton with Tab-navigable
placeholders. The bodies are indented with four spaces, matching the
convention used across the examples, so an expansion drops in as valid,
correctly indented Capa.

Available prefixes:

- `import` / `importas` / `importfrom`: a plain `import module`, an
  aliased `import module as alias`, or a selective
  `import module (name as alias)`.
- `main`: entry point `fun main(stdio: Stdio)` with a `println`.
- `fun` / `pubfun`: a function (or `pub` function) with parameters and a
  return type.
- `lambda`: an inline `fun (x: Int) -> Int => ...` lambda.
- `struct`: a `type` with fields.
- `sum`: a `type` with variants.
- `impl` / `impltrait`: an inherent `impl` block, or `impl Trait for Type`.
- `trait`: a `trait` declaration.
- `capability`: a user-defined `capability` declaration.
- `match`: a `match` expression with arms and a `_` fallback.
- `ifelif` / `ifelse`: an `if` / `elif` / `else` chain or an `if` / `else`.
- `for`: a `for ... in` loop.
- `while`: a `while` loop.
- `let` / `var`: an immutable or mutable binding.
- `println` / `print`: writing to stdout through the `Stdio` capability.
- `security`: a function annotated with a `@security(...)` audit record.
- `constant_time`: a `@constant_time()` function with a `@secret` parameter.
- `strict_ifc`: a `@strict_ifc()` entry point.

## Editing

Capa is indent-sensitive, and the extension ships Python-style automatic
indentation. Pressing Enter after a block header (a named `fun` definition,
a `type` opener, `impl` / `trait` / `capability` / `typestate` / `linear`,
or an `if` / `elif` / `else` / `while` / `for` / `match` statement) indents
the next line. One-line `if ... then ... else` expressions and inline `=>`
lambdas (which carry their body on the same line) do not trigger an indent,
and `else` / `elif` are dedented back to their `if`.

## Language server

The extension bundles a client that launches the Capa language server and
connects the editor's rich features (diagnostics, hover, go-to-definition,
rename, formatting, and the rest) to it. The client talks to the server
over stdio; there is no socket or port to configure.

### Requirements

The server ships with the Capa compiler. There are two supported ways to
provide it:

- Standalone binary (>= compiler v1.12.0): the `capa` binary installed via
  `install.sh` / `install.ps1` serves the LSP out of the box. It bundles
  everything the server needs (including `pygls`), so no extra `pip` step
  is required. The extension auto-detects this binary on PATH (see below).
- Pip install of the compiler: the server runs as a Python process under
  `python -m capa lsp`. This requires Python >=3.10 and the
  language-server extra: `pip install "capa-language[lsp]"`. The extra pulls in
  `pygls`, which the server requires. If `pygls` is missing the server
  exits immediately and the extension shows a message telling you to run
  that command.

### Server auto-detection

By default the `capa.languageServer.command` setting is empty, which means
"auto-detect". When it is empty the extension resolves the launch command
itself: it looks for a `capa` executable on PATH (`capa.exe` and the
PATHEXT variants on Windows) and, if one is found, launches `capa lsp`.
When no `capa` binary is on PATH it falls back to `python -m capa lsp`.

Detection is deterministic: the extension resolves the executable's
presence on PATH and does not spawn any probe process. Setting the command
to an explicit argument vector (in any settings scope) overrides
auto-detection and is always used verbatim.

If the resolved command cannot run (binary or Python not found, wrong
command) or the server keeps stopping, the extension reports it and stays
out of the way: syntax highlighting, snippets, and indentation keep working
without the server. When the Python fallback exits because `pygls` is
missing (exit code 2), the message is specific and offers to copy the
install command.

### Settings

All settings live under the `capa.` prefix:

- `capa.languageServer.enabled` (boolean, default `true`): turn the
  language server client on or off. With it off, only highlighting,
  snippets, and indentation remain.
- `capa.languageServer.command` (string array, default `[]`): the command
  used to launch the server, as an argument vector (first item is the
  executable). The empty default means auto-detect (prefer the `capa`
  binary on PATH, otherwise `python -m capa lsp`); see
  [Server auto-detection](#server-auto-detection). Set an explicit vector
  to override, for example `["capa", "lsp"]` to force the binary, or
  `["python3", "-m", "capa", "lsp"]` where the interpreter is named
  `python3`.
- `capa.languageServer.capaPath` (string array, default `[]`): extra
  directories the server searches when resolving Capa imports, passed as
  the `CAPA_PATH` environment variable (joined with the platform path
  separator).

Changing any of these restarts the client automatically.

### Commands

- `Capa: Restart Language Server`: restarts the client (use this after
  installing the `capa` binary, installing `capa-language[lsp]`, or fixing the
  launch command).
- `Capa: Show Language Server Output`: opens the output channel where the
  server's logs and stderr appear.

## Install

From the VSCode Marketplace: search for "Capa Language" in the
Extensions view, or run `code --install-extension nelsonduarte.capa-language`.

### From source (development)

To work on the extension itself, install it locally:

### Option A, symlink (preferred during development)

```bash
# macOS / Linux
ln -s "$(pwd)/vscode" ~/.vscode/extensions/capa-language

# Windows (PowerShell, as admin if your user dir is locked down)
New-Item -ItemType Junction -Path "$env:USERPROFILE\.vscode\extensions\capa-language" -Target "$pwd\vscode"
```

Restart VSCode. `.capa` files should now highlight.

### Option B, copy

```bash
cp -r vscode ~/.vscode/extensions/capa-language
```

Or package as a `.vsix`. The extension now carries TypeScript client code
that is bundled with esbuild, so install the dev dependencies and let
`vsce` run the bundle step first:

```bash
cd vscode
npm install
npx @vscode/vsce package --no-dependencies -o capa-language.vsix
code --install-extension capa-language.vsix
```

`npm run bundle` produces `dist/extension.js` (the entry point named by
`main`); `npm run watch` rebuilds it on change while you work.

## Reporting issues

Open an issue at the main Capa repository: <https://github.com/nelsonduarte/capa-language/issues>. Mention "vscode" in the title.

## License

MIT, same as the rest of the Capa project.
