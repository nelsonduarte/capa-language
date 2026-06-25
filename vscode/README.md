# Capa Language, VSCode extension

Syntax highlighting for the [Capa programming language](https://github.com/nelsonduarte/capa-language), a capability-centric language with a pythonic surface, built around the idea that the authorities a function holds (network, filesystem, environment, ...) must be visible in its signature.

This extension provides TextMate-based highlighting. A capability-aware language server has shipped separately (`python -m capa lsp`); you can wire it up with any generic LSP client extension for VSCode (search the Marketplace for "Generic LSP" or similar) pointed at `python -m capa lsp`. A first-party VSCode extension that bundles the LSP client is on the roadmap.

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

Or package as a `.vsix`:

```bash
npm install -g @vscode/vsce
cd vscode && vsce package
code --install-extension capa-language-0.11.0.vsix
```

## What's not in this extension yet

- **Bundled LSP client**: the LSP server itself (`python -m capa lsp`) is shipped and delivers diagnostics, hover, go-to-definition, find-references, document symbols, and Quick Fixes. This extension does not yet auto-launch it; you currently wire it up through a generic LSP client extension or in a fork that adds the `vscode-languageclient` dependency. A first-party bundled client is queued.

## Reporting issues

Open an issue at the main Capa repository: <https://github.com/nelsonduarte/capa-language/issues>. Mention "vscode" in the title.

## License

MIT, same as the rest of the Capa project.
