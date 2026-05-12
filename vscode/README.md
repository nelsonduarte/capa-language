# Capa Language, VSCode extension

Syntax highlighting for the [Capa programming language](https://github.com/nelsonduarte/capa), a capability-centric language with a pythonic surface, built around the idea that the authorities a function holds (network, filesystem, environment, ...) must be visible in its signature.

This extension provides TextMate-based highlighting only. A full language server (diagnostics, hover, go-to-definition) is on the roadmap but not yet shipped.

## What it highlights

- Keywords by category: declarations (`fun`, `type`, `trait`, `impl`, `capability`, ...), control flow (`if`, `then`, `elif`, `else`, `match`, `while`, `for`, ...), storage modifiers (`let`, `var`, `pub`, `consume`), logical operators (`and`, `or`, `not`).
- Built-in primitive types (`Int`, `Float`, `String`, `Bool`, `Char`, `Unit`).
- Built-in capabilities (`Stdio`, `Fs`, `Net`, `Env`, `Clock`, `Random`, `Proc`, `Db`, `Unsafe`), highlighted distinctly from regular user types.
- Built-in generic types (`List`, `Option`, `Result`, `Map`, `Set`, `Fun`, `JsonValue`, `IoError`).
- Built-in variant constructors (`Some`, `None`, `Ok`, `Err`, and the `JsonValue` variants).
- Built-in functions (`parse_int`, `parse_float`, `to_int`, `to_float`, `new_map`, `new_set`, `parse_json`, `to_json`, `py_import`, `py_invoke`).
- Integer (decimal, hex, octal, binary), float, and string literals, with proper handling of `${...}` interpolation (the interpolated expression is highlighted recursively).
- Range operators `..` and `..=`, the lambda body separator `=>`, the result-propagation operator `?`, and the or-pattern separator `|`.
- Reserved-for-future-use keywords (`async`, `await`, `yield`, `defer`, `where`, `mut`) are flagged with the `invalid.deprecated.reserved` scope so themes can render them as a warning.

## Install (manual, alpha)

The extension is not on the VSCode Marketplace yet. To install it for local use:

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
code --install-extension capa-language-0.2.0.vsix
```

## What's not in this extension yet

- **Language server** (LSP): no diagnostics, no hover, no go-to-definition, no autocomplete based on the analyzer. Run `python -m capa --check file.capa` in a terminal for type errors until the LSP lands.
- **Snippets** for `fun main(stdio: Stdio)` etc.: would be a small follow-up.
- **Better indentation rules**: Capa is indent-sensitive, but the auto-indent heuristics here are minimal. Use Tab and Shift-Tab explicitly.

## Reporting issues

Open an issue at the main Capa repository: <https://github.com/nelsonduarte/capa/issues>. Mention "vscode" in the title.

## License

MIT, same as the rest of the Capa project.
