# Changelog

## 0.13.1

- Type-check gate fixed. `npm run check-types` (`tsc --noEmit`) failed with
  `TS2307: Cannot find module 'vscode-languageclient/node'` because the
  config left `moduleResolution` implicit, so tsc used classic `node10`
  resolution, which cannot read the `exports` map of
  `vscode-languageclient` 10. The type-check now uses `node16` module
  resolution (with `module` set to `node16` to satisfy TypeScript, which
  couples the two), so tsc resolves the package the same way Node does at
  runtime. The `tsconfig` change itself does not affect the shipped bundle,
  which is produced by esbuild (`--format=cjs --platform=node`) and does
  not read `tsconfig`.
- Output channel is now a log channel, fixing a latent defect the repaired
  gate surfaced. `vscode-languageclient` 10 types the client's
  `outputChannel` as `LogOutputChannel` and, at runtime, calls its
  `error`/`warn`/`info`/`debug` methods and reads `logLevel`. The extension
  passed a plain `OutputChannel` (created without `{ log: true }`), so those
  calls would have thrown at runtime whenever the client logged through the
  channel; the broken type-check had hidden the mismatch. The channel is now
  created with `{ log: true }`; the extension's own `appendLine`/`show`
  usage is unaffected because `LogOutputChannel` extends `OutputChannel`.
- Grammar currency. The built-in capability pattern now includes `Serve`
  (the tenth capability), so it highlights as a built-in capability rather
  than a user type. The `extern` keyword (block-opening `extern component
  ... from "..."`) and the `borrow` binding modifier (the invoke-only
  companion to `consume`) are now scoped as keywords instead of plain
  identifiers. No enforcement change; highlighting only.
- Corrected a stale comment in `src/extension.ts` that referred to
  `vscode-languageclient` 8.x; the dependency is pinned at `^10.1.0` and
  the best-effort internal handle it relies on still exists in v10.

## 0.13.0

- Server auto-detection. The `capa.languageServer.command` setting now
  defaults to an empty array, which means "auto-detect". When it is empty
  the extension resolves the launch command itself: it prefers a `capa`
  binary on PATH (the standalone build serves the LSP out of the box since
  compiler v1.12.0) and falls back to `python -m capa lsp` when no `capa`
  binary is found. Detection is deterministic, resolving the executable's
  presence on PATH (`capa.exe` plus the PATHEXT variants on Windows,
  `capa` elsewhere) without spawning a probe process. An explicit command
  configured in any settings scope is always respected verbatim and
  overrides auto-detection. Users who previously relied on the old default
  now get auto-detection; users who set their own command are unaffected.
- Graceful degradation is unchanged: a command that cannot run, a server
  that keeps stopping, and the missing-`pygls` exit (code 2) on the Python
  fallback all still produce specific messages and keep highlighting,
  snippets, and indentation working. The restart cap still applies.
- Documentation. The README now states accurately that the standalone
  binary (>= compiler v1.12.0) serves the LSP without an extra `pip` step,
  that a pip install of the compiler needs the `capa[lsp]` extra, and
  describes the new auto-detection.
- Build: bumped the `esbuild` devDependency to the 0.28 line, clearing the
  moderate dev-server advisory on esbuild <=0.24.2. esbuild is a
  build-time bundler only; it is not distributed in the `.vsix`. The
  bundle and type-check still pass and the packaged `.vsix` is unchanged in
  shape (bundle plus grammar, snippets, language configuration, and icons).

## 0.12.0

- Bundled language server client. The extension now ships a TypeScript
  client (built on `vscode-languageclient` 8.1, compatible with the
  declared `vscode ^1.80.0` engine) that launches the Capa language
  server over stdio and wires up its rich features: diagnostics, hover,
  go-to-definition, find-references, document highlight, rename,
  formatting, document and workspace symbols, semantic tokens,
  completion, signature help, inlay hints, folding, selection ranges,
  code actions, and code lenses. The client starts when a `.capa` file
  is opened and stops when the extension is deactivated. Highlighting,
  snippets, and indentation are unchanged and keep working with or
  without the server.
- Runtime requirement: the server runs as a Python process, so it needs
  Python >=3.10 with `pip install "capa[lsp]"` (which provides `pygls`).
  The standalone PyInstaller binary does not yet serve the LSP because it
  does not bundle `pygls`.
- Graceful degradation. If the launch command cannot run (for example
  Python is not on PATH), the extension reports it with a hint to fix the
  `capa.languageServer.command` setting and keeps highlighting active. If
  the server exits because `pygls` is missing (exit code 2), the message
  is specific and offers to copy `pip install "capa[lsp]"`. Auto-restart
  is capped so a broken command cannot loop forever.
- Settings (all under `capa.`): `capa.languageServer.enabled` (default
  `true`), `capa.languageServer.command` (default
  `["python", "-m", "capa", "lsp"]`), and `capa.languageServer.capaPath`
  (passed to the server as `CAPA_PATH`). Changing any of them restarts
  the client.
- Commands: `Capa: Restart Language Server` and `Capa: Show Language
  Server Output`.
- Build: client code lives in `src/`, is bundled to `dist/extension.js`
  with esbuild, and is excluded from the packaged `.vsix` along with
  `node_modules` and source maps. The `.vsix` carries the final bundle
  plus the existing grammar, snippets, language configuration, and icons.

## 0.11.1

- Added import snippets, completing the snippet set. Three prefixes cover
  every import form the grammar accepts: `import` for a plain
  `import module`, `importas` for `import module as alias`, and
  `importfrom` for a selective `import module (name as alias)`. The
  syntactic form matches the parser and the formatter's canonical output.
  Unlike the other snippets, an import skeleton uses a placeholder module
  name that does not resolve on its own, so its expansion is not expected
  to pass `capa --check` in isolation; it is a skeleton to fill in inside
  a real file.

## 0.11.0

- Code snippets for common Capa constructs, contributed through
  `contributes.snippets` and registered against the `capa` language. Type
  a prefix and press Tab to expand a skeleton with Tab-navigable
  placeholders. Bodies are indented with four spaces to match the language
  convention, so an expansion is valid, correctly indented Capa.
- Prefixes: `main`, `fun`, `pubfun`, `lambda`, `struct`, `sum`, `impl`,
  `impltrait`, `trait`, `capability`, `match`, `ifelif`, `ifelse`, `for`,
  `while`, `let`, `var`, `println`, `print`, `security`, `constant_time`,
  and `strict_ifc`. Each was checked against the examples and the grammar;
  an assembled program exercising every construct passes `capa --check`.
- Import snippets were intentionally left out: an import snippet uses a
  placeholder module name that never resolves in isolation, so its
  expansion could not pass `capa --check` the way the other snippets do.

## 0.10.1

- Documentation refresh. The README now describes the Python-style
  automatic indentation shipped in 0.10.0 (previously it still listed
  "better indentation rules" as not-yet-implemented and told users to
  indent with Tab and Shift-Tab). Added a short "Editing" section
  describing what the indent rule does, documented the `->` arrow as a
  highlighted operator (it was already in the grammar but unlisted), and
  updated the example `.vsix` filename to the current version. No grammar
  or behaviour changes.

## 0.10.0

- Python-style automatic indentation. Pressing Enter after a block header
  now indents the next line. The previous `indentationRules` were too
  loose: the increase pattern was anchored with `^.*`, so any line that
  merely contained a keyword (`fun`, `if`, `for`, `type`, `match`, ...)
  anywhere, including inside string literals, inline lambdas, one-line
  `if ... then ... else` expressions, and identifiers that happen to
  contain a keyword as a substring, would indent the following line. The
  decrease pattern was a blank line, which made no sense.
- The increase pattern is now anchored to the start of the line (after
  the current indentation and an optional `pub `) and only fires on real
  block headers: a named `fun` definition (not a `fun (...)` lambda), a
  `type` struct or sum-type opener, `impl` / `trait` / `capability` /
  `typestate` / `linear`, the `if` / `elif` / `else` / `while` / `for` /
  `match` statements (and `return` / `let` match-expressions), a
  `match` arm whose body is on the next line (the line ends with `->`),
  and a multi-line lambda whose body starts on the next line (the line
  ends with `=>`). One-line `if ... then ... else` expressions and inline
  lambdas (which carry their body after `=>` on the same line) no longer
  trigger indentation. The `if` / `elif` / `while` / `for` exclusion of
  one-line `then` expressions now ignores a `then` that appears only
  inside a `//` line comment.
- The decrease pattern now aligns `else` and `elif` back to their `if`
  instead of keying off blank lines.

## 0.9.0

- The extension now ships the Capa logo as its marketplace icon
  (the hooded figure), shown in the VSCode extensions list.
- `.capa` files now display the Capa icon in the explorer when the
  active icon theme supports language icons (the default VSCode theme
  does). A purple-on-transparent variant is used for the dark theme and
  a higher-contrast purple variant for the light theme.

## 0.8.0

- Highlight the typestate, information-flow, linearity, and
  constant-time surface: `typestate`, `linear`, and `become` keywords,
  the `declassify` built-in, and the `@strict_ifc` / `@constant_time`
  attributes plus the `@secret` / `@public` information-flow labels.
- First VSCode Marketplace release.

## 0.7.0

- TextMate grammar for the core language: keywords, primitive types,
  built-in capabilities and generic types, variant constructors,
  built-in functions, literals (with `${...}` interpolation), operators,
  and reserved-for-future keywords.
