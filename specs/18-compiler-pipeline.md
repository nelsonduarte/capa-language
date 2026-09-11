# 18. Pipeline: lexer, parser, analyzer, IR, codegen

> **What this chapter covers.** The reference compiler's phase chain:
> source -> lexer -> parser -> AST -> analyzer -> (legacy transpiler |
> IR) -> codegen, and the package structure of `capa/`. Where each
> phase lives, what it consumes and produces, and how the CLI drives
> the phases by flag. It does not describe the analyzer's interior
> (the discipline, linear and IFC passes are covered in chapters 10,
> 14, 15 and 16) or the backends' interiors (chapters 21 and 22).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification; all `file:line` citations are against this commit.

Depends on: [04-grammar.md](04-grammar.md).

---

## 1. The phase chain

A Capa program crosses five floors before it runs. Each floor consumes
the previous artefact and produces the next:

| Phase | Package | Consumes | Produces | Flag that reveals it |
|---|---|---|---|---|
| 1. Lexer | `capa/lexer/`, `capa/tokens.py` | source text | `Token` stream (with layout) | *(default, no flag)* |
| 2. Parser | `capa/parser/`, `capa/capa_ast/` | `Token`s | `Module` (AST) | `--parse` |
| 3. Analyzer | `capa/analyzer/` | AST | `AnalysisResult` (types, bindings, errors, warnings) | `--check` |
| 4a. Legacy transpiler | `capa/transpiler/` | AST + types | Python code (`str`) | `--transpile` / `--run` |
| 4b. IR (lowering) | `capa/ir/` | AST + types | CIR (IR `Module`) | `--ir`, and always for `--wasm` |
| 5a. Python emitter | `capa/ir/_emit_python.py` | CIR | Python code (`str`) | `--ir --transpile` |
| 5b. Wasm emitter | `capa/ir/_emit_wasm/` | CIR | WAT / Wasm component | `--wasm --transpile` |

The central structural point, and the reason there are TWO codegen
entries (4a and 4b): there are two code-generation paths for the
Python backend. The **legacy** path (`capa/transpiler/`) generates
Python directly from the AST, with no IR. The **CIR** path
(`capa/ir/`) lowers the AST to a dedicated intermediate representation
and emits from it. The Wasm backend exists ONLY on the CIR path.
Section 6 measures the observable difference between the two.

## 2. The `capa/` package tree

Phase packages (subfolders of `capa/`, listed at this commit):

- `lexer/` (4 mixins: `_indent _comments _literals _tokens`) and the
  top-level `tokens.py`.
- `parser/` (5 mixins: `_types _patterns _statements _expressions
  _items`).
- `capa_ast/` (6 node modules: `_base _exprs _items _stmts _types
  _patterns`).
- `analyzer/` (17 `.py` modules: `__init__ _callables _declarations
  _discipline _dispatch _e3 _expressions _frozen _ifc _ifc_summary
  _ifc_tables _items _linear _patterns _return_origin _statements
  _typing`).
- `ir/` (the IR and the emitters; section 5), with the subpackages
  `_emit_wasm/` (26 `.py` files: 25 emitter modules plus
  `__init__.py`, and a `_wasi/` subpackage) and `_monomorphise/`.
- `transpiler/` (4 mixins: `_expressions _items _methods
  _statements`).

Support modules at the top of `capa/` that the pipeline uses: the
`cli/` package (the driver, section 8: `__init__ _ctx _diagnostics
_emitters _execute _floor _grants _parser _run_python subcommands`),
`loader.py` (import resolution before analysis, section 4),
`typesys.py` (the type system and `CAPABILITY_NAMES`), `builtins.py`,
`errors.py` (the `LexerError` base reused by parser and analyzer for
the caret diagnostic format), `foreign.py`, `_declassify.py`,
`_labels.py`, `_borrow.py`, `_owned_obligation.py`.

## 3. Phase 1: lexer

Source: [`capa/lexer/`](../capa/lexer/__init__.py). The lexer is
hand-written, with maximal munch and significant indentation managed
by a level stack that emits `NEWLINE` / `INDENT` / `DEDENT` (module
docstring). It is split into four mixins composed in the `Lexer`
class: `_indent` (indentation stack), `_comments`, `_literals`
(numbers, normal and raw strings, chars, escapes), `_tokens` (token
dispatcher with maximal-munch lookahead). The token catalogue and
keywords live in [`capa/tokens.py`](../capa/tokens.py) (`Token`,
`TokenKind`, `Pos`, `KEYWORDS`). The concrete token shapes and layout
rules are in [03-lexis-and-layout.md](03-lexis-and-layout.md); the
normative lexis in [`Capa-EBNF.md`](../Capa-EBNF.md) chapters 3 and 4.

The lexer's product is directly observable: with no processing flag,
the CLI prints the token stream. For the program:

```capa
// pipe.capa
fun double(n: Int) -> Int
    return n * 2

fun main(stdio: Stdio)
    stdio.println("double(21) = ${double(21)}")
```

```
$ python -m capa pipe.capa
   2:1    KW_FUN          'fun'
   2:5    IDENT           'double'
   2:11   LPAREN          '('
   2:12   IDENT           'n'
   2:13   COLON           ':'
   2:15   IDENT           'Int'
...
```

(Output trimmed; each line is `line:col  TokenKind  text`; the line-1
comment produces no token, so the dump starts at line 2.) The
programmatic entry is `Lexer(source, filename=filename).lex()`
([`capa/cli/__init__.py`](../capa/cli/__init__.py) line 321). A
lexical error is a `LexerError` with caret formatting.

## 4. Phase 2: parser

Source: [`capa/parser/`](../capa/parser/__init__.py). Pure recursive
descent with precedence climbing for binary expressions; the parser
consumes only `NEWLINE` / `INDENT` / `DEDENT` as structural tokens
(module docstring). The `Parser` class composes five mixins, one per
production group: `_types`, `_patterns`, `_statements`, `_expressions`
(precedence climbing), `_items` (top-level declarations). The grammar
it implements is [04-grammar.md](04-grammar.md)'s subject.

The parser consumes `Token`s and produces a `Module`, the AST root.
AST nodes live in `capa/capa_ast/` (`Module`, `FunDecl`, `Param`,
`Block`, `ReturnStmt`, `BinOp`, `Ident`, `IntLit`, ...).

`--parse` runs lexer plus parser and prints the AST:

```
$ python -m capa --parse pipe.capa
Module(
  items=[
    - FunDecl(
      name='double'
      params=[
        - Param(
          name='n'
          type_expr=TypeName(
            name='Int'
          )
          name_pos=Pos(line=2, col=12, offset=24, filename='pipe.capa')
        )
...
```

**The import -> loader link.** Before analysis, transitive imports are
resolved by [`capa/loader.py`](../capa/loader.py)
(`ModuleLoader.load_root`, driven from
[`capa/cli/__init__.py`](../capa/cli/__init__.py) around line 350).
The loader does its own lex + parse of the root file (so source
positions stay consistent) and imported modules become extra `Item`s
in the linked AST. Only pure `--parse` (without `--check` or a
codegen flag) skips the linker, so the inspected AST shows the root
file's imports verbatim. The capability-flow discipline crosses module
boundaries without exception; see
[08-functions-closures-modules.md](08-functions-closures-modules.md).

## 5. Phase 3: analyzer

Source: [`capa/analyzer/`](../capa/analyzer/__init__.py). The public
entry is the free function `analyze(module, source, filename, ...)`
(`__init__.py` line 1283), which instantiates the `Analyzer` class
(line 365) and runs `Analyzer.analyze(module)` (line 826). The
analyzer combines name resolution and type checking in one pass over
the AST, after a pre-pass that registers top-level declarations (to
support forward references). Its interior (typing, capability
discipline, dispatch, patterns, linear, IFC) is covered by chapters
10, 14, 15 and 16; the modules composing it are the 17 listed in
section 2.

The product is an `AnalysisResult` (`__init__.py` line 303), a
dataclass with, among others, `errors` (fatal), `warnings` (non-fatal,
the IFC warn tier), `types` (`id(node) -> Ty`), `bindings`
(`id(Ident) -> Symbol`) and `global_symbols`. The `ok` property is
`not self.errors` (line 342): warnings do NOT change the exit code.
The two single-source catalogues the analyzer consults are
`CAPABILITY_NAMES` ([`capa/typesys.py`](../capa/typesys.py) line 190,
the 10 capabilities) and `_ATTRIBUTE_SCHEMA`
([`capa/analyzer/_items.py`](../capa/analyzer/_items.py) line 43, the
7 recognized function attributes).

`--check` runs up to analysis and reports the summary:

```
$ python -m capa --check pipe.capa
pipe.capa: ok (2 items, 8 expressions typed, 3 bindings)
```

`2 items`, `8 expressions typed` and `3 bindings` are the
cardinalities of, respectively, the module items, the `types` map and
the `bindings` map of the `AnalysisResult`. A semantic error prints
the caret diagnostic and exits 1; an IFC warning prints `warning:` and
does not change the exit code (see
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md)).

## 6. Phase 4: the two codegen paths

After analysis, `--transpile` / `--run` generate Python. There are two
paths, chosen by flag
([`capa/cli/_run_python.py`](../capa/cli/_run_python.py)):

- **Legacy transpiler (default).** `transpile(module, ...)`
  (`capa/transpiler/`) generates Python directly from the AST. This is
  the path of `--transpile` and `--run` without `--ir`.
- **CIR pipeline (`--ir`, opt-in).** `compile_program(module, ...)`
  (`capa/ir/`) lowers the AST to the IR (`Lowerer`,
  `capa/ir/_lower.py`) and emits Python from it (`PythonEmitter`,
  `capa/ir/_emit_python.py`). If the program uses a construct the IR
  does not cover, the `Lowerer` raises `UnsupportedInIR` and the CLI
  falls back to the legacy transpiler with a one-line stderr notice
  (`capa/cli/_run_python.py` lines 63 to 69). The observable behaviour
  is identical; only the path differs.

The Wasm backend exists ONLY on the CIR path: `--wasm` has no fallback
and fails loudly if the IR does not cover the program
([`capa/cli/_execute.py`](../capa/cli/_execute.py)).

The structural difference between the two paths is visible in the
shape of the generated Python for `double`/`main`. The legacy path
emits nested expressions directly:

```
$ python -m capa --transpile pipe.capa
...
def double(n):
    return _capa_imul(n, 2)

def main(stdio):
    stdio.println(('double(21) = ' + str(double(21))))
```

The CIR path lowers to three-address form with explicit temporaries
(`_ir_t0`, `_ir_t1`), which makes the intermediate IR visible:

```
$ python -m capa --ir --transpile pipe.capa
...
def double(n):
    _ir_t0 = _capa_imul(n, 2)
    return _ir_t0

def main(stdio):
    _ir_t0 = double(21)
    _ir_t1 = f'double(21) = {_ir_t0}'
    stdio.println(_ir_t1)
```

Both produce the same result when run. The IR nodes
(`capa/ir/_nodes.py`), the lowering (`_lower*.py`) and the
monomorphisation (`capa/ir/_monomorphise/`) are the bridge to the
backends (chapters 21 and 22).

## 7. Phase 5: the emitters (backends)

From the IR depart the emitters, one per backend:

- **Python.** `PythonEmitter`
  ([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py)). The
  generated code imports the support runtime
  (`from capa.runtime import ...`), where capabilities are
  materialized as objects that interpose the effects. Detail in
  [21-python-backend.md](21-python-backend.md).
- **Wasm Component Model.** `WasmEmitter`
  ([`capa/ir/_emit_wasm/`](../capa/ir/_emit_wasm/__init__.py), the 25
  emitter modules plus the `_wasi/` subpackage), with WIT generation
  (`capa/ir/_emit_wit.py`). It emits WAT, then assembles it into a
  component. No fallback. Detail in
  [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md).

The same `pipe.capa` runs on both backends with identical output:

```
$ python -m capa --run pipe.capa
double(21) = 42
$ python -m capa --run --wasm pipe.capa
double(21) = 42
```

`--wasm --transpile` prints the WAT; `double` gets an `i64`-typed
signature and the same `_ir_t0` temporary as the IR:

```
$ python -m capa --wasm --transpile pipe.capa
...
  (func $double (export "double") (param $n i64) (result i64)
    (local $_ir_t0 i64)
    ...
```

The capability manifest is embedded in the component as a custom
section `capa-manifest` (measured in the WAT:
`(@custom "capa-manifest" ...)`); the byte-identical-output promise
and its scope are in [24-backend-parity.md](24-backend-parity.md).

## 8. How the CLI drives the phases

Source: the [`capa/cli/`](../capa/cli/__init__.py) package (`__init__`
holds the per-invocation driver; `_parser` the flag surface; `_ctx`,
`_diagnostics`, `_emitters`, `_execute`, `_floor`, `_grants`,
`_run_python`, `subcommands` the leaves). The sequence per invocation,
with flags acting as stop points:

1. Lex always (`Lexer(...).lex()`, `capa/cli/__init__.py` line 321).
2. If the flag requires an AST (`--parse`, or any later phase), parse
   (with the loader when imports must be linked; pure `--parse` skips
   the linker).
3. If the flag requires semantics (`--check`, `--run`, `--manifest`,
   the SBOM emitters, `--wit`, `--wasm`, ...), run `analyze(...)`.
4. `--parse` without a later flag prints the AST and stops; `--check`
   without `--run` prints the summary and stops.
5. `--transpile` / `--run` generate code (legacy or CIR, section 6);
   `--wasm` follows the CIR -> WAT -> binary pipeline
   (`capa/cli/_execute.py`).
6. Without any processing flag, the token stream is printed.

The complete flag and subcommand reference is
[25-cli-commands-and-flags.md](25-cli-commands-and-flags.md).

## 9. Notes

- JUDGEMENT (the 4a/4b boundary). The characterization "legacy
  transpiler = AST -> Python direct; CIR = AST -> IR -> Python/WAT" is
  a reading of the structure of `capa/cli/_run_python.py` and
  `capa/ir/__init__.py`; the two paths coexist by design (legacy
  covers all of Python, the IR is the only path to Wasm and the
  opt-in for Python). The code does not label the paths with these
  names; the distinction is what the flags and the `UnsupportedInIR`
  fallback make observable (section 6).
- Scope of the measurements. All pasted outputs are from `pipe.capa`,
  a minimal two-function program, run at `8e2c609` on both backends.

---

## Links

- [04-grammar.md](04-grammar.md): the grammar the parser (phase 2)
  implements.
- [10-capability-model.md](10-capability-model.md),
  [14-linearity-consume-typestates.md](14-linearity-consume-typestates.md),
  [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md),
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md): the
  analyzer's discipline, linear and IFC passes.
- [21-python-backend.md](21-python-backend.md) and
  [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the two emitters (phase 5).
- [25-cli-commands-and-flags.md](25-cli-commands-and-flags.md): the
  complete reference of the flags that drive the phases.
