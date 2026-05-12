# Contributing to Capa

Thanks for your interest. Capa is a personal project but an open one;
issues, design discussions, and pull requests are welcome. This
document covers the practical bits.

For security issues, please read [SECURITY.md](SECURITY.md) instead -
those go through a private channel.

## Before you start

If your change is more than a small fix, **open an issue first** to
sketch the approach. This avoids the worst kind of pull request: one
where you have done good work that I cannot accept because the
direction is wrong for the project.

Small fixes (typos, obvious bugs with an obvious fix, single-test
contributions) can skip the issue and go straight to a pull request.

## Setting up

Requirements:

- Python 3.10 or newer
- Git

Clone and install in editable mode:

```bash
git clone https://github.com/nelsonduarte/capa
cd capa
pip install -e .
```

Run the test suite (~15 seconds, currently 519 tests):

```bash
python -m unittest discover tests
```

The suite is expected to pass on Ubuntu, macOS, and Windows, on
Python 3.10, 3.12, and 3.14. CI confirms this for every pull request.

## How the compiler is structured

```
.capa source
   |
   v
capa/lexer.py        tokens with significant-indentation handling
   |
   v
capa/parser.py       recursive-descent parser -> AST
   |
   v
capa/analyzer.py     name resolution + types + capability discipline
   |
   v
capa/transpiler.py   codegen for Python 3.10+
   |
   v
capa/runtime/        Result, Option, Stdio, Fs, Net, ..., Unsafe
```

The CLI (`capa/cli.py`) wires the four stages together. Tests live in
`tests/`, one file per stage plus end-to-end tests that transpile and
run programs.

The internals are documented in [`Capa-WhitePaper.md`](Capa-WhitePaper.md)
(rationale and design decisions) and [`Capa-EBNF.md`](Capa-EBNF.md)
(formal grammar). Reading both is the fastest way to understand the
project; the grammar is small.

## What kinds of contributions help most

- **Fixing analyzer bugs.** A `.capa` program that should compile and
  does not, or one that should not compile and does, is always
  interesting. Include the program in the issue.
- **More test coverage** in `tests/test_analyzer.py`, especially
  around capabilities and `consume`.
- **Documentation fixes**, the white paper and the EBNF should match
  the implementation; if they drift, please report it.
- **Examples** in `examples/` that exercise an idiom not already
  covered. Real-world miniatures (a small parser, a small networking
  client) are more useful than synthetic demonstrations.
- **Tooling**: language server, formatter, and `capa init` are
  prioritised on the [roadmap](docs/roadmap.html). Discuss in an
  issue before starting.

## What does not currently fit

- Large refactors of the analyzer or transpiler without a prior
  design discussion. The code is intentionally readable rather than
  clever, and trades simplicity for performance; restructurings need
  to preserve that balance.
- New built-in capabilities. The seven we have are deliberate; adding
  one is a language-design decision that needs justification.
- Major dependencies. The compiler currently has zero runtime
  dependencies outside the Python standard library; a PR that adds
  one needs to argue why.
- Macros, syntax extensions, async/await machinery. These are
  explicitly out of scope for v1.

## Pull-request conventions

- One concern per pull request. A PR that fixes a bug and adds a
  feature is two PRs.
- Add or update tests. CI must stay green.
- Run the full test suite locally before submitting:
  `python -m unittest discover tests`.
- Follow the existing style. The codebase prefers terse, explicit
  Python, no over-engineering, no decorative comments, no
  abstractions introduced for hypothetical future needs.
- Commit messages: imperative present tense, short title (≤ 70
  chars), optional body wrapped at ~72 chars. Look at `git log` for
  examples. Example:

  ```
  Allow user-cap return types in plain functions

  The structural rule forbade any capability appearing in a return
  type. That was too tight for user-defined caps, whose whole point
  is to be produced by factories.
  ```

## Coding style

- The project does not run an autoformatter today (`capa-fmt` is on
  the roadmap). Match the style of the surrounding code: PEP 8 with
  exceptions for long descriptive identifiers.
- No emoji in code or comments.
- Comments only when the *why* is non-obvious. The codebase favours
  well-named identifiers over restating what code does.
- New modules go into `capa/`. The naming convention `capa_ast.py`
  and `typesys.py` (rather than `ast.py` / `types.py`) is deliberate
 , it avoids collisions with Python stdlib modules under
  `python -m capa` invocation.

## Reporting bugs

For non-security bugs, open a regular issue at
<https://github.com/nelsonduarte/capa/issues>. Please include:

- A minimal `.capa` program that reproduces the problem
- The output of `python -m capa --check <file>` (or `--run`,
  `--transpile`, whichever stage is wrong)
- What you expected to happen instead
- `python --version`, your OS, and `git rev-parse HEAD`

## Code of conduct

Participation in this project is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contribution will be released
under the project's [MIT license](LICENSE).
