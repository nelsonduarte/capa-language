# Testing Capa projects: `capa test`

`capa test` discovers and runs the project's Capa test programs:

```bash
capa test            # Python backend (same pipeline as capa --run)
capa test --wasm     # Wasm backend (same pipeline as capa --wasm --run)
capa test --both     # both backends + cross-backend output diff
```

## Discovery

- The **project root** is the nearest ancestor of the current
  directory that contains a `capa.toml`, or the current directory
  when there is none. `capa test` therefore works from any
  subdirectory of a project, like `git`.
- Test files are `tests/test_*.capa`, directly under the project
  root, run in sorted (file-name) order. Nested directories under
  `tests/` are not scanned, so fixtures and helper modules
  (`tests/testutil.capa`, `tests/data/...`) are never picked up as
  tests.

## The result contract

Each test file is a **plain Capa program** executed exactly like
`capa --run <file>` (a fresh process, cwd = project root).

- exit code 0 = the test **passed**
- anything else = the test **failed**

Capa has no `exit()` builtin and `main`'s return value is ignored
by the bootstrap on both backends, so a Capa program exits 0
exactly when `main` runs to completion, and 1 when a **runtime
error escapes `main`**: division by zero, an out-of-bounds index,
a Wasm trap, an uncaught host error. A test signals failure by
letting a runtime error escape on its failing path.

On failure, `capa test` prints the file's captured stdout and
stderr inline, then keeps going; the final exit code is 1 when any
test failed, 0 when all passed, and 2 for configuration problems
(no test files, a broken `capa.toml`, unvendored dependencies).

## Cross-backend parity: `--both`

`--both` runs every test on the Python **and** the Wasm backend.
Passing now requires three things:

1. exit 0 on the Python backend,
2. exit 0 on the Wasm backend,
3. **byte-identical stdout on both.**

A test whose two runs both exit 0 but print different output is
reported as `DIVERGED`, a failure kind of its own, with a unified
diff of the two stdouts:

```
test_json_errors.capa ... DIVERGED (0.54s)
  both backends exited 0 but their stdout differs:
  --- python backend
  +++ wasm backend
  @@ -1 +1 @@
  -error: Expecting property name enclosed in double quotes: ...
  +error: expected key string at 1
```

stderr is deliberately excluded from the diff: it carries
backend-specific diagnostics (Python tracebacks, wasmtime frames)
even for healthy programs.

This makes `capa test --both` the cheapest way for a library to
guarantee it behaves identically under `capa --run` and
`capa --wasm --run`. Tip: assert on semantic values (variants,
your own messages), not on host-engine error texts, which are the
one legitimately backend-specific surface.

## Module resolution inside tests

Test files resolve imports like any Capa program, plus two
conveniences: the runner prepends the project root and its parent
to `CAPA_PATH` for each test process. In practice:

- `import testutil` finds `tests/testutil.capa` (sibling of the
  test file; importer-relative resolution).
- vendored deps and **dev-dependencies** (`vendor/<name>/...`)
  resolve through the project's `capa.toml`, same as `capa --run`.
- `import mylib` finds `<root>/mylib.capa` (flat layouts).
- `import mypkg.model` finds `<root>/../mypkg/model.capa`, i.e.
  the seed-library convention of running tests with
  `CAPA_PATH=..` works with no environment setup.

If `capa.toml` declares git dependencies (regular or dev) that are
not vendored yet, `capa test` refuses up front and tells you to
run `capa install`; it never installs anything by itself.

## A test layout that scales

The convention the seed libraries use works well here:

```
myproject/
├── capa.toml          # dev-deps for test-only helpers go in
│                      # [dev-dependencies]
├── mylib.capa
└── tests/
    ├── testutil.capa  # shared assertion helpers (not a test)
    ├── test_parsing.capa
    └── test_edge_cases.capa
```

To make a helper-based suite fail the run (and not only print
`FAIL` lines), let the failure path end in a runtime error, e.g.
finish `main` with an intentional trap when the failure count is
non-zero.
