# Capa packages: `capa.toml` and `capa install`

Capa projects declare their dependencies in a `capa.toml`
file at the project root. Running `capa install` resolves the
declared deps, fetches the git ones into `./vendor/`, and writes
a `capa.lock` so the resolution is reproducible.

When a `capa.toml` file is present in the working directory, the
Capa loader picks up `./vendor/` and the parent of every `path =`
dep automatically, no `CAPA_PATH` environment variable needed.

## Quick start

A two-file project:

```
my-project/
├── capa.toml
└── main.capa
```

```toml
# capa.toml
[package]
name = "my-project"
version = "0.1.0"
capa = ">=0.8.4"

[dependencies]
capa_log = { git = "https://github.com/nelsonduarte/capa_log", tag = "v0.1" }
```

```capa
// main.capa
import capa_log.log
import capa_log.stdio_logger

fun main(stdio: Stdio)
    let log = make_stdio_logger(stdio, INFO)
    log.info("hello")
```

Then:

```bash
capa install
capa --run main.capa
```

`capa install` clones `nelsonduarte/capa_log` at tag `v0.1`
into `./vendor/capa_log/` and writes `capa.lock`. `capa --run`
finds the dependency through the loader's `capa.toml` hook.
Commit `capa.toml` and `capa.lock`; gitignore `vendor/`.

## Manifest schema

### `[package]`

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | the project's name |
| `version` | string | yes | the project's version (SemVer-style) |
| `capa` | string | no | minimum Capa version, e.g. `">=0.8.4"` |

### `[dependencies]`

Each entry is `name = { ... }`, where the table holds **exactly
one source** plus its pin:

**git source** (must include `tag` xor `rev`):

```toml
# Production-grade: pin to an immutable commit SHA. Tags are
# mutable upstream (a maintainer or a compromised account can
# re-point them); ``rev`` makes the artefact what you audited.
mylib = { git = "https://github.com/user/mylib", rev = "abc123def" }

# Development-grade: a tag is more readable but mutable. ``capa
# install`` records the resolved SHA in capa.lock and refuses on
# subsequent runs when the upstream tag has moved (see
# "Lockfile" below). ``--update`` is the explicit escape hatch.
mylib = { git = "https://github.com/user/mylib", tag = "v0.1" }
```

A git source may also carry a `verify_key` fingerprint; when
present, `capa install` runs `git verify-tag` (or
`git verify-commit` for a `rev` pin) against your local GPG
keyring and refuses to install when the signature is absent,
invalid, or from a different key. The fingerprint is the trust
anchor: it must already be in the consumer's keyring (via
`gpg --import` or `gpg --recv-keys`). Use the multi-line table
form for legibility:

```toml
[dependencies.mylib]
git = "https://github.com/user/mylib"
tag = "v0.1"
verify_key = "1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678"
```

The 40-char fingerprint may include spaces or colons for
readability; the parser normalises before comparison.

#### SLSA L2 build provenance (implicit)

When `verify_key` is set AND the git URL points at GitHub AND
the pin is a tag AND the `gh` CLI is on your PATH, `capa
install` also runs `gh attestation verify` against the source
tarball attached to the GitHub release for that tag, against
the public Sigstore Rekor transparency log. This is the third
supply-chain layer (lockfile SHA + GPG fingerprint + SLSA L2
provenance); it runs automatically with no extra capa.toml
field needed.

`capa install` refuses when the release tarball is published
**and** its SLSA attestation in Rekor is invalid, tampered, or
issued by a different identity than the repository owner.

It gracefully skips (logs nothing, install continues) when:

- The repo is not GitHub-hosted (no Sigstore pipeline today).
- The `gh` CLI is missing from PATH.
- The release for this tag has no source-tarball asset
  (publisher hasn't adopted the attesting workflow yet).
- The network is unreachable.

The skip-on-missing behaviour is deliberate: the SLSA layer
augments the GPG layer rather than replacing it. A publisher
who hasn't shipped attestations yet still gets verified by
the GPG fingerprint. A future opt-in `verify_provenance =
"required"` field can flip every skip path to fail-closed for
consumers who want the strictest mode.

> **Security posture (best-effort / fail-open).** The SLSA
> provenance check is *best-effort*: it is a fail-open layer
> today. When `gh` is absent, the asset is missing, or the
> network is down, the install **continues without** the SLSA
> check rather than refusing. Do not read "the three-layer
> stack" as "SLSA provenance is always verified whenever
> `verify_key` is set" - only the lockfile-SHA and GPG-
> fingerprint layers are unconditional; the SLSA layer fires
> only when all of its preconditions hold. A `verify_provenance
> = "required"` config field that makes the SLSA layer fail-
> closed is **deferred** (see audit 2026-05-25 M4); until it
> lands, treat SLSA verification as a bonus, not a guarantee.

The reference seed libraries (capa_cli, capa_datetime,
capa_log, capa_http) ship attestations from v0.1.2 onwards;
each repo's `.github/workflows/release.yml` is the canonical
publisher-side template.

**path source**:

```toml
mylib = { path = "../mylib" }
```

The parser is strict: unknown keys, a missing `git` / `path`, or
a git source without `tag`/`rev` are all errors with a pointer
at the offending entry. Typos in a config file should be loud,
not silent.

### `[dev-dependencies]`

Test- and tooling-only dependencies live in their own table with
**exactly the same per-entry schema** (git + `tag`/`rev` +
optional `verify_key`, or `path`) and the same security
validation (URL allow-list, name allow-list, pin shape, GPG /
SLSA verification):

```toml
[dev-dependencies]
capa_testkit = { git = "https://github.com/user/capa_testkit", tag = "v0.2" }
```

Semantics:

- `capa install` fetches dev-deps when run **on the project
  itself** (the invocation root), into the same `./vendor/`
  directory, so test files import them exactly like regular
  deps.
- When your package is consumed **as a dependency** of another
  project, its dev-deps are never fetched. (Capa v1 reads only
  the root manifest, so this holds by construction; it stays
  the contract when transitive resolution lands in v2.)
- A name declared in both `[dependencies]` and
  `[dev-dependencies]` is a parse error: both would vendor into
  `vendor/<name>`.
- In `capa.lock`, dev-dep entries carry `dev = true` so an
  auditor can tell test-only pins from shipping pins without
  re-reading the manifest. Entries without the marker are
  regular deps (older lockfiles parse unchanged).

`capa add --dev <name> ...` declares a dev-dependency from the
command line; with `--force` it also moves an existing entry
from one table to the other.

## Sources, in detail

### Git

`capa install` shallow-clones the git URL at the supplied
`tag`, or full-clones and checks out a specific `rev`. The
clone lands in `./vendor/<name>/`. The resolved commit SHA is
recorded in `capa.lock`. Re-running `capa install` after a pin
change wipes and re-fetches the directory, so the state stays
in sync with the manifest.

### Path

The path resolves relative to the manifest directory. It is
validated (must exist, must be a directory) but no files are
copied; the loader adds the path to its search list directly.
Useful when:

- Developing a library alongside its consumer (no `git push`
  required to test a change).
- Vendoring by hand into `./libraries/` is preferred over
  fetching at install time.

Path deps do not appear in `capa.lock`: they are by definition
not reproducible across machines.

## Lockfile

`capa.lock` records, for every git dep, the URL, the pin
(`tag` or `rev`) declared in the manifest, and the resolved
commit SHA. Lockfile entries are emitted in dependency-order
(regular deps first, then dev-deps, each in manifest order) so
diffs against `git diff` stay readable. Dev-dep entries carry
`dev = true`.

Commit `capa.lock` alongside `capa.toml`.

**Lockfile enforcement.** When `capa.lock` exists, `capa
install` reads it and refuses to silently consume a different
commit for the same git URL + pin. Concrete scenario: a
dependency declared as `mylib = { git = "...", tag = "v0.1" }`
resolves to SHA `abc` on the first install; the upstream
maintainer (or an attacker who compromised the account)
force-pushes `v0.1` to point at SHA `def`; the next `capa
install` clones the new SHA, compares against `capa.lock`,
sees `abc != def`, and exits with `LockMismatchError`
*without* overwriting the lockfile. The vendor directory has
the new code but the build is refused until the operator
acknowledges the change.

Two ways to accept the new SHA:

- Delete `capa.lock` and re-run `capa install`. Signals "I
  accept whatever the manifest pin resolves to today".
- Pass `capa install --update` (or `allow_lock_update=True`
  via the API). Same effect, friendlier for CI scripts that
  want to bump a single dep deliberately.

The check fires for `tag`-pinned deps only in practice; an
`rev`-pinned dep cannot move (the SHA is the pin), so a
mismatch there means the upstream rewrote git history, which
should also be loud.

## Loader resolution order

When the loader resolves `import x.y` from inside a `capa.toml`
project, it walks the following search paths, in order:

1. The directory of the importing `.capa` file (sibling
   imports work without configuration).
2. Every directory listed in the `CAPA_PATH` environment
   variable.
3. `./vendor/`: when `capa.toml` declares at least one git
   dependency (in `[dependencies]` or `[dev-dependencies]`).
4. The parent of every `path = "..."` dependency (both tables).
5. `./libraries/`: conventional fallback for hand-vendored
   projects.
6. The directory of the root file (so a submodule can import a
   sibling of the file the user passed to `capa --run`).

Each path is deduplicated, and a missing directory is silently
skipped (so an unused entry never produces an error).

## Worked example: extracting a library

Three of the seed libraries (`capa_cli`, `capa_datetime`,
`capa_log`) already live in standalone repos and are consumed
via the package manager; the fourth (`capa_http`) is still
under `libraries/` in the Capa repo. The same recipe applies
to it and to any user-authored library:

1. Copy the library directory out:
   ```bash
   cp -r capa-language/libraries/capa_log ./capa_log
   ```
2. `git init`, commit, tag a release:
   ```bash
   cd capa_log
   git init -b main
   git add -A
   git commit -m "Initial commit: capa_log v0.1"
   git tag v0.1
   gh repo create capa_log --public --source=. --push
   git push --tags
   ```
3. In every consumer project, replace the vendored copy with a
   git dep:
   ```toml
   # capa.toml
   [dependencies]
   capa_log = { git = "https://github.com/<user>/capa_log", tag = "v0.1" }
   ```
4. `rm -rf libraries/capa_log && capa install`.

The same process applies to any user-authored library.

## Resolving symbol collisions between dependencies

Two dependencies can export the same `pub` name. `capa_csv` and
`capa_cli` both ship a `pub fun parse`. A plain `import capa_csv`
+ `import capa_cli` merges both into one flat scope and the
loader reports a `name conflict: 'parse'`.

Use the **selective import** form to bring only what you need and
rename one (or both) sides:

```capa
import capa_csv (parse as csv_parse)
import capa_cli (parse as cli_parse)

fun main(stdio: Stdio)
    stdio.println(csv_parse(read_csv))
    stdio.println(cli_parse(argv))
```

Only one side needs a rename if the other's bare name is free:

```capa
import capa_csv (parse)
import capa_cli (parse as cli_parse)
```

Selectors cover functions, types, consts, and capabilities (see
[`reference.md`](reference.md) section 7.1 for the full rules).
This keeps the resolution explicit and auditable: the import line
names exactly which symbol came from which dependency.

## Limitations (v1)

- **No transitive resolution.** A dep's own `capa.toml` is
  not read; if `mylib` depends on `helperlib`, the top-level
  manifest has to declare both. Cargo / npm-style transitive
  resolution + version unification is planned for v2.
- **No `capa remove`.** `capa add` (with `--dev`, `--force`,
  `--no-install`) covers declaring deps; removal is still a
  hand edit of `capa.toml`.
- **No `capa install --frozen`.** Today every `capa install`
  re-fetches against the current pin. A future iteration will
  honour `capa.lock` as authoritative when `--frozen` is
  passed.
- **No private registries.** Every git dep is a URL clone;
  fine for public OSS, fine for private repos behind your
  shell's ssh agent. A centralised registry is out of scope
  for v1.
- **No version ranges in `capa = ".."`.** The field is read
  and stored but not yet checked against the running Capa
  version. Treat it as documentation for now.
