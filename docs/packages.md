# Capa packages: `capa.toml` and `capa install`

Capa projects declare their dependencies in a `capa.toml`
file at the project root. Running `capa install` resolves the
declared deps, fetches the git ones into `./vendor/`, and writes
a `capa.lock` so the resolution is reproducible.

When a `capa.toml` file is present in the working directory, the
Capa loader picks up `./vendor/` and the parent of every `path =`
dep automatically, no `CAPA_PATH` environment variable needed.

For the security posture of each step below (which checks are
fail-closed, which are best-effort, and what is trusted as a premise),
see the [trust model](trust-model.md).

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

#### Where `verify_key` comes from, and what it actually proves

You can set `verify_key` two ways, and they give **different**
strength guarantees:

- **Pinned by hand** (you write the fingerprint into `capa.toml`,
  or pass `capa add --verify-key <fpr>`). This is the strong form:
  you obtained the publisher's fingerprint out of band (their
  website, a keyserver you trust, a prior known-good release) and
  the install refuses anything not signed by that exact primary
  key. The trust is anchored on the publisher's own identity.

- **Filled from the registry index** (`capa add <name>` with no
  `--verify-key`). The index entry carries the `verify_key`, and
  the index itself is signed by the registry **root key** baked
  into the toolchain. This is **trust-on-first-use (TOFU) anchored
  on the root key**, not independent verification of the publisher:
  you are trusting that whoever holds the root key vouches for the
  fingerprint in that entry. It is genuinely weaker than a
  hand-pinned key, where you verified the publisher yourself.

For anything you care about, prefer pinning `verify_key` by hand.

> **Known limitation: single root key.** The registry index and
> every package fingerprint it vouches for are anchored on one
> root key. That key is a single point of failure: a compromise of
> the root key lets an attacker re-sign an index that points every
> unpinned dependency at attacker-chosen code and keys. Pinning
> `verify_key` manually removes that dependency for the deps you
> pin (they no longer trust the index for their fingerprint).
> Per-publisher keys / delegated trust are a deliberate future
> direction, not a property of the current model.

#### SLSA L2 build provenance (`verify_provenance`)

When the git URL points at GitHub AND the pin is a tag AND the
`gh` CLI is on your PATH, `capa install` runs
`gh attestation verify` against the source tarball attached to
the GitHub release for that tag, against the public Sigstore
Rekor transparency log. This is the third supply-chain layer
(lockfile SHA + GPG fingerprint + SLSA L2 provenance). The
attestation check is scoped to `--repo {owner}/{repo}` (not just
`--owner`), so an attestation built from a *different* repo under
the same owner does not satisfy it.

`capa install` always refuses when the release tarball is
published **and** its SLSA attestation in Rekor is invalid,
tampered, or issued by a different identity than the repository.
That fail-closed path holds in every mode.

What happens when a *precondition* is missing (not GitHub-hosted,
`gh` absent, no release tarball, offline, or a rev pin) is
controlled per dependency by the `verify_provenance` field, which
takes one of three values:

```toml
[dependencies.mylib]
git = "https://github.com/user/mylib"
tag = "v0.1"
verify_provenance = "warn"   # off | warn | required
```

- **`off`** every graceful-skip path is a silent no-op. Use this
  only when you deliberately want SLSA verification disabled for
  this dependency.
- **`warn`** (**default**) every graceful-skip path prints a clear
  stderr warning naming the dependency and the reason
  (`capa: warning: SLSA provenance not verified for 'mylib': gh
  not found in PATH`), then continues the install. Best-effort,
  but no longer invisible: a silent SLSA downgrade now leaves a
  trace.
- **`required`** every path that would otherwise skip becomes
  **fail-closed**: the install is refused with a message that
  names the dependency and the reason. Only a build with a valid
  Sigstore attestation passes. This is the strict, supply-chain-
  hardened mode.

`verify_provenance` is independent of `verify_key`: a dependency
can require provenance without pinning a GPG key, and the SLSA
layer is reached on its own (it is no longer gated behind
`verify_key`). It applies only to git deps; setting it on a path
dependency is a manifest error.

> **CI gate: `CAPA_REQUIRE_PROVENANCE=1`.** Setting this
> environment variable raises the *effective* level of **every**
> dependency to `required`, regardless of each dep's `capa.toml`
> value. It only **tightens** (it never lowers a dep below what
> its `capa.toml` already asks for). Set it in CI to refuse any
> build whose SLSA provenance cannot be verified, without editing
> every dependency entry.

> **Security posture.** In `warn` (the default) the SLSA layer is
> **best-effort but visible**: when `gh` is absent, the asset is
> missing, the host is not GitHub, or the network is down, the
> install continues but prints a warning. It is `required` (per
> dep, or globally via `CAPA_REQUIRE_PROVENANCE=1`) that makes the
> layer **fail-closed**. Do not read the default as a guarantee:
> only the lockfile-SHA and GPG-fingerprint layers are
> unconditional in every mode. Under `warn`, treat SLSA
> verification as a bonus you can *see* the absence of; under
> `required`, it is load-bearing.

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
optional `verify_key` + optional `verify_provenance`, or `path`)
and the same security validation (URL allow-list, name allow-list,
pin shape, GPG / SLSA verification):

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

**Build-time re-verification of `./vendor/`.** Lockfile
enforcement at install time is not enough on its own: once a dep
is vendored, the read/build path (`capa --check` / `--run` /
`--transpile`, `capa migrate`, and the per-test subprocesses
`capa test` spawns) reads the sources straight out of
`./vendor/<name>/`. If those files are tampered with *after*
install (a rebase of `vendor/<name>` onto a malicious commit, an
in-place edit of the checked-out files, or a stale checkout that
drifted from the lock), nothing would otherwise notice. So before
the loader is allowed to read `./vendor/`, Capa re-verifies every
git dep against `capa.lock`. Per dep, two local, offline checks
(no network, no re-clone, no re-run of GPG):

- `git -C vendor/<name> rev-parse HEAD` must equal the SHA the
  lockfile froze; and
- `git -C vendor/<name> status --porcelain` must be empty, i.e.
  the working tree must be clean at that commit.

The HEAD check alone is not enough: editing a tracked file in
`vendor/<name>` *without committing* leaves HEAD equal to the
locked SHA, so the adulterated code would run undetected. The
working-tree check closes that, the most trivial post-install
tamper vector. It uses `status --porcelain` (not `diff --quiet
HEAD`) so it also catches a deleted or substituted file and a
planted untracked importable module; a freshly cloned vendor tree
reports clean, and a normal Capa build writes no artifacts into
`./vendor/` source dirs, so this does not produce a false
positive on a healthy install.

This is **fail-closed**: the build is refused, naming the
dependency and telling you to run `capa install`, when

- `capa.toml` declares git deps but there is no `capa.lock`;
- `vendor/<name>` is missing or has no `.git` (not verifiable);
- the HEAD of `vendor/<name>` differs from the locked commit;
- the working tree of `vendor/<name>` is not clean at HEAD (an
  in-place edit, deletion, or substitution of a checked-out file);
- the working tree cannot be inspected (git absent or errored:
  unverifiable, so fail-closed);
- a git dep in `capa.toml` has no entry in `capa.lock`.

The premise is that `capa.lock` is committed and is part of the
project's trusted computing base: its `commit` was already
GPG/SLSA-verified at install time, so re-checking the SHA *and*
the working tree on each build is exactly what catches
post-install vendor tampering. By the same premise, what this
does **not** catch is an attacker who adulterates `vendor/<name>`,
commits the change so HEAD moves, *and* rewrites `capa.lock` to
match: an attacker who can rewrite the committed lockfile has
already breached the trusted computing base this check builds on. In
the same out-of-model class, `git update-index --assume-unchanged` or
`--skip-worktree` on a vendor file (or an uninitialised vendored
submodule) can mask an edit from `git status --porcelain`. That too
requires an attacker who already has local write access and runs git
locally, against a lockfile and a local git state that are part of the
project's trusted computing base, so it is the same class of threat as
a coherently rewritten lock, not a new gap.

The check applies to git deps declared in `capa.toml` and
vendored under `./vendor/` only. Path deps carry no locked commit
and are never verified. `CAPA_PATH` directories and the
`./libraries/` fallback are **operator-trusted source roots that
sit outside this per-SHA guarantee**: the verification is keyed by
the git deps of `capa.toml` resolved under `./vendor/`, not by
arbitrary search paths, so code reached through `CAPA_PATH` or
`./libraries/` is read on the operator's trust, not against a
locked commit. `capa install` and `capa add` are not subject to
the check (they *generate* the verified state; verifying before
install would be circular).

**Opt-out: `CAPA_NO_VERIFY=1`.** Setting this environment
variable skips the build-time verification entirely, with a
single warning. It **annuls the build-time supply-chain
guarantee** that `./vendor/` matches the locked, verified
commits, and exists only for the rare case where the
re-verification is genuinely in the way (for instance bisecting
offline against a hand-checked-out vendor tree). Do not set it in
CI or in any build whose supply-chain integrity you rely on.

> **Note (LSP).** The language server does not resolve imports
> from `./vendor/`, so it never executes or analyzes
> unverified vendor code. This is a known divergence from the
> compiler's loader resolution: the editor experience does not
> reach into `./vendor/`, and the execution risk from that path
> is therefore nil. The build-time check above is what guards the
> compiler's read of `./vendor/`.

## Loader resolution order

When the loader resolves `import x.y` from inside a `capa.toml`
project, it walks the following search paths, in order:

1. The directory `capa.toml` binds to the import's leading name:
   the declared directory of a `path = "..."` dependency of that
   name, or the project root itself when it matches
   `[package].name`. The latter is what lets a repository that
   *is* the package import its own modules as `<pkg>.<module>`;
   it is scoped to that one declared name, and a declared
   dependency of the same name wins.
2. The directory of the importing `.capa` file (sibling
   imports work without configuration).
3. Every directory listed in the `CAPA_PATH` environment
   variable.
4. `./vendor/`: when `capa.toml` declares at least one git
   dependency (in `[dependencies]` or `[dev-dependencies]`).
   Before this entry is added, the vendored git deps are
   re-verified against `capa.lock` (see "Build-time
   re-verification of `./vendor/`" above); an unverifiable vendor
   tree refuses the build unless `CAPA_NO_VERIFY=1` is set.
5. The parent of every `path = "..."` dependency (both tables).
6. `./libraries/`: conventional fallback for hand-vendored
   projects.
7. The directory of the root file (so a submodule can import a
   sibling of the file the user passed to `capa --run`).

Each path is deduplicated, and a missing directory is silently
skipped (so an unused entry never produces an error).

The directory *containing* the project root is deliberately absent
from that list. It was a search root once, to serve the
self-reference in item 1, but as an open root it also satisfied
imports that `./vendor/` could not: an undeclared transitive
dependency would resolve against whatever same-named sibling
directory happened to sit next to the project, linking sources
that were never fetched, never verified against `capa.lock` and
never recorded in the SBOM. A missing dependency now fails closed
with "cannot resolve", which is the diagnosable failure.

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
