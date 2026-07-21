# `fleet/`: the canonical copies of what every adopter copies

Every repository that adopts the shared release guards also copies four
test files and the workflow that runs them, together about 1700 lines of
security-checking logic.
Fifteen more repositories are queued to receive them.

Nothing noticed when a copy diverged. This fleet has been bitten by that
twice: a capability tuple hand-copied at 21 sites in this repository that
had already drifted before anyone looked, and `capa_authgate`'s
`check_tag_version.sh` becoming a second copy whose two versions
immediately printed different messages while looking interchangeable.

The alternative to copying was to hoist the bodies into the compiler and
have adopters invoke them. That was rejected deliberately, because these
tests have to run on a machine with nothing installed and no network,
which is the property that makes them runnable at all. So the copies
stay, and a drift check is what keeps them honest.

Copying a *guard* is a different question and was answered the other
way: `capa_authgate` used to keep a byte-identical copy of
`tools/check_tag_version.sh` so it could be rehearsed offline, and that
copy had already drifted once. It is gone, and the guard is now tested
once, here, by `tests/test_check_tag_version.py`, against the file the
release actually runs.

## What is here

| Path | What it is |
| --- | --- |
| `templates/tests/test_release_wiring.sh` | The canonical wiring test. Complete file, config block filled with placeholders. |
| `templates/tests/test_wiring_mutations.sh` | The canonical mutation test for it. Same shape. |
| `templates/tests/test_shared_regions.sh` | The adopter-side drift check. Zero configuration; copied verbatim. |
| `templates/tests/test_guard_pins.sh` | The adopter-side guard-pin audit. Zero configuration; copied verbatim. |
| `templates/.github/workflows/checks.yml` | The CI workflow that RUNS the four on every push. A `whole:` entry; do not edit it in an adopter. |
| `templates/.github/shared-regions.sha256` | The adopter's audit record, with the digests filled in and the revision left as an unusable placeholder so an unedited copy fails closed. |
| `shared-regions.sha256` | The canonical digests, which the adopter record copies. |
| `shared_region_digest.sh` | Regenerates those digests after a deliberate change here. |
| `adopt.sh` | Performs an adoption or a re-pin against one repository. Not copied into adopters, and not in the record; see below. |

The templates are stored as COMPLETE files rather than as headerless
fragments, so that the extraction logic is identical on both sides of
the comparison. A fragment would need assembly rules of its own, and two
implementations of a boundary is how a boundary moves.

## How the drift check works

There are two kinds of entry, and which kind a file is is the design
decision that matters most here.

### Region entries

`test_release_wiring.sh` and `test_wiring_mutations.sh` have to say
repo-specific things, so each is split by two marker lines:

```
# ================== CONFIG: the only repo-specific part ==================
# ======================= END CONFIG; shared body =========================
```

Everything OUTSIDE that region, markers included, is digested and
compared. The markers are inside the digested region on purpose: if they
were outside it, the marker text could be edited to move the boundary and
enlarge the part nobody checks.

The config region is un-digested by construction, so a digest alone is
not enough. It is therefore also checked by GRAMMAR: blank lines,
comments, and single-line assignments to an allowlist of names, each
exactly once, and nothing else. Without that rule, one line reading
`trap 'exit 0' EXIT` placed in the config region makes the wiring test
exit 0 while still printing every failure it found. That is a green CI
run over a release gate that is no longer there, and the shared-region
digest does not move.

### Whole-file entries

`test_shared_regions.sh`, `test_guard_pins.sh` and
`.github/workflows/checks.yml` have no repo-specific content at all, so
the whole file is digested. They carry no markers, no config block, no
grammar and no allowlist.

**Keep it that way.** The config region is the only part of a shared
file that nothing digests, which makes it the un-digested attack
surface. Adding one to a zero-config file, to carry some future flag
needed in one repository out of twenty-two, would manufacture exactly
the bypass class the grammar exists to police. If a zero-config file
needs to vary, change it here for everyone.

The drift check being a whole-file entry is what makes it cover itself.
Before it was, its own table of checked files was in no record: deleting
one row removed a file from the check entirely, and both the drift check
and the neutralised wiring test then reported success. Measured, before
the change:

```
delete the wiring-test row from SHARED_FILES, then neutralise the wiring test
  drift check : exit=0   FAILs=0
  wiring test : exit=0
```

Self-digesting would not have closed that, since whoever edits the table
can regenerate the number. Layer 2 does, because the number it compares
against is upstream's.

## Something has to actually run them

All four test files once appeared in both adopters' YAML only inside
comments. Four controls whose entire purpose is noticing silent
divergence executed zero times per push, across a fleet of seventeen
repositories, and would have gone on doing so until someone ran them by
hand. A drift check that runs when a human remembers reports the state
of that human's memory.

`templates/.github/workflows/checks.yml` is the workflow that runs them,
and it is itself a `whole:` entry in the record, so every byte of it is
compared against the canonical copy. **Do not edit it in an adopter.**
A repository that needs more CI adds a separate workflow, which is what
every adopter with extra checks has already done.

It was briefly left out of the record on the premise that workflows
differ per repository, so byte-identity would force forks. The fleet
had already falsified that premise. `capa_authgate` is the shape it
predicted would need variation, with five entry points, a negative
ceiling entry, a compiler-rejects fixture and nested vendoring, and its
copy is byte-identical to the pure library's. That is structural rather
than lucky: every repo-specific fact is absorbed by the CONFIG region of
the wiring tests one layer down, and this workflow only ever invokes
four fixed script paths. So there was no variation to accommodate, and
no YAML config grammar was needed; the existing `whole:` kind was
enough.

Leaving it out also left a one-line bypass. The check that stood in for
a digest asked whether each shared file was NAMED by a step, refusing
`|| true`, `if: false` and `continue-on-error: true` on a step. A
job-level disable is none of those:

```yaml
  wiring:
    runs-on: ubuntu-latest
    if: false
```

reported `30 passed, 0 failed, 0 skipped`, exit 0, with the whole
apparatus off. That is the line a person writes to park a job, so it was
the accident case as much as the attack case.

The naming check is kept, in a smaller role. It is cheap and it covers
two states the digest does not: a repository mid-adoption whose record
does not yet carry `checks.yml`, and a repository invoking the shared
files from some other workflow, which is not digested and never will
be. It is no longer the mechanism.

**What no digest reaches.** Actions being disabled for the repository,
branch protection not requiring these checks, and the required-check
configuration itself. Those live in GitHub settings rather than in git,
so no file-based mechanism here covers them.

## The two layers

Layer 1 is offline, compares against the recorded digest, and never
skips. Layer 2 fetches the canonical file at the pinned revision and
confirms the recorded digest is that file's own; it may SKIP without
`gh`. Layer 1 alone would be self-certifying, since anyone who edits a
body can regenerate the number; layer 2 is what stops that.

The audit record carries its OWN `revision` line, independent of the
guard pin in `.github/guard-pins.sha256`. Sharing one revision would make
every guard bump force a wiring re-audit and every wiring bump force a
guard re-audit, and that friction is the likeliest reason for either
audit to be skipped.

## Guard-pin completeness, stated twice on purpose

`test_guard_pins.sh` requires the audit record to cover every file the
release guards execute. It says so twice:

* a HARDCODED list, which is the only completeness statement available
  with no network, and which is itself a fleet fact replicated into
  every copy;
* a DERIVED set, read out of the pinned `release-guards.yml` while it is
  being fetched anyway, which is what notices a sixth guard file
  appearing upstream without twenty-two files changing in lockstep.

The derived set is ADDITIVE and never a replacement. It is a regex over
YAML, so an invocation written some other way would not be seen; on its
own it would under-approximate what runs, which is the one outcome this
must not ship. A divergence between the two lists is itself a signal
worth reading.

## Adopting, per repository

```
bash fleet/adopt.sh <target-repo-dir> <compiler-ref>
```

That is the whole adoption. It resolves the ref to a full commit SHA,
fetches the five shared files and all five digests **from that
revision**, splices your existing CONFIG blocks into the fresh bodies,
asserts `.gitattributes` pins LF, and runs the installed drift check.

**Why it exists rather than the checklist below.** Two of the manual
steps could go wrong quietly, and one was uniquely dangerous:
transcribing the five digests. The natural shortcut is to copy
`.github/shared-regions.sha256` from a sibling repository rather than
from the compiler revision being adopted. If that sibling is one
revision stale, layer 1 goes **green**, because the test files came from
the same stale place and genuinely match, while layer 2 goes red. The
obvious response is to bump the revision line until it passes, and that
is exactly the "update the digests without re-copying" fork the record's
own header warns against. It is the one place in this design where the
obvious way to make it green is the wrong action; everywhere else the
wrong move looks wrong. The script does not discourage that path, it
removes it: no human transcribes a digest and no sibling is ever read.

**Run it from a checkout of the revision you are adopting.** It refuses
otherwise, and that refusal is the second thing it exists for. Every
byte comes from the API at the resolved revision; your checkout is not
read for any of them. So if your `fleet/templates/` differs from that
revision, you install files you have not read and then write a commit
message describing files that were not installed. That is not
hypothetical: the script's first real use adopted `ddf452e` from a
branch carrying an unpushed template change, installed `ddf452e`, and
produced two commit messages in two repositories asserting the opposite
of what they contained. The record is the one file no digest covers, so
nothing downstream would ever have caught it. At two repos it gets
noticed; at fifteen it is fifteen stale stampings.

**When it refuses rather than repairs.** A CONFIG block whose markers
are malformed, or whose set of assigned names differs from the
template's in either direction. Both are questions about what your
repository means, and a script that answered them would invent a value
nobody chose. The refusal names the file and the exact names.

All refusals fire **before anything is written**, and say so.

**What it does not reach.** Whether Actions is enabled, whether branch
protection requires these checks, and the required-check configuration.
Those live in GitHub settings rather than in git. The script says so on
every run.

`adopt.sh` is deliberately **not** in the shared-region record. That
record exists because files are copied and copies drift; this file is
copied nowhere, lives here, and has one instance. Shipping it into
seventeen repositories in order to check that seventeen copies agree
would manufacture the problem the record exists to solve. It is held
honest the way `tools/check_tag_version.sh` is: one copy, tested where
it lives, by `tests/test_fleet_adopt.py`.

### What the script does not do for you

1. Fill in the CONFIG block of the two wiring tests. On a fresh adoption
   every value in them is a placeholder; the script says so and names
   the files. Run `bash tests/test_release_wiring.sh` and fix what it
   reddens, which will name every top-level module you have not
   accounted for. Edit ONLY the CONFIG block: nothing else in those two
   files, and nothing at all in the other three.
2. The release workflows, the manifest floor and the clean-room
   rehearsal, which are the checklist in the wiring test's own header.
3. Require the `checks` workflow on the default branch, in the
   repository settings, and confirm Actions is enabled.

If you are adopting by hand instead, the steps are: copy all four of
`templates/tests/*.sh` into `tests/`; copy
`templates/.github/workflows/checks.yml` into `.github/workflows/`
verbatim; copy `templates/.github/shared-regions.sha256` into `.github/`
and replace the placeholder `revision` with the compiler commit you
copied from, taking the digests from THAT commit's
`fleet/shared-regions.sha256` and not from another adopter; add
`* text eol=lf` to `.gitattributes`; then run
`bash tests/test_shared_regions.sh` and `bash tests/test_guard_pins.sh`
and expect both green with layer 2 confirming rather than skipping.
Prefer the script: the digest-transcription step above is the one this
apparatus cannot make safe by hand.

Editing only the CONFIG block is the whole design: if you find yourself
editing below the line, the config block is missing a dimension, and the
fix is to add one here rather than to fork the body. If you find
yourself editing a whole-file entry at all, the same applies with no
exceptions, because there is no line to be below.

## Changing a template

1. Edit the template here.
2. `bash fleet/shared_region_digest.sh` and record the new numbers in
   `shared-regions.sha256` AND in
   `templates/.github/shared-regions.sha256`.
3. `python -m unittest tests.test_fleet_templates`, which runs the real
   adopter-side checks against the templates, drives layer 2 through a
   stubbed `gh`, and refuses any disagreement between the awk and Python
   implementations.
4. In each adopter, read the diff, then

   ```
   bash fleet/adopt.sh <adopter-dir> <the new compiler revision>
   ```

   which re-copies all five files, preserves the local CONFIG blocks,
   and rewrites the revision and the digests together from that
   revision. It refuses rather than guessing if the set of CONFIG names
   changed, which is the case where reading the diff was the point.

Updating an adopter's digests without re-copying is how a local edit
becomes a permanent fork with a green test over it.
