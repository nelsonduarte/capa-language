# `fleet/` — the canonical copies of what every adopter copies

Every repository that adopts the shared release guards also copies
`tests/test_release_wiring.sh` and `tests/test_wiring_mutations.sh`,
together about a thousand lines of security-checking logic. Fifteen more
repositories are queued to receive them.

Nothing noticed when a copy diverged. This fleet has been bitten by that
twice: a capability tuple hand-copied at 21 sites in this repository that
had already drifted before anyone looked, and `capa_authgate`'s
`check_tag_version.sh` becoming a second copy whose two versions
immediately printed different messages while looking interchangeable.

The alternative to copying was to hoist the body into the compiler and
have adopters invoke it. That was rejected deliberately, because these
tests have to run on a machine with nothing installed and no network,
which is the property that makes them runnable at all. So the copies
stay, and a drift check is what keeps them honest.

## What is here

| Path | What it is |
| --- | --- |
| `templates/tests/test_release_wiring.sh` | The canonical wiring test. Complete file, config block filled with placeholders. |
| `templates/tests/test_wiring_mutations.sh` | The canonical mutation test for it. Same shape. |
| `templates/tests/test_shared_regions.sh` | The adopter-side drift check. No repo-specific configuration; copied verbatim. |
| `templates/.github/shared-regions.sha256` | The adopter's audit record, with the digests filled in and the revision left as an unusable placeholder so an unedited copy fails closed. |
| `shared-regions.sha256` | The canonical digests, which the adopter record copies. |
| `shared_region_digest.sh` | Regenerates those digests after a deliberate template change. |

The templates are stored as COMPLETE files rather than as headerless
fragments, so that the extraction logic is identical on both sides of
the comparison. A fragment would need assembly rules of its own, and two
implementations of a boundary is how a boundary moves.

## How the drift check works

Each shared file is split by two marker lines:

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

There are two layers. Layer 1 is offline, compares against the recorded
digest, and never skips. Layer 2 fetches the canonical template at the
pinned revision and confirms the recorded digest is the template's own;
it may SKIP without `gh`. Layer 1 alone would be self-certifying, since
anyone who edits the body can regenerate the number; layer 2 is what
stops that.

The audit record carries its OWN `revision` line, independent of the
guard pin in `.github/guard-pins.sha256`. Sharing one revision would make
every guard bump force a wiring re-audit and every wiring bump force a
guard re-audit, and that friction is the likeliest reason for either
audit to be skipped.

## Adopting, per repository

1. Copy `templates/tests/*.sh` into `tests/`.
2. Copy `templates/.github/shared-regions.sha256` into `.github/`, and
   replace the placeholder `revision` with the commit of this repository
   you copied from.
3. Edit ONLY the CONFIG block of the two wiring tests. Nothing else.
4. `bash tests/test_shared_regions.sh` — expect it green with layer 2
   confirming the digests rather than skipping.
5. Follow the adoption checklist in the wiring test's own header, which
   covers the workflows, the manifest floor and the clean-room rehearsal.

Step 3 is the whole design: if you find yourself editing below the line,
the config block is missing a dimension, and the fix is to add one here
rather than to fork the body.

## Changing a template

1. Edit the template here.
2. `bash fleet/shared_region_digest.sh` and record the new numbers in
   `shared-regions.sha256` AND in
   `templates/.github/shared-regions.sha256`.
3. `python -m unittest tests.test_fleet_templates`, which runs the real
   adopter-side check against the templates and refuses any
   disagreement.
4. In each adopter: read the diff, re-copy both files keeping the local
   CONFIG blocks, then update the revision and the digests together.

Updating an adopter's digests without re-copying is how a local edit
becomes a permanent fork with a green test over it.
