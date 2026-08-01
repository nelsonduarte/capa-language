# Capa security advisory, 2026-08-01: a hand-written Wasm artifact could exercise a capability it never declared

> **Status.** Published with the `1.25.1` release. On the Wasm backends
> the per-instance capability handle table was bootstrapped with a root
> handle for EVERY handle-bearing capability (Fs, Net, Db, Proc, Env,
> Clock) regardless of what the artifact declared, and those roots are
> small predictable integers. So a hand-crafted `.wasm` / `.cwasm`
> whose capability binding (`capa:main-cap-types`) named only one
> capability could forge the integer of an UNDECLARED capability's root,
> call that capability's `capa:host/*` import, and exercise authority it
> never declared. This is a capability-confinement bypass across
> capabilities: the artifact declared one authority and reached another.
> The fix bootstraps the table with a root only for the capabilities the
> artifact declares, so a forged integer for an undeclared capability
> fails the typed handle-table lookup and the privileged operation
> denies. That closes cross-capability forgery on all three Wasm hosts.
> It is a change to the observable behaviour of a covered surface, a
> forged access that previously succeeded now denies, claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** and
> therefore shipping as a **PATCH** bump, not a MAJOR one. The rationale,
> and the honest scope of what it does and does not give you, are stated
> below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: the Wasm capability handle backend has carried this
defect since it shipped. The handle-table foundation landed on
2026-05-30 (commit `45c6108`), and the design record confirmed the
forgeability present at commit `6321246` (2026-07-22) and noted it is
not a regression from recent work, so it is long-standing on the Wasm
backend. The exact first fully-exploitable release was not bisected, so
the honest range is **all releases with the Wasm capability backend,
through `1.25.0`**. The default Python backend was never affected.
Fixed in: `1.25.1`.
Reporter / process: found internally during a research, design, review
and pentest chain over the Wasm capability backend, and reproduced on
all three hosts that bootstrap the handle table, the core
`capa --run --wasm` host, the AOT `capa run-aot` path, and the Component
host, from a source checkout.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.25.1` `CHANGELOG.md`
entry.

## The finding

Capa's promise on the Wasm backends is that a program's authority is its
declared capability set, and that the manifest / SBOM reads that set off
the same declaration. The per-instance handle table is what carries a
capability into the running guest: `main`'s capability parameters are
root handles the host allocates at instance init, and every privileged
`capa:host/*` import takes a handle as its first argument, looks the
handle up in the table, and enforces the attenuation state bound to it.

Two facts combined into a bypass. First, the host bootstrapped the table
with a root handle for EVERY handle-bearing capability it could serve
(Fs, Net, Db, Proc, Env, Clock), regardless of which capabilities the
artifact's `capa:main-cap-types` binding actually declared. Second,
those roots are small consecutive integers assigned deterministically
(for example `stdio=1`, `fs=2`), and `WasmHost`'s linker defines every
`capa:host/*` import unconditionally. So a hand-written module could name
an integer it was never handed.

The consequence, measured and exiting 0: a hand-crafted `.wasm` /
`.cwasm` whose binding declared only `net` could import
`capa:host/fs.read`, call it with the integer the Fs root was
deterministically assigned, hit the live Fs root, and read a secret file
it never had authority over. No diagnostic, exit 0. It was reachable
through the shipped `capa run-aot` verb, and equally through the core
`capa --run --wasm` host and the Component host. This is a
cross-capability confinement bypass: the artifact declared one
capability (`net`) and exercised a different, undeclared one (`fs`).

## Threat model: who has to do what for this to bite

This is a **capability-confinement bypass on a hand-crafted or edited
Wasm artifact**, not remote code execution, and the trigger is worth
stating precisely.

It requires an artifact whose bytes were authored or edited to name a
handle integer its binding does not declare. A program the Capa compiler
produced from Capa source does not do this: the emitter passes each
`main` slot the root of its declared type, and Capa is memory-safe, so
Capa code cannot fabricate a handle. The exposure is at the
foreign-artifact boundary: an operator who runs a `.wasm` / `.cwasm`
that some other party crafted, trusting the artifact's declared
capability set (or its SBOM) as a statement of what it can do, while the
artifact reaches past that declaration into an undeclared capability's
authority.

What it does **not** grant is authority beyond the host capabilities the
process itself can perform (filesystem, network, process, environment,
clock, and database access through the same Python-side capability
objects). It is a real cross-capability confinement bypass, bounded to
that.

## The fix

The gate moved into the handle-table bootstrap. `bootstrap_root_handles`
now takes the artifact's declared capability kinds and allocates a root
for a handle-bearing capability ONLY when the artifact declares it; the
gated set is derived from `HANDLE_BEARING_CAPS`, so a capability
reclassified as handle-bearing cannot be left behind. The non-capability
host services (stdio, random, unsafe) carry no attenuation surface and
stay always-present. A forged integer for an UNDECLARED capability now
resolves to no table entry, or to the wrong-type entry a declared
capability occupies, and fails the typed handle-table lookup
(`CapHandleTable.lookup(handle, Fs)` raises), so the privileged operation
denies at the call. This lives in
[`capa/runtime/_cap_handles.py`](../../capa/runtime/_cap_handles.py),
with the two hosts passing their declared cap types from
[`capa/runtime/_wasm_host.py`](../../capa/runtime/_wasm_host.py) and
[`capa/runtime/_wasm_component_host.py`](../../capa/runtime/_wasm_component_host.py).

The linker was deliberately **not** changed: every `capa:host/*` import
stays defined. The gate is the missing root, not a missing import, so a
forged call reaches the bridge and is denied by the typed lookup rather
than failing to link. The result is that the declared capability set is a
runtime-enforced **upper bound** on the authority the artifact can
exercise, on all three hosts (core `--run --wasm`, AOT `run-aot`, and
Component). A regression test builds a module declaring only `net`, calls
`capa:host/fs.read` with the forged Fs-root integer, and asserts the
secret is denied on all three hosts; a bootstrap unit asserts an
undeclared handle-bearing capability receives no root
([`tests/test_wasm_cap_binding.py`](../../tests/test_wasm_cap_binding.py),
[`tests/test_cap_handles.py`](../../tests/test_cap_handles.py)).

## Honest scope: what this does and does not give you

This closes cross-capability forgery. It does not do more, and reading it
as more would be exactly the overclaim this project exists to avoid.

- **It restores the honesty of the declared / SBOM capability set, not a
  sandbox.** The imports an artifact can exercise can no longer exceed
  its declaration. But the `capa:main-cap-types` binding is the
  artifact's OWN, freely-editable self-declaration, and there is no
  operator-supplied capability allowlist on `run-aot`. A malicious
  artifact may simply declare all six handle-bearing capabilities and
  receive all six roots. `capa run-aot` is therefore **not** a sandbox
  for arbitrary or untrusted artifacts. Operator
  capability-allowlisting is a separate, open, undecided question.
- **The intra-capability widening residual is still open.** Within a
  capability it DID declare, root handles and their `restrict_to`
  children are still small predictable integers, so a guest can name the
  unrestricted root of that capability instead of an attenuated child.
  This is not a cross-capability escalation, it is authority the artifact
  already holds by declaring the capability, and on the single-artifact
  core path there is no in-instance trust boundary to escalate across.
  Full handle **unforgeability** (unguessable tokens, or a
  Component-Model resource-type migration) remains separate, deferred,
  tracked work.
- **The executed artifact stays in the TCB.** Running a
  third-party-supplied `.wasm` / `.cwasm` trusts that artifact's declared
  capability set as its authority ceiling. The fix makes that ceiling
  ENFORCED rather than advisory; it does not remove the artifact from the
  trusted computing base.
- **The default Python backend was never affected.** Capabilities there
  are first-class objects that carry their attenuation state directly;
  there is no handle integer to forge.

## Why this is a security fix and not a breaking change

Denying a forged handle changes observable behaviour: a hand-crafted
artifact that previously read a file through an undeclared capability now
gets a denial. Under `STABILITY.md` a runtime path that tightens so a
previously-successful input now fails would ordinarily be a major-bump
surface. It ships as a **patch** under the **security exception**,
because the previous success was itself the vulnerability. A declared
capability set that an artifact could exceed at will is not a smaller
confinement than intended, it is a broken one, and the SBOM it produced
misreported the artifact's authority. The direction of the change is
strictly narrowing: only a call that reached an undeclared capability now
fails, and no artifact whose imports stay within its declaration is
affected.

## Who is affected, and what to do

You are affected if you ran a `.wasm` / `.cwasm` you did not compile
yourself from trusted Capa source on a Wasm backend of any release
through `1.25.0`, and relied on that artifact's declared capability set
(or an SBOM derived from it) as a true statement of the authority it
could exercise. A forged artifact could exercise a handle-bearing
capability its binding never declared.

**Remediation is to upgrade to `1.25.1`.** There is no mitigation short
of upgrading: on an affected version the table served every capability
root unconditionally, with no flag or setting that gated it to the
declared set. After upgrading, note the honest scope above: `run-aot`
still runs the artifact's own declared capabilities and is not a sandbox
for an artifact you do not trust, so continue to treat a third-party
`.wasm` / `.cwasm` as trusted code whose declared capability set is now
enforced as its ceiling, not as a confined guest.
