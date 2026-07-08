# Typed foreign-component ABI (feature #4)

A **typed foreign component** is an external Wasm Component Model artifact
Capa calls across a declared, capability-checked boundary:

```capa
extern component Bureau from "vendor/bureau.wasm"
    fun submit(net: Net, x: Int) -> Int

fun main(net: Net) -> Int
    return Bureau.submit(net, 41)
```

The Wasm runtime physically confines the component to exactly the
capabilities the call grants, so the SBOM's honest-but-coarse
authority-unknown TOP node becomes a **sound BOUNDED node** under the
Wasm-sandbox posture. This note pins the ABI contract a foreign component
must conform to, so a component author (in any language that compiles to a
Wasm component) and the Capa host agree.

## The three signatures

A declared method such as `submit(net: Net, x: Int) -> Int` maps to THREE
distinct signatures, because a capability is authority (never a plain
value) and must be host-mediated, not handed to the child as data:

1. **Child export** (what the foreign component provides):

   ```wit
   export submit: func(x: s64) -> s64;
   ```

   Only the ordinary (scalar) parameters appear. Capabilities do NOT
   appear as export params.

2. **Child imports** (how the child receives capabilities): the child
   IMPORTS the canonical `capa:host/<cap>` interface for each granted
   capability, with the exact Capa signatures (see
   `capa.ir._emit_wit._WIT_SIGNATURES`), e.g.

   ```wit
   package capa:host;
   interface net {
     get: func(handle: u32, url: string) -> result<string, io-error>;
     post: func(handle: u32, url: string, body: string) -> result<string, io-error>;
     restrict-to: func(handle: u32, host: string) -> u32;
     allows: func(handle: u32, host: string) -> bool;
   }
   world netchild {
     import net;
     export submit: func(x: s64) -> s64;
   }
   ```

3. **Parent import** (what the Capa parent core module calls): the
   capability params become `u32` handles so the host can resolve the
   caller's pre-attenuated cap:

   ```
   (import "capa:foreign/Bureau" "submit"
       (func $foreign_Bureau_submit (param i32) (param i64) (result i64)))
   ```

   The `i32` is the guest's cap handle; the `i64` is the scalar `x`.

## The host-bound linker (why this is sound)

For each call the host (`capa.runtime._foreign.dispatch_foreign_call`):

1. Resolves each `u32` handle on the PARENT's handle table into the
   caller's already-attenuated cap instance (`Net` restricted to
   `example.com`, say).
2. Builds a RESTRICTED Component-Model linker that registers ONLY the
   `capa:host/<cap>` interfaces for the granted caps. Each interface's
   host closures **capture the resolved cap and IGNORE any guest-supplied
   handle**, so the child holds no authority-bearing value it could forge
   or widen. `restrict-*` on the child is a no-op (returns 0): the child
   can never exceed the caller's grant.
3. Instantiates the child in its OWN fresh store. A child that imports any
   `capa:host/<cap>` interface NOT granted fails at `instantiate` -- a
   host-enforced STRUCTURAL deny of the capability SET, surfaced as
   `ForeignDenied`. This is the core win: static-declared == runtime-
   enforced for the capability set.
4. Calls the child's export with the scalar args and returns the scalar
   result.

Scalar arguments and the scalar result marshal through this Python closure
(Int -> i64/s64, Bool -> i32/bool, Float -> f64), so no cross-store value
lifting is needed.

## String crossing types (F2b)

F2b adds the **String** crossing type, reusing the SAME canonical-ABI
machinery the WASI cap methods already use for strings. A method
`submit(net: Net, s: String) -> String` maps to:

1. **Child export** -- only the ordinary params appear; a String is a
   canonical `string`:

   ```wit
   export submit: func(s: string) -> string;
   ```

   The child must provide `cabi_realloc` (the canonical ABI allocates the
   argument's lowered bytes and the returned string in the child's
   memory). wasmtime-py lifts/lowers between the component `string` and a
   Python `str` automatically -- the host closure just hands the child a
   `str` and gets a `str` back.

2. **Parent import** -- the String does NOT lower to a single core value.
   A String ARGUMENT crosses as a `(ptr, len)` i32 pair pushed straight
   from the value's bytes in the parent's linear memory
   (`_push_string_arg`). A String RESULT uses the canonical-ABI indirect
   return: the parent allocates an 8-byte return area, passes its pointer
   as the trailing import arg, and the host writes `(ptr, len)` into it
   after copying the returned bytes into the parent's memory via `$alloc`.
   The parent then materialises a Capa `String` from the area (the shared
   `string` materialiser).

   ```
   (import "capa:foreign/Bureau" "submit"
       (func $foreign_Bureau_submit
           (param i32)   ;; net cap handle
           (param i32)   ;; s_ptr
           (param i32)   ;; s_len
           (param i32))) ;; ret_area (8 bytes: out_ptr @0, out_len @4)
   ```

The host closure reads the String argument out of the caller's memory
into a Python `str`, dispatches the child export, and writes the returned
`str` back. This is the ONLY change F2b makes: **which VALUE types cross
the boundary**. The sandbox enforcement is byte-for-byte identical to F2a
(same restricted host-bound linker, same bare store, same handle
resolution, same structural cap-set deny). A String is plain data
(F1-quarantine-clean) and carries no authority.

## Resource ceiling (sandbox availability bound)

Confinement (which capabilities the child can reach) is only half of a
sandbox; the other half is a RESOURCE BOUND so a malicious or buggy
foreign component cannot deny service to the host. The child store is
therefore metered on THREE axes IN ADDITION to the restricted linker
(`capa.runtime._foreign.dispatch_foreign_call`):

- **CPU (fuel).** The child runs on a `consume_fuel` engine with a
  bounded per-call fuel budget (`Store.set_fuel`). wasmtime charges ~1
  fuel per executed wasm instruction, so an infinite loop / CPU spin
  drains the budget and TRAPS ("all fuel consumed") instead of hanging
  the host forever. The host reports it as a clean
  `foreign component <label>: exceeded its CPU/fuel budget` diagnostic
  (exit 1), detected robustly by `Store.get_fuel() == 0` after the trap.
- **Store growth.** `Store.set_limits` bounds EVERY growable store
  resource, not just linear memory: `memory_size` (the linear-memory
  ceiling), `table_elements` (funcref/table growth -- fuel does NOT
  bound `table.grow`, so an ~8-byte-per-element table could otherwise
  allocate ~1 GB under the memory cap), and the `memories` / `tables` /
  `instances` object counts. A child whose declared minimum exceeds a
  limit is refused at instantiation; a runaway `memory.grow` /
  `table.grow` returns `-1` so the host never OOMs. Over-limit
  instantiation surfaces as
  `foreign component <label>: exceeded its memory / resource limit`
  (exit 1).
- **Host wall-time in blocking closures.** Fuel meters wasm
  instructions, NOT time spent inside a granted host closure, so a
  blocking closure the child can reach is bounded separately or it would
  hang the host despite the fuel ceiling. `clock.sleep` is clamped to a
  bounded maximum per call; a `db.exec` / `db.query` SQL statement is
  aborted past a bounded wall-clock deadline (a sqlite progress handler);
  `net.get` / `net.post` (urllib `timeout=10`) and `proc.exec`
  (`timeout=30`) are already bounded in `capa.runtime._capabilities`.

This is separate from the parent `--wasm-memory-cap` (which bounds the
PARENT's `$alloc` write-back of a returned aggregate); the ceiling here
bounds the untrusted CHILD's OWN allocation, CPU, and blocking time. The
confinement (restricted linker, granted-cap set, host-bound closures,
handle resolution, marshalling) is UNCHANGED -- this only adds the store
ceiling and the blocking-closure bounds. The child is still confined to
its granted capabilities; now it also cannot hang or exhaust the host by
CPU spin, unbounded blocking, or runaway allocation.

**Defaults and flags.**

| Axis | Default | Flag | Notes |
|------|---------|------|-------|
| CPU | 1,000,000,000 fuel (~1e9 instr) | `--foreign-fuel <N>` | `0` opts out (child runs on the unmetered engine); negative is rejected. |
| Store growth | 256 MiB memory + 1,000,000 table elements + bounded memory/table/instance counts | `--foreign-memory-cap <MiB>` | `0` opts out (no store limits); negative is rejected. |
| Blocking closures | 5 s per `clock.sleep` / SQL statement; existing net/proc timeouts | (fixed) | Bounds host wall-time a granted blocking closure can consume. |

The `--foreign-*` flags take effect on the `--wasm --run` path only (the
backend that sandboxes the child) and reject negative values (a typo
cannot silently disable a bound; `0` is the explicit opt-out). Absent,
the generous defaults apply: they let every legitimate crossing fixture
(which uses a single 64 KiB page and trivial CPU) run unaffected, while
bounding the pathological case. The defaults live in
`capa.runtime._foreign` as `DEFAULT_FOREIGN_FUEL` /
`DEFAULT_FOREIGN_MEMORY_CAP_BYTES` / `DEFAULT_FOREIGN_TABLE_ELEMENTS` /
`MAX_FOREIGN_BLOCKING_SECS`.

## Scope and limits

- **F2a: SCALAR crossing types** -- Int / Bool / Float (and Unit return).
- **F2b (this increment): the STRING crossing type**, marshalled through
  the canonical-ABI `(ptr, len)` + `$alloc` machinery above.
- **Aggregate crossing types are a further sub-phase.** A record
  (Struct), Sum, `List<T>`, `Map`, tuple, `Option<T>` or `Result<T, E>`
  crossing type needs a general, recursive, type-driven Capa-heap
  reader/writer on the HOST side of the parent boundary: the host must
  read a Capa aggregate out of the parent's linear memory (understanding
  its heap layout for every element/field type) into a Python value, and
  write the reverse. The existing canonical-ABI path only hand-codes a
  FIXED set of shapes (`option<string>`, `list<string>`,
  `result<string, io-error>`) for the WASI caps; there is no general
  marshaller. A foreign call using an aggregate crossing type is rejected
  up front with a clear error naming the aggregate kinds and the
  sub-phase; the boundary is still fully type-checked (`--check`) and
  recorded in the SBOM (`--manifest`).
- **Core `--wasm` path only.** The `--component` wrapping path does not
  yet carry `capa:foreign` imports.
- **Python backend: unsupported.** The Python backend cannot sandbox a
  foreign component, so a foreign call requires `--wasm`.
- **SBOM posture.** The composed SBOM downgrades a foreign call from TOP
  to BOUNDED {declared caps} ONLY under the `wasm-sandbox` enforcement
  posture (`--compose-sbom --wasm`), because the cap SET is host-enforced.
  The default / Python posture keeps it TOP (nothing enforces it there).
  This bounds the cap SET; composing WITHIN-cap host-granular attenuation
  across the boundary is feature #6.
