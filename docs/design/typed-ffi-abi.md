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

## Scope and limits

- **F2a (this increment): SCALAR crossing types only** -- Int / Bool /
  Float (and Unit return). A String or aggregate crossing type (Struct /
  Sum / List / Map / tuple / Option / Result) needs the linear-memory
  canonical ABI (indirect return + `$alloc`) on the parent-import leg;
  that is **F2b**. A foreign call using one is rejected up front with a
  clear "feature #4 F2b" error; the boundary is still fully type-checked
  (`--check`) and recorded in the SBOM (`--manifest`).
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
