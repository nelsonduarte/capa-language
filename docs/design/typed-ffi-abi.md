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
