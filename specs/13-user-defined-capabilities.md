# 13. User-defined capabilities

> **What this chapter covers.** Building a higher-level capability out
> of the built-ins: the `capability` declaration, the implementor
> struct that wraps built-in authority in a field (the "cap-bearing
> struct" relaxation), and the factory that produces it. The invariant
> that keeps the authority chain readable in the types (an implementor
> MUST be given the built-in authority it wraps), the rules that
> prevent smuggling (`Unsafe` never; no capability containers;
> built-ins still cannot be returned), and how these capabilities
> appear in the manifest. The built-ins are in
> [11-builtin-capabilities.md](11-builtin-capabilities.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification. The example program is
[`examples/user_capabilities.capa`](../examples/user_capabilities.capa),
copied to the working folder as `usercap.capa`.

Depends on: [11-builtin-capabilities.md](11-builtin-capabilities.md),
[06-generics-and-traits.md](06-generics-and-traits.md).

---

## 1. What a user capability is

The set of built-in capabilities is fixed (ten,
[11-builtin-capabilities.md](11-builtin-capabilities.md) section 1).
But a program rarely wants to expose raw `Net` to a subsystem; it
wants to expose "the authority to send an email", "the authority to
write the audit log". A **user-defined capability** is exactly that: a
higher-level authority type, declared with the `capability` keyword,
wrapping one or more built-ins.

`capability X` declares a type the discipline treats as a capability
(it reaches the analyzer as `SymbolKind.CAPABILITY`, identical to a
built-in: no aliasing, no storage in plain bindings, and so on), while
`trait X` arrives as `SymbolKind.TRAIT`; method dispatch and `impl`
checking are the same in both cases
([`capa/analyzer/_declarations.py`](../capa/analyzer/_declarations.py)).
The difference is semantic: a `capability` is authority, a `trait` is
an interface.

## 2. The implementor pattern: a complete example

[`examples/user_capabilities.capa`](../examples/user_capabilities.capa)
declares the capability `SendEmail`, implements it with the struct
`SmtpMailer` (which wraps `Net`), and provides a factory that consumes
`Net` and produces the `SmtpMailer`:

```capa
// usercap.capa  (== examples/user_capabilities.capa)
capability SendEmail
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>

type SmtpMailer {
    server: String,
    net: Net
}

impl SendEmail for SmtpMailer
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>
        return Ok(())

fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer
    return SmtpMailer {
        server: server,
        net: net.restrict_to(server)
    }

fun send_welcome(mailer: SendEmail, to: String) -> Result<Unit, IoError>
    return mailer.send(to, "Welcome", "Hello and welcome to Capa")

fun main(stdio: Stdio, net: Net)
    let mailer = make_smtp_mailer(net, "smtp.example.com")
    let result = send_welcome(mailer, "alice@example.com")
    match result
        Ok(_) -> stdio.println("sent welcome email (stub)")
        Err(e) -> stdio.eprintln("failed: ${e}")
```

```
$ python -m capa --check usercap.capa
usercap.capa: ok (6 items, 27 expressions typed, 14 bindings)
$ python -m capa --run usercap.capa
sent welcome email (stub)
$ python -m capa --run --wasm usercap.capa
sent welcome email (stub)
```

The two backends produce identical output. (`send` is a stub in v1:
the example exercises the discipline, not the SMTP protocol. A real
implementation would call `self.net.get(...)` on the
already-restricted `Net`.)

The four links of the chain:

1. `main` receives `Net` from the runtime.
2. `make_smtp_mailer` takes `Net`, attenuates it
   (`net.restrict_to(server)`) and wraps it in an `SmtpMailer`,
   returning the high-level capability.
3. `send_welcome` receives only `SendEmail`. It never sees `Net`; it
   can only call `send`.
4. To obtain an `SmtpMailer` you need `Net` (the factory requires
   it), so the chain `main -> Net -> SmtpMailer -> SendEmail` is
   visible in the signatures end to end.

## 3. The invariant: an implementor must be given the authority it wraps

By default a struct **cannot** have a capability-typed field (the
structural "no capability as struct field" rule). This prevents an
anonymous struct from smuggling `Net` inside a data value. The
exception, and it is the heart of the pattern, is the **cap-bearing
relaxation**: a struct that **implements a user capability** may hold
built-in capability fields. It is because `SmtpMailer` implements
`SendEmail` that it could declare `net: Net`.

The effect is that the built-in authority a user capability grants is
never invisible: to construct it you must supply the authority it
wraps, and that passing shows up in the factory's signature.

A struct declaring `net: Net` without implementing any user
capability is refused:

```capa
// plain_field.capa
type Holder {
    net: Net
}

fun main(net: Net, stdio: Stdio)
    let h = Holder { net: net }
    stdio.println("built")
```

```
$ python -m capa --check plain_field.capa
plain_field.capa:3:5: error: capability 'Net' cannot appear in struct field 'net'; capabilities only flow through function parameters
   3 |     net: Net
           ^

plain_field.capa: 1 error
```

## 4. The limits of the relaxation (what stays forbidden)

The cap-bearing relaxation is narrow on purpose. Three limits close
the smuggling routes:

**(a) `Unsafe` never**, not even in a cap-bearing struct. `Unsafe` is
the FFI hatch, not an attenuable built-in; wrapping it would hide the
exit to arbitrary code.

```capa
// unsafe_field.capa (excerpt)
type Wrap {
    u: Unsafe
}

impl Danger for Wrap
    ...
```

```
$ python -m capa --check unsafe_field.capa
unsafe_field.capa:6:5: error: capability 'Unsafe' cannot appear in struct field 'u', even in a capability-bearing struct; Unsafe is the FFI escape hatch, not an attenuable built-in capability
   6 |     u: Unsafe
           ^

unsafe_field.capa: 1 error
```

**(b) No capability containers.** The relaxation admits a field with a
BARE capability (`net: Net`), not a container (`caps: List<Net>`),
which would hide authority like any other container.

**(c) Built-ins still cannot be returned.** A factory may return a
BARE user capability (it is an ordinary Capa value; only built-ins
are forbidden in return position), but not a built-in, and not a user
capability wrapped in a container (`-> List<Logger>`). That is why
`make_smtp_mailer -> SmtpMailer` is accepted while
`grab(fs: Fs) -> Fs` is not
([10-capability-model.md](10-capability-model.md) section 3).

## 5. How they appear in the manifest

The manifest recognizes user capabilities as first-class citizens and
keeps the authority chain explicit: a function that declares only
`SendEmail` shows `Net` in its transitively reachable capabilities,
because the implementor wraps it.

Measured excerpts of `python -m capa --manifest usercap.capa`:

```
"user_defined_capabilities": [
  {
    "name": "SendEmail",
    "methods": [ "send" ],
    "implementors": [ "SmtpMailer" ],
    "doc": null
  }
]
```

```
"name": "send_welcome",
"declared_capabilities": [ "SendEmail" ],
"transitively_reachable_capabilities": [ "Net", "SendEmail" ],
"provably_excluded_capabilities": [
  "Clock", "Db", "Env", "Fs", "Proc", "Random", "Serve", "Stdio", "Unsafe"
],
"authority_provable_from_types": true
```

```
"name": "make_smtp_mailer",
"declared_capabilities": [ "Net" ],
"transitively_reachable_capabilities": [ "Net", "SendEmail" ],
"provably_excluded_capabilities": [
  "Clock", "Db", "Env", "Fs", "Proc", "Random", "Serve", "Stdio", "Unsafe"
],
"authority_provable_from_types": true
```

`send_welcome` declares only `SendEmail`, but the manifest honestly
reports that it reaches `Net` transitively (via the implementor). This
is the property that makes a user capability auditable: the high
level does not hide the underlying built-in authority; it overlays a
name on it. (Authority a body MINTS through a factory is also
unioned into the reachable set; measured in
[29-capability-manifest.md](29-capability-manifest.md) section 2.1.)

## 6. They do not cross a component boundary

A user capability is a Capa value (a struct), not a host authority. It
therefore **cannot be passed to a foreign Wasm component**: only the
host built-ins (`Net`, `Fs`, `Env`, ...) are the granted authority the
sandbox physically confines. A foreign-component method signature
declaring a user-capability parameter is refused, and a cap-bearing
struct (carrying a built-in in a field) cannot cross as a value
either, so the built-in cannot be smuggled
([`capa/analyzer/_declarations.py`](../capa/analyzer/_declarations.py)).
The foreign boundary detail is in
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md).

---

## Links

- [10-capability-model.md](10-capability-model.md): the propagation
  discipline the user capability extends.
- [11-builtin-capabilities.md](11-builtin-capabilities.md): the
  built-ins an implementor wraps.
- [12-attenuation.md](12-attenuation.md): the attenuation
  (`net.restrict_to`) the factory applies before wrapping.
- [06-generics-and-traits.md](06-generics-and-traits.md):
  `trait`/`impl`, the machinery `capability`/`impl` reuses.
- [29-capability-manifest.md](29-capability-manifest.md): the
  `user_defined_capabilities` field and transitive reachability.
