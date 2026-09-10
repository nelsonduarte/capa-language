# 14. Linearity (`consume`) and typestates

> **What this chapter covers.** Capa's two single-use disciplines: the
> `consume` qualifier (use-at-most-once, in the style of linear types,
> applied to capabilities and to `linear type` values) and typestates
> (a value carries its lifecycle state in the type, `Claim[Draft]`
> versus `Claim[Approved]`, and an illegal transition is a type error).
> It also covers the ownership rules for carriers (structs owning
> linear fields) and the single operand-place resolver behind the
> use-once rules. Every rule is demonstrated with a real, executed
> example.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10, `python -m capa` importing the checkout under specification.

Depends on: [10-capability-model.md](10-capability-model.md).

---

## 1. Two dual single-use disciplines

Capa has two related but distinct static flow checks, both in
[`capa/analyzer/_linear.py`](../capa/analyzer/_linear.py) (see the
module header):

- **`consume` (use-after-consume)**: a capability or a linear value
  passed to a `consume` parameter cannot be used again. It errors on
  the **use after it was consumed**. The state is `self._consumed`
  (the same set the capability discipline uses).
- **`linear type` (never-consumed)**: a value of a `linear type` must
  be consumed before it leaves scope. It errors on the value **dropped
  without being consumed** (the resource leak: a file never closed, a
  transaction never finished). The state is `self._live_linear`.

The two are duals: the first forbids using twice; the second forbids
using zero times. Together they give strict linear semantics (exactly
once) over the values that require it.

Branch merging differs for each (module header of `_linear.py`):
use-after-consume merges by **union** (consumed if any branch
consumes, the conservative rule), and never-consumed merges by
**intersection** over non-diverging arms (an obligation survives only
if it persists unconsumed on some reachable path). Section 4 runs both
sides.

## 2. The `consume` qualifier

A parameter marked `consume` takes ownership of the argument: after
the call, the caller can no longer use that capability or value. A
parameter without `consume` is a borrow (the caller keeps use).

Use-after-consume. `adopt` consumes `stdio`; the next line tries to
use it:

```capa
// uac.capa
fun adopt(consume stdio: Stdio)
    stdio.println("kept forever")

fun error_use_after_consume(stdio: Stdio)
    adopt(stdio)
    stdio.println("this should fail")

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check uac.capa
uac.capa:7:5: error: capability 'stdio' was consumed earlier and cannot be used again
   7 |     stdio.println("this should fail")
           ^

uac.capa: 1 error
```

The diagnostic comes from
[`capa/analyzer/_expressions.py`](../capa/analyzer/_expressions.py)
(use via `Ident`, line 1081; use via `FieldAccess`, line 1242). The
consumption is marked in
[`capa/analyzer/_discipline.py`](../capa/analyzer/_discipline.py) line
81 (`self._consumed.add(path)`), after the arguments are evaluated, so
the first occurrence (the argument of `adopt` itself) does not trigger.

The same rule catches re-passing to another function:

```capa
// repass.capa
fun adopt(consume stdio: Stdio)
    stdio.println("kept forever")

fun peek(stdio: Stdio)
    stdio.println("temporary")

fun error_repass(stdio: Stdio)
    adopt(stdio)
    peek(stdio)

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check repass.capa
repass.capa:10:10: error: capability 'stdio' was consumed earlier and cannot be used again
  10 |     peek(stdio)
                ^

repass.capa: 1 error
```

Dropping a `consume` parameter WITHOUT re-consuming it stays legal (it
is the documented terminal-owner semantics of `adopt`/`discard`): the
parameter is drop-exempt via `_drop_exempt_linear`
([`capa/analyzer/__init__.py`](../capa/analyzer/__init__.py) line 633),
with use-after-consume tracking still on.

## 3. Passing the same capability twice in one call

Aliasing inside a single call is rejected independently of the
cross-statement flow: a capability cannot appear in two argument
positions of the same call.

```capa
// twice.capa
fun sink(consume a: Stdio, consume b: Stdio)
    a.println("a")

fun main(stdio: Stdio)
    sink(stdio, stdio)
```

```
$ python -m capa --check twice.capa
twice.capa:2:28: error: capability parameter 'b' is declared but never used; prefix the name with '_' to silence this check
   2 | fun sink(consume a: Stdio, consume b: Stdio)
                                  ^

twice.capa:6:17: error: capability 'stdio' appears as argument 2 but was already used as argument 1 of the same call; capabilities cannot be aliased (each call uses each capability at most once)
   6 |     sink(stdio, stdio)
                       ^

twice.capa: 2 errors
```

The aliasing error is at
[`capa/analyzer/_discipline.py`](../capa/analyzer/_discipline.py) line
581. (The first error is orthogonal: `b` is declared but never used.)

## 4. Branch merging

Consuming in only one branch of an `if` poisons the capability for the
code after the `if` (the union merge):

```capa
// branch.capa
fun adopt(consume stdio: Stdio)
    stdio.println("kept forever")

fun peek(stdio: Stdio)
    stdio.println("temporary")

fun error_after_if(stdio: Stdio, cond: Bool)
    if cond
        adopt(stdio)
    peek(stdio)

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check branch.capa
branch.capa:11:10: error: capability 'stdio' was consumed earlier and cannot be used again
  11 |     peek(stdio)
                ^

branch.capa: 1 error
```

Consuming in **both** branches, with no use afterward, is valid:

```capa
// okbranch.capa
fun adopt(consume stdio: Stdio)
    stdio.println("kept")

fun ok_branch_consume(stdio: Stdio, cond: Bool)
    if cond
        adopt(stdio)
    else
        adopt(stdio)

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check okbranch.capa
okbranch.capa: ok (3 items, 11 expressions typed, 7 bindings)
```

(The complete worked example of these cases lives in
[`examples/consume.capa`](../examples/consume.capa).)

## 5. `linear type`: closing the resource-leak class

A `linear type Foo { ... }` produces values that **must be consumed**
before leaving scope: passed to a `consume` parameter (including a
`consume self` method, typically `close`), or returned (which
transfers the obligation to the caller). Dropping one is a compile
error ([`capa/analyzer/_linear.py`](../capa/analyzer/_linear.py)).

A resource constructed and never consumed:

```capa
// linear.capa
linear type File { fd: Int }

fun close(consume f: File)
    return

fun leak(fd: Int)
    let f = File { fd: fd }
    return

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check linear.capa
linear.capa:8:5: error: linear value 'f' is dropped without being consumed; a `linear type` value must be passed to a consuming function (e.g. a `consume self` method like `close`) or returned before it goes out of scope
   8 |     let f = File { fd: fd }
           ^

linear.capa: 1 error
```

The valid flow (consume with `close`) passes and runs identically on
both backends:

```capa
// linear_ok.capa
linear type File { fd: Int }

fun close(consume f: File)
    return

fun main(stdio: Stdio)
    let f = File { fd: 3 }
    close(f)
    stdio.println("closed")
```

```
$ python -m capa --run linear_ok.capa
closed
$ python -m capa --run --wasm linear_ok.capa
closed
```

## 6. Typestates: the state in the type

A `typestate` declares named states; a value carries its state in the
type (`Name[State]`) and is linear (must be consumed / transitioned).
Because the state lives in the type, the ordinary type checker plus
the linear discipline of section 5 enforce the protocol.

An approval protocol `Claim[Draft] -> Claim[Approved]`. Only a
`Claim[Approved]` can be paid:

```capa
// claim_ok.capa
typestate Claim { amount: Int }
    Draft
    Approved

fun approve(consume c: Claim[Draft]) -> Claim[Approved]
    return become(c, Approved)

fun pay(consume c: Claim[Approved], stdio: Stdio)
    stdio.println("paid ${c.amount}")

fun main(stdio: Stdio)
    let c = Claim[Draft] { amount: 100 }
    let a = approve(c)
    pay(a, stdio)
```

```
$ python -m capa --run claim_ok.capa
paid 100
$ python -m capa --run --wasm claim_ok.capa
paid 100
```

The two backends produce identical output.

## 7. An illegal transition is a type error

Paying a `Claim[Draft]` directly (without going through `approve`) is
a state mismatch, caught by the type checker because `Claim[Draft]`
and `Claim[Approved]` are distinct types:

```capa
// claim_bad.capa
typestate Claim { amount: Int }
    Draft
    Approved

fun pay(consume c: Claim[Approved], stdio: Stdio)
    stdio.println("paid ${c.amount}")

fun main(stdio: Stdio)
    let c = Claim[Draft] { amount: 100 }
    pay(c, stdio)
```

```
$ python -m capa --check claim_bad.capa
claim_bad.capa:11:9: error: call to 'pay': argument 1 expects Claim[Approved], got Claim[Draft]
  11 |     pay(c, stdio)
               ^

claim_bad.capa: 1 error
```

## 8. `become` consumes the previous state

`become(value, State)` (`_check_become`,
[`capa/analyzer/_expressions.py`](../capa/analyzer/_expressions.py)
line 1400) transitions a typestate value: it consumes the value in the
current state (the linear obligation moves to the result) and returns
the same value retyped at the new state. Because it consumes the old
value, using the old name after a `become` is use-after-consume.

Transitioning the same `Claim[Draft]` twice:

```capa
// claim_stale.capa
typestate Claim { amount: Int }
    Draft
    Approved

fun approve(consume c: Claim[Draft]) -> Claim[Approved]
    return become(c, Approved)

fun pay(consume c: Claim[Approved], stdio: Stdio)
    stdio.println("paid ${c.amount}")

fun main(stdio: Stdio)
    let c = Claim[Draft] { amount: 100 }
    let a = approve(c)
    let a2 = approve(c)
    pay(a, stdio)
    pay(a2, stdio)
```

```
$ python -m capa --check claim_stale.capa
claim_stale.capa:15:22: error: linear value 'c' was consumed earlier and cannot be used again
  15 |     let a2 = approve(c)
                            ^

claim_stale.capa: 1 error
```

`become` to a nonexistent state is rejected naming the real states,
and `become` on a non-typestate with `become expects a typestate
value`:

```
$ python -m capa --check become_bad.capa   # body: return become(c, Paid)
become_bad.capa:7:12: error: typestate 'Claim' has no state 'Paid' (states: Draft, Approved)
   7 |     return become(c, Paid)
                  ^
```

## 9. State-indexed methods

`impl Type[State]` declares methods callable only when the receiver is
in that state; a transition method can `consume self` and return the
value in a new state. A method name must be unique across all states
(Capa dispatches by name over the base type). A full protocol, run on
both backends:

```capa
// door.capa
typestate Door { name: String }
    Open
    Closed

impl Door[Open]
    fun shut(consume self) -> Door[Closed]
        return become(self, Closed)

impl Door[Closed]
    fun demolish(consume self) -> String
        return self.name

fun main(stdio: Stdio)
    let d = Door[Open] { name: "front" }
    let c = d.shut()
    stdio.println("demolished ${c.demolish()}")
```

```
$ python -m capa --run door.capa
demolished front
$ python -m capa --run --wasm door.capa
demolished front
```

Calling a method in the wrong state is rejected:

```capa
// door_bad.capa (main body)
    let d = Door[Open] { name: "front" }
    let s = d.demolish()
```

```
$ python -m capa --check door_bad.capa
door_bad.capa:16:13: error: method 'demolish' requires Door[Closed], but the receiver is Door[Open]
  16 |     let s = d.demolish()
                   ^

door_bad.capa: 1 error
```

## 10. Ownership hardening: consume-param reuse, carriers, one place resolver

Three further rules complete the single-use discipline. All are
analyzer-only and reject-only: a rejected program never reaches
codegen, and backend output for accepted programs is unaffected.

### 10.1 Reusing a `consume` parameter inside the body that receives it

A linear / typestate `consume` parameter is seeded OWNED into the same
`_live_linear` tracker as a `let` value, so reusing it inside its own
body falls into the single existing use-after-consume check (pinned by
`TestLinearConsumeParamReuse` and
`TestLinearConsumeParamDoubleFreeRuntime` in
[`tests/analyzer/test_linear_obligation.py`](../tests/analyzer/test_linear_obligation.py)):

```capa
// lin1.capa
linear type Handle { id: Int }

fun close(consume h: Handle) -> Unit
    return ()

fun spend(consume h: Handle) -> Unit
    close(h)
    close(h)

fun main(stdio: Stdio)
    stdio.println("start")
```

```
$ python -m capa --check lin1.capa
lin1.capa:9:11: error: linear value 'h' was consumed earlier and cannot be used again
   9 |     close(h)
                 ^

lin1.capa: 1 error
```

### 10.2 Carriers: a struct owning a linear field is must-consume

A struct that transitively OWNS a linear / typestate field (a CARRIER)
is itself a must-consume value: it has to be consumed, transitioned,
returned, or have its linear fields moved out before leaving scope.
The must-consume predicate is single-sourced in
[`capa/_owned_obligation.py`](../capa/_owned_obligation.py), consulted
by both the analyzer
([`capa/analyzer/_linear.py`](../capa/analyzer/_linear.py)) and the
manifest ([`capa/manifest/_funrec.py`](../capa/manifest/_funrec.py)).

Packing then reusing (the obligation moves into the carrier; the old
name is poisoned):

```capa
// carrier.capa (main body)
    let h = Handle { id: 1 }
    let b = Box { h: h }
    close(h)
    sink(b)
```

```
$ python -m capa --check carrier.capa
carrier.capa:15:11: error: linear value 'h' was consumed earlier and cannot be used again
  15 |     close(h)
                 ^
```

Dropping a carrier without consuming it (the leak):

```
$ python -m capa --check carrier_leak.capa
carrier_leak.capa:11:5: error: linear value 'b' is dropped without being consumed; a `linear type` value must be passed to a consuming function (e.g. a `consume self` method like `close`) or returned before it goes out of scope
```

Deliberate coupling with the manifest (measured via `--manifest`): a
factory `fun mk() -> Box` reports `produces_linear: true`, and
`fun sink(consume b: Box)` reports the parameter with
`is_linear: true`, `consuming: true` and
`linear_obligations.consumes: ["b"]`, so linear obligations of carrier
factories appear on the SBOM obligation surface (see
[29-capability-manifest.md](29-capability-manifest.md)).

### 10.3 One operand-place resolver behind every use-once rule

A use-once rule must RESOLVE its operand to a place before deciding.
Every deciding position (a `match` binder, a struct pattern, a
selection expression that returns an existing place, a projected call
receiver, whole-value assignment, generic-return aliasing) consults a
single operand-place resolver
([`capa/analyzer/_e3.py`](../capa/analyzer/_e3.py) and `_path_of` in
[`capa/analyzer/_linear.py`](../capa/analyzer/_linear.py)), so an
aliased spelling of a double-free is rejected like the direct
spelling. Pinned by
[`tests/analyzer/test_linear_alias_introduction.py`](../tests/analyzer/test_linear_alias_introduction.py)
and
[`tests/analyzer/test_single_use_resolution_guard.py`](../tests/analyzer/test_single_use_resolution_guard.py)
(a guard that fails when a rule decides its operand by syntax).

Four aliased spellings, each rejected at `8e2c609`:

A `match` binder aliasing an existing place:

```capa
// e3_binder.capa (main body)
    let a = open()
    let t = match 0
        _ -> a
    close(t)
    close(a)
```

```
$ python -m capa --check e3_binder.capa
e3_binder.capa:15:11: error: linear value 'a' was consumed earlier and cannot be used again
  15 |     close(a)
                 ^
```

Whole-value aliasing through assignment (`var t = open(); close(t);
t = s; close(t); close(s)`):

```
$ python -m capa --check e3_assign.capa
e3_assign.capa:16:11: error: linear value 's' was consumed earlier and cannot be used again
  16 |     close(s)
                 ^
```

Aliasing through a generic identity return (`let b = idc(a)` with
`fun idc<T>(x: T) -> T`):

```
$ python -m capa --check e3_generic.capa
e3_generic.capa:17:11: error: linear value 'a' was consumed earlier and cannot be used again
  17 |     close(a)
                 ^
```

Destructuring a linear carrier and then touching the moved field
(`let Holder { c, tag } = h; close(c); close(h.c)`):

```
$ python -m capa --check e3_destructure.capa
e3_destructure.capa:13:11: error: linear value 'h.c' was consumed earlier and cannot be used again
  13 |     close(h.c)
                 ^
```

## 11. What it guarantees

- **Guarantees** (static, every program that passes `--check`): a
  consumed capability or linear value is not reused; one capability is
  not aliased within a call; a `linear type` / typestate value is not
  dropped without consumption; a carrier owning a linear field is
  itself must-consume; a typestate transition only occurs between
  compatible states, and the value in the old state is consumed by the
  transition.
- JUDGEMENT. The guarantee is one of ownership discipline and protocol
  order, not of information-flow absence: a typestate value can hold a
  `@secret` field, and that dimension is governed by the IFC layer
  ([15-ifc-model-and-labels.md](15-ifc-model-and-labels.md)), not by
  this chapter.
- Consuming a capability or linear value **captured** from an
  enclosing scope inside a lambda is rejected (a closure may be
  invoked many times, but the value can be consumed only once; see the
  `capconsume` transcript in
  [08-functions-closures-modules.md](08-functions-closures-modules.md)).

---

## Links

- [10-capability-model.md](10-capability-model.md): the capability
  discipline that `consume` is the dual of.
- [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md): the
  orthogonal information-flow layer over values (including typestate
  fields).
- [07-pattern-matching.md](07-pattern-matching.md): destructuring of
  structs and typestates.
- [29-capability-manifest.md](29-capability-manifest.md): how linear
  obligations surface in the manifest.
