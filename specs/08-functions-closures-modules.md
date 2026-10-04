# 08. Functions, closures, const, modules and visibility

> **What this chapter covers.** Function declaration and the seven real
> attributes; parameters (including capability parameters and the
> `consume`/`borrow` qualifiers); return types and the
> return-on-every-path rule; closures/lambdas and capture; the module
> system (`import`, `pub`/private visibility, and the unqualified,
> alias-qualified and selective call forms); the reserved built-in
> names (section 8). Anchored in the real
> parser, analyzer and loader, with examples executed on both backends.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10, `python -m capa` importing the checkout under specification.
Primary sources: [`capa/parser/_items.py`](../capa/parser/_items.py)
(function declaration, imports, parameters),
[`capa/parser/_statements.py`](../capa/parser/_statements.py) (lambdas),
[`capa/analyzer/_items.py`](../capa/analyzer/_items.py) (attributes,
capability-use rule, return rule),
[`capa/_borrow.py`](../capa/_borrow.py) (the `borrow` discipline), and
[`capa/loader.py`](../capa/loader.py) (module linking and visibility).

Depends on: [04-grammar.md](04-grammar.md).

---

## 1. Function declaration

The full form (grammar in [04-grammar.md](04-grammar.md) section 3;
parser `_parse_fun_decl` in
[`capa/parser/_items.py`](../capa/parser/_items.py)):

```ebnf
function_decl = { doc_comment } { attribute NEWLINE } [ "pub" ] "fun" IDENT
                [ generic_params ] "(" [ param_list ] ")" [ "->" type ] block
```

The header opens on a `NEWLINE` followed by `INDENT` (no `:`, see
[03-lexis-and-layout.md](03-lexis-and-layout.md)). The return type is
optional; when omitted, the function returns `Unit` (see section 4).

An authority-threading function (`stdio` passed explicitly), run on
both backends:

```capa
// thread.capa
fun greet(stdio: Stdio, name: String)
    stdio.println("Hello, ${name}")

fun main(stdio: Stdio)
    greet(stdio, "Ana")
    greet(stdio, "Rui")
```

```
$ python -m capa --run thread.capa
Hello, Ana
Hello, Rui
$ python -m capa --run --wasm thread.capa
Hello, Ana
Hello, Rui
```

The two backends produce identical output.

## 2. Attributes: the seven real ones

The grammar accepts any `@name(key: "value", ...)` before a `fun`, but
the analyzer restricts the catalogue to **seven**, in the
`_ATTRIBUTE_SCHEMA` schema
([`capa/analyzer/_items.py`](../capa/analyzer/_items.py) line 43).
Argument values must be string literals (guaranteed by the parser), so
the metadata is statically inspectable.

| Attribute | Allowed keys | Nature |
|---|---|---|
| `security` | `cve`, `cwe`, `severity`, `fixed_in`, `description` | supply-chain metadata |
| `deprecated` | `reason`, `since`, `use`, `removed_in` | documentation metadata |
| `audited` | `date`, `by`, `scope`, `notes` | audit metadata |
| `vex` | `cve`, `status`, `justification`, `detail`, `first_issued` | VEX metadata |
| `strict_ifc` | (none) | behavioural (detected flows become hard errors) |
| `constant_time` | (none) | behavioural (CWE-208) |
| `export` | (none) | behavioural (Wasm Component Model export surface) |

The first four are declarative (they feed `--manifest`, `--vex` and
audit tooling, see
[29-capability-manifest.md](29-capability-manifest.md)); the last three
are **behavioural** and are written without arguments (`@strict_ifc()`,
`@constant_time()`, `@export()`). `@strict_ifc` makes every
detected flow in the function a hard error and turns on the
implicit-flow checks (see
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md));
`@constant_time` rejects control decisions or indexing that depend on a
`@secret`; `@export` marks a top-level function for the Wasm Component
Model export surface (only valid on a top-level function, not on an
impl method, and not on `main`, which is exported unconditionally; see
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)).

The `@secret`/`@public` labels and the `declassify` operation are
**not** attributes: they are language constructs (see
[15-ifc-model-and-labels.md](15-ifc-model-and-labels.md)). The parser
disambiguates `@secret`/`@public` (a type label, not followed by `(` in
type position) from `@name(...)` (an attribute before a declaration) by
position.

Valid metadata attributes pass `--check`:

```capa
// attrs.capa
@deprecated(reason: "use add2", since: "1.2.0")
@audited(date: "2026-08-01", by: "team")
pub fun add(a: Int, b: Int) -> Int
    return a + b

fun main(stdio: Stdio)
    stdio.println("${add(1, 2)}")
```

```
$ python -m capa --check attrs.capa
attrs.capa: ok (2 items, 9 expressions typed, 4 bindings)
```

An attribute outside the catalogue is rejected, listing the known ones:

```capa
// badattr.capa
@inline()
fun f() -> Int
    return 1

fun main(stdio: Stdio)
    stdio.println("${f()}")
```

```
$ python -m capa --check badattr.capa
badattr.capa:2:1: error: unknown attribute '@inline'; known attributes are: audited, constant_time, deprecated, export, security, strict_ifc, vex
   2 | @inline()
       ^

badattr.capa: 1 error
```

An unknown key (or any key on `strict_ifc`, whose allowed set is empty)
is rejected:

```capa
// sifc_arg.capa
@strict_ifc(level: "high")
fun f() -> Int
    return 1

fun main(stdio: Stdio)
    stdio.println("${f()}")
```

```
$ python -m capa --check sifc_arg.capa
sifc_arg.capa:2:1: error: unknown key 'level' in '@strict_ifc'; allowed keys are: 
   2 | @strict_ifc(level: "high")
       ^

sifc_arg.capa: 1 error
```

Validation runs in `_check_function_attributes`
([`capa/analyzer/_items.py`](../capa/analyzer/_items.py) line 105),
which also rejects a repeated attribute on the same function and a
repeated key inside the same attribute. Attributes are valid only on
`fun`: their presence on `const`/`type`/`trait`/`capability`/`import`
is a parse error (`_parse_item` in
[`capa/parser/_items.py`](../capa/parser/_items.py)).

## 3. Parameters

```ebnf
param = [ "consume" ] [ "borrow" ] ( IDENT ":" type | "self" )
```

Parser `_parse_param` ([`capa/parser/_items.py`](../capa/parser/_items.py)
line 810): `consume` is read before the special `self` case (to allow
`consume self`); `borrow` follows it. Both qualifiers are restrictions
enforced by the **analyzer**, not the parser.

### 3.1 Capability parameters

A parameter whose type is a built-in capability (`Stdio`, `Fs`, `Net`,
...) is one way a built-in capability can reach a function; a field of
a struct that implements a user-defined capability and a closure that
captured one (section 5.1) are two others. There is no global
capability value (see
[10-capability-model.md](10-capability-model.md)). The
analyzer requires a declared capability parameter to be **used**;
otherwise it is an error (prefixing with `_` silences it). The rule is
in [`capa/analyzer/_items.py`](../capa/analyzer/_items.py) (diagnostic
at line 574).

A declared and unused capability parameter:

```capa
// unused.capa
fun main(stdio: Stdio, fs: Fs)
    stdio.println("hi")
```

```
$ python -m capa --check unused.capa
unused.capa:2:24: error: capability parameter 'fs' is declared but never used; prefix the name with '_' to silence this check
   2 | fun main(stdio: Stdio, fs: Fs)
                              ^

unused.capa: 1 error
```

### 3.2 `consume`: linear ownership

`consume` marks the parameter as taken by ownership (linearity, detail
in [14-linearity-consume-typestates.md](14-linearity-consume-typestates.md)).
A `linear type` value passed to a `consume` function cannot be used
again.

Correct use, and use-after-consume, the second rejected:

```capa
// lin.capa
linear type Ticket { id: Int }

fun redeem(consume t: Ticket) -> Int
    return t.id

fun main(stdio: Stdio)
    let t = Ticket { id: 42 }
    let n = redeem(t)
    stdio.println("redeemed ${n}")
```

```
$ python -m capa --run lin.capa
redeemed 42
$ python -m capa --run --wasm lin.capa
redeemed 42
```

```
$ python -m capa --check lin_bad.capa   # body: let a = redeem(t); let b = redeem(t)
lin_bad.capa:10:20: error: linear value 't' was consumed earlier and cannot be used again
  10 |     let b = redeem(t)
                          ^
```

### 3.3 `borrow`: invoke-only function-typed parameter

`borrow` is valid only on a **function-typed** parameter
(`Fun(...) -> ...`). It marks it invoke-only: the body may call it
(`f(...)`) but not store it, return it, alias it, pass it to another
function (except intra-module forwarding into another `borrow`
position), or capture it in a lambda. The property is checked locally
and syntactically, and fails closed ([`capa/_borrow.py`](../capa/_borrow.py),
module docstring and `borrow_escapes` at line 88). The value of the
discipline: a higher-order function that only invokes its callback does
not have to charge the callback's authority against its own capability
ceiling (the authority was already accounted for where the closure was
created), and the product SBOM still sees all the authority the handler
exercises.

Valid invoke-only use, on both backends:

```capa
// borrow_ok.capa
fun each(xs: List<Int>, borrow f: Fun(Int) -> Int) -> Int
    var total = 0
    for x in xs
        total += f(x)
    return total

fun main(stdio: Stdio)
    stdio.println("${each([1, 2, 3], fun (n) => n + 1)}")
```

```
$ python -m capa --check borrow_ok.capa
borrow_ok.capa: ok (2 items, 18 expressions typed, 8 bindings)
$ python -m capa --run borrow_ok.capa
9
$ python -m capa --run --wasm borrow_ok.capa
9
```

An escape (returning the callback) is rejected:

```capa
// borrow_bad.capa
fun keep(borrow f: Fun(Int) -> Int) -> Fun(Int) -> Int
    return f
```

```
$ python -m capa --check borrow_bad.capa
borrow_bad.capa:3:12: error: borrow parameter 'f' may only be invoked (called as `f(...)`); it escapes here. A borrow function must not be stored, returned, aliased, passed to another function, or captured by a lambda.
   3 |     return f
                  ^

borrow_bad.capa: 1 error
```

`borrow` on a non-function-typed parameter is rejected
(`is_fun_typed_param`, [`capa/_borrow.py`](../capa/_borrow.py) line 77):

```
$ python -m capa --check borrow_nonfun.capa   # fun f(borrow x: Int) -> Int
borrow_nonfun.capa:2:7: error: borrow applies only to a function-typed parameter (a `Fun(...) -> ...` type); parameter 'x' is not one
   2 | fun f(borrow x: Int) -> Int
             ^
```

## 4. Return type and return-on-every-path

There is no implicit return of a block's last expression (unlike
Rust/OCaml). A function with a declared return type requires **every
path** to end in `return`; otherwise it is an error (the function would
fall through and return `None` at runtime). Rule in
[`capa/analyzer/_items.py`](../capa/analyzer/_items.py) (diagnostic at
line 456).

A loose tail expression is not a return:

```capa
// impret.capa
fun add(a: Int, b: Int) -> Int
    a + b
```

```
$ python -m capa --check impret.capa
impret.capa:2:5: error: function 'add' declares return type but not every path ends in `return`; the function will fall through and return None at runtime
   2 | fun add(a: Int, b: Int) -> Int
           ^

impret.capa: 1 error
```

The consequence for the reader: `if`/`while`/`for` are statements, not
expressions; a conditional value is written with the ternary
`if c then a else b` or with `match` (see
[09-expressions-and-control.md](09-expressions-and-control.md)).

## 5. Closures and lambdas

A lambda starts with `fun`, has parameters (the type annotation can be
omitted when inferable from context), and uses `=>` for the body (an
expression, or an indented block). Parser `_parse_lambda_expr`
([`capa/parser/_statements.py`](../capa/parser/_statements.py) line 152;
`=>` is `FAT_ARROW`, line 184).

A closure capturing a variable, an inferred lambda passed to `map`, and
a higher-order function, all on both backends:

```capa
// clos.capa
fun apply_twice(f: Fun(Int) -> Int, x: Int) -> Int
    return f(f(x))

fun main(stdio: Stdio)
    let base = 10
    let add_base = fun (n: Int) => n + base
    stdio.println("add_base(5) = ${add_base(5)}")
    stdio.println("twice = ${apply_twice(add_base, 1)}")
    let xs = [1, 2, 3, 4]
    let sum_doubled = xs.map(fun (x) => x * 2).fold(0, fun (acc, x) => acc + x)
    stdio.println("sum_doubled = ${sum_doubled}")
```

```
$ python -m capa --run clos.capa
add_base(5) = 15
twice = 21
sum_doubled = 20
$ python -m capa --run --wasm clos.capa
add_base(5) = 15
twice = 21
sum_doubled = 20
```

The two backends produce identical output. Note that the `map` lambda
has its parameter type inferred (`fun (x) => x * 2`), while `add_base`
annotates it (`fun (n: Int) => ...`).

### 5.1 Capability capture: borrowed, not consumable

Capabilities captured by a closure are **borrowed**. A closure can
capture a capability from the enclosing scope and exercise it when
invoked, but the analyzer rejects `consume` on a **captured** value (a
closure can be invoked many times; a `linear type` can be consumed only
once).

Capturing `Stdio` in a closure invoked in a loop (Python backend):

```capa
// capcap.capa
fun run_each(items: List<String>, action: Fun(String) -> Unit)
    for it in items
        action(it)

fun main(stdio: Stdio)
    let names = ["Ana", "Rui", "Zed"]
    run_each(names, fun (n) => stdio.println("hi ${n}"))
```

```
$ python -m capa --run capcap.capa
hi Ana
hi Rui
hi Zed
```

Backend scope (fail-loud). The same program is **refused** by the Wasm
backend: a lambda whose return type is `Unit` is not supported by the
Wasm closure lowering, and the refusal names the workaround:

```
$ python -m capa --run --wasm capcap.capa
capa: --wasm: lambda return type "UnitType(pos=Pos(line=0, col=0, offset=0, filename=''), label=None)" not supported by the Wasm closure lowering. Workaround: use the Python backend, or refactor the lambda body to return a scalar. Original: Capa type "UnitType(pos=Pos(line=0, col=0, offset=0, filename=''), label=None)" has no Wasm encoding yet
```

A lambda returning a scalar (the `clos.capa` case above) crosses both
backends; the refusal is specific to closures returning `Unit`. See
[24-backend-parity.md](24-backend-parity.md).

Consuming a capture inside a lambda is rejected:

```capa
// capconsume.capa
linear type Ticket { id: Int }

fun redeem(consume t: Ticket) -> Int
    return t.id

fun main(stdio: Stdio)
    let t = Ticket { id: 1 }
    let f = fun () => redeem(t)
    stdio.println("${f()}")
```

```
$ python -m capa --check capconsume.capa
capconsume.capa:9:30: error: cannot consume linear value 't' captured from enclosing scope; closures may be invoked multiple times, but a `linear type` / typestate value can only be consumed once
   9 |     let f = fun () => redeem(t)
                                    ^

capconsume.capa:8:5: error: linear value 't' is dropped without being consumed; a `linear type` value must be passed to a consuming function (e.g. a `consume self` method like `close`) or returned before it goes out of scope
   8 |     let t = Ticket { id: 1 }
           ^

capconsume.capa: 2 errors
```

## 6. Top-level constants

```ebnf
const_decl = [ "pub" ] "const" IDENT ":" type "=" expression NEWLINE
```

Evaluated at compile time; the expression is a const subset (no
function calls, no mutation, no capability-dependent operations). Type
checking and the propagation of the `@secret`/`@public` label to the
global symbol are in `_check_const`
([`capa/analyzer/_items.py`](../capa/analyzer/_items.py)). `pub`
exports the const to importing modules (section 7). A const may not
take a reserved built-in name (section 8).

## 7. Modules, `import` and visibility

Source: parser `_parse_import`
([`capa/parser/_items.py`](../capa/parser/_items.py) line 259) and the
loader [`capa/loader.py`](../capa/loader.py). `import foo.bar` resolves
to a Capa file; `import mathlib` (a single component) resolves
`mathlib.capa` in the importer's directory (the full resolution order,
including declared dependencies and `CAPA_PATH`, is in
[`capa/loader.py`](../capa/loader.py)).

The loader links the imported modules into a single AST. Visibility is
enforced by **per-module name mangling**: every non-`pub` item of an
imported module is renamed with a fresh prefix, leaving the merged
global scope; `pub` items keep their original name. A call to another
module's private function hits a dedicated diagnostic.

The imported module used in the examples:

```capa
// mathlib.capa
pub const PI: Float = 3.14159

pub fun add(a: Int, b: Int) -> Int
    return a + b

fun secret_helper(x: Int) -> Int
    return x * 2

pub fun double(x: Int) -> Int
    return secret_helper(x)
```

### 7.1 Unqualified import

`import mathlib` brings all `pub` items into the importer's scope under
their original names. On both backends:

```capa
// main_unqual.capa
import mathlib

fun main(stdio: Stdio)
    stdio.println("add = ${add(2, 3)}")
    stdio.println("double = ${double(5)}")
    stdio.println("PI = ${PI}")
```

```
$ python -m capa --run main_unqual.capa
add = 5
double = 10
PI = 3.14159
$ python -m capa --run --wasm main_unqual.capa
add = 5
double = 10
PI = 3.14159
```

`double` internally calls `secret_helper` (private), which is
legitimate: privacy only blocks access **from outside** the module. The
two backends produce identical output.

### 7.2 A private item is not reachable from outside

Calling the private function from the importer:

```capa
// main_priv.capa
import mathlib

fun main(stdio: Stdio)
    stdio.println("${secret_helper(3)}")
```

```
$ python -m capa --check main_priv.capa
main_priv.capa:5:22: error: undefined name 'secret_helper' (private to module 'mathlib'; mark it 'pub' to expose)
   5 |     stdio.println("${secret_helper(3)}")
                            ^

main_priv.capa: 1 error
```

### 7.3 Alias-qualified import

`import mathlib as m` registers `m` as an alias; a call `m.add(...)` is
rewritten by the loader into the unqualified call `add(...)`
([`capa/loader.py`](../capa/loader.py), the rewriter of
`MethodCall(Ident(alias), method, args)`).

Qualified calls on both backends:

```capa
// main_qual2.capa
import mathlib as m

fun main(stdio: Stdio)
    stdio.println("add = ${m.add(10, 20)}")
    stdio.println("double = ${m.double(21)}")
```

```
$ python -m capa --run main_qual2.capa
add = 30
double = 42
$ python -m capa --run --wasm main_qual2.capa
add = 30
double = 42
```

Scope of the alias form. The rewriter covers only the **call** shape
`alias.fn(...)`. A field/const access through the alias (`m.PI`, with
no `(...)`) is **not** rewritten and lands on an "undefined name":

```capa
// main_qual.capa
import mathlib as m

fun main(stdio: Stdio)
    stdio.println("add = ${m.add(10, 20)}")
    stdio.println("PI = ${m.PI}")
```

```
$ python -m capa --check main_qual.capa
main_qual.capa:6:27: error: undefined name 'm'
   6 |     stdio.println("PI = ${m.PI}")
                                 ^

main_qual.capa: 1 error
```

To reach a const of an aliased module, use it unqualified (`PI`) or via
a selective import (section 7.4).

### 7.4 Selective import

`import mathlib (add as plus, PI)` brings only the listed `pub`
symbols, each optionally renamed with `as`; the module's other `pub`
items stay out of scope. The parser requires at least one selector
(`_parse_import_selectors`,
[`capa/parser/_items.py`](../capa/parser/_items.py) line 278).

A selective import with a rename, on both backends:

```capa
// main_sel.capa
import mathlib (add as plus, PI)

fun main(stdio: Stdio)
    stdio.println("plus = ${plus(7, 8)}")
    stdio.println("PI = ${PI}")
```

```
$ python -m capa --run main_sel.capa
plus = 15
PI = 3.14159
$ python -m capa --run --wasm main_sel.capa
plus = 15
PI = 3.14159
```

The two backends produce identical output.

A selector's `as` alias is a declaration of the importing file and is
judged by the reserved-name rule of section 8 at the alias itself.

### 7.5 The capability discipline crosses modules

Authority flow does not change at a module boundary: a function in
another module that receives `Fs` still needs to receive it by
parameter from a holder of `Fs`. An import brings functions and types,
never a capability value (see
[10-capability-model.md](10-capability-model.md)). `borrow`-ness is
**not** carried across the module boundary (it is not part of the
exported interface), so forwarding a `borrow` parameter into a callee
from another module fails closed ([`capa/_borrow.py`](../capa/_borrow.py),
FORWARDING section of the module docstring).

## 8. Reserved built-in names

The transcripts in this section were run on 2026-10-04, later than the
commit named at the top of this chapter, `python -m capa` importing a
`git archive` extraction of the tree that carries the rule.

### 8.1 The rule

The names of the built-in globals are reserved. The reserved set has
one source: whatever `register_builtins`
([`capa/builtins.py`](../capa/builtins.py)) installs in the global
scope. `builtin_global_names`
([`capa/_builtin_identity.py`](../capa/_builtin_identity.py)) obtains
it by RUNNING that registration against a recording scope, so the set
cannot drift from what the analyzer binds. It holds the built-in free
functions (the `FREE_FUNCTIONS` table, including two
compiler-internal ones whose names start with `_capa_`), the primitive
types, the built-in capabilities, the other built-in types, `JsonValue`
and the built-in variants. To print it:

```
python -c "from capa._builtin_identity import builtin_global_names; print(sorted(builtin_global_names()))"
```

`TestReservedNameSet` in
[`tests/test_builtin_names_reserved.py`](../tests/test_builtin_names_reserved.py)
pins its size (47) and a sample of members, so a change to the
built-in table is a visible event.

Two classes of declaration, two rules (`is_reserved_for` in
`capa/_builtin_identity.py`):

- **Value binders take no reserved name.** A `let` / `var` variable, a
  parameter of a function, method or lambda that has a body, a `for`
  variable, a pattern binder in `let`, `for` or `match` (struct-pattern
  shorthand included), a module-level `const`, a module-level `fun`
  (with or without `pub`) and the alias of a selectively imported
  function or constant.
- **Type-namespace declarations take no built-in FUNCTION name.** A
  struct or sum type, a variant, a `typestate`, a `trait`, a
  `capability`, an `extern component` (the set `TYPE_NAMESPACE_KINDS`),
  and the alias of a selectively imported type. Any other built-in name
  (a built-in type, capability or variant name, such as
  `type Range { ... }` or `capability Stdio`) is not refused for a
  declaration of this class by this rule.

The parameters of a signature without a body (a `trait` or
`capability` method signature, an `extern component` function) bind
nothing and are not refused.

And a built-in FUNCTION may only be called, never used as a value
(`_refuse_builtin_value` in
[`capa/analyzer/_builtin_names.py`](../capa/analyzer/_builtin_names.py)).

The rule applies to every linked file: the root program, a direct
dependency, a transitive one, and a dependency item the importer did
not select. A refusal is reported in the file that holds the
declaration. Method names and struct field names are not module-scope
or lexical binders and are not affected.

In a `match` arm a bare capitalised name is a variant pattern, not a
binder, so `match` refuses only the reserved names that can be binders
there.

### 8.2 Why

Because no local binder and no top-level value can take a built-in's
name, whether a called identifier names the built-in never depends on
lexical scope. It is a fact about
module scope alone: a built-in-named callee is the built-in exactly when
the linked module declares no top-level item of that name
(`builtin_callee` / `builtin_call` in `capa/_builtin_identity.py`). That
fact is available in every phase without the analyzer's bindings: the
cross-function summary pass, IR lowering, the Python transpiler and the
manifest. IR lowering records the decision on each call as
`Call.callee_kind` ([`capa/ir/_nodes.py`](../capa/ir/_nodes.py)). The
Wasm emitter ([`capa/ir/_emit_wasm/`](../capa/ir/_emit_wasm/)) and the
check that decides whether the bundled JSON helpers are needed
([`capa/ir/_builtin_json.py`](../capa/ir/_builtin_json.py)) read that
field instead of deciding again by name. The Python transpiler
([`capa/transpiler/`](../capa/transpiler/)) does not read the IR field:
it calls the same decision, `builtin_call` over `module_scope_names`,
directly. (Consumers found by searching `capa/` for the field and for
the two functions.) Where
the analyzer's own binding is available it must agree with the
decision; `check_agreement` raises `IdentityDisagreement` (a compiler
defect, raised rather than compiled) when it does not.

### 8.3 Mechanism

All in [`capa/analyzer/_builtin_names.py`](../capa/analyzer/_builtin_names.py):

- `_define_local` is the one door every lexical binder goes through
  (parameters, lambda parameters, `let` / `var` / `for` / `match`
  pattern binders, struct-pattern shorthands); it applies the rule
  before defining the name.
- `_refuse_reserved_item` runs for every top-level item of every
  linked file while the globals are collected. It reads the names an
  item declares off the one table `_ITEM_DECLS` in
  `capa/_builtin_identity.py`, judging the name the author wrote and,
  for a selective-import alias, the alias itself. An item class missing
  from that table raises `UnknownItemError` instead of being skipped.
- `_assert_module_scope_agrees` fails closed when the table's
  enumeration of top-level names differs from what the analyzer
  registered, on every module whose globals collect without error.

### 8.4 Diagnostics

A variable, and a constant whose reserved name is not a function:

```capa
// reserved.capa
fun main(stdio: Stdio)
    let panic = 2
    stdio.println("${panic}")
```

```
$ python -m capa --check reserved.capa
reserved.capa:3:9: error: 'panic' is the name of a built-in function and is reserved, so it cannot name a variable; rename the variable
   3 |     let panic = 2
               ^

reserved.capa: 1 error
```

```capa
// reserved_const.capa
const Random: Int = 1

fun main(stdio: Stdio)
    stdio.println("${Random}")
```

```
$ python -m capa --check reserved_const.capa
reserved_const.capa:2:7: error: 'Random' is the name of a built-in name and is reserved, so it cannot name a constant; rename the constant
   2 | const Random: Int = 1
             ^

reserved_const.capa: 1 error
```

A built-in function used as a value:

```capa
// value.capa
fun main()
    let xs = [1.5, 2.5]
    let ys = xs.map(to_int)
```

```
$ python -m capa --check value.capa
value.capa:4:21: error: the built-in function 'to_int' cannot be used as a value; call it directly, or wrap the call in a lambda
   4 |     let ys = xs.map(to_int)
                           ^

value.capa: 1 error
```

A local in a dependency (`main.capa` imports `helperpkg.util (scale)`,
and `helperpkg/util.capa` binds `let to_float = n * 10`). The CLI
prints the dependency file's full path with the host's separator,
abbreviated here as `<project>/`:

```
$ python -m capa --check main.capa
<project>/helperpkg/util.capa:2:9: error: 'to_float' is the name of a built-in function and is reserved, so it cannot name a variable; rename the variable
   2 |     let to_float = n * 10
               ^

main.capa: 1 error
```

The binder word in the message follows the declaration: `variable`,
`parameter`, `constant`, `function`, `type`, `variant`, `capability`
and `import alias` are among those observed.

### 8.5 What the tests pin, and the bound

[`tests/test_builtin_names_reserved.py`](../tests/test_builtin_names_reserved.py)
generates its cases from the analyzer's own built-in table, crossed
with every binder kind it lists: root binders (more than 900 cases),
dependency binders (direct, private, unselected, aliased in and out,
transitive), the type-namespace kinds against every built-in function
name in the root and in dependencies, the selective-import alias of a
type, and every value position (`let`, `var`, list and tuple elements,
positional and named arguments, method arguments, `return`, a `const`
initializer, a lambda body, a `match` arm, an `if` expression, a struct
field) against every built-in function. Every refused case has a twin
that differs only in the name and must stay accepted, so a refusal
cannot come from anything but the name. It also pins what stays legal:
direct calls of every built-in function, a built-in called inside a
lambda, methods and struct fields named like built-ins, `type Range`,
and names that only contain a built-in name.
[`tests/test_builtin_identity.py`](../tests/test_builtin_identity.py)
pins the identity decision: that the analyzer, the module-scope
decision and the IR `callee_kind` agree on a corpus of accepted
programs, that the guards fire, and that the backends read the one
decision.

The bound: the binder kinds above are the ones the analyzer's two doors
cover and the test module enumerates. A binder form this section does
not list is not claimed by it.

A program that avoids the reserved names compiles and runs as before.
This one uses a method and a field named like built-ins and wraps
`to_int` in a lambda:

```capa
// reserved_ok.capa
type Gauge { panic: Int }

impl Gauge
    fun to_int(self) -> Int
        return self.panic

fun main(stdio: Stdio)
    let limit = 2
    let g = Gauge { panic: 7 }
    let Gauge { panic: p } = g
    let xs = [1.5, 2.5]
    let ys = xs.map(fun (x: Float) -> Int => to_int(x))
    stdio.println("${limit} ${g.to_int()} ${p} ${ys.length()}")
```

```
$ python -m capa --run reserved_ok.capa
2 7 7 2
$ python -m capa --wasm --run reserved_ok.capa
2 7 7 2
$ python -m capa --wasm --component --wasi --run reserved_ok.capa
2 7 7 2
```

---

## Links

- [04-grammar.md](04-grammar.md): the `function_decl`, `param`,
  `import` and `lambda_expr` productions.
- [10-capability-model.md](10-capability-model.md): why a capability
  parameter is the only authority entry.
- [14-linearity-consume-typestates.md](14-linearity-consume-typestates.md):
  the semantics of `consume` and `linear type`.
- [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md): the
  behaviour of `@strict_ifc` and `@constant_time`.
- [24-backend-parity.md](24-backend-parity.md): the Unit-returning
  closure refusal on the Wasm backend.
- [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the `@export` surface.
