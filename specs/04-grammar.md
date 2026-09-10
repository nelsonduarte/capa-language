# 04. Grammar (EBNF summary)

> **What this chapter covers.** An EBNF-style summary of the syntactic
> grammar: the structure of a program and its items (`fun`, `const`,
> `type`, `typestate`, `trait`, `impl`, `capability`, `extern component`,
> `import`), types, statements, expressions (with precedence) and
> patterns. Anchored in the real parser (`capa/parser/`) and in the
> normative grammar [`Capa-EBNF.md`](../Capa-EBNF.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). The parser and lexer sources are byte-identical
between the previous measurement commit (`1834554`) and `8e2c609`
(verified with `git diff`), so the productions below describe the
current parser; all transcripts were re-run at `8e2c609` on 2026-09-10.
Primary sources: [`capa/parser/_items.py`](../capa/parser/_items.py)
(declarations), [`capa/parser/_types.py`](../capa/parser/_types.py)
(types), [`capa/parser/_statements.py`](../capa/parser/_statements.py)
(statements),
[`capa/parser/_expressions.py`](../capa/parser/_expressions.py)
(expressions), [`capa/parser/_patterns.py`](../capa/parser/_patterns.py)
(patterns), and [`Capa-EBNF.md`](../Capa-EBNF.md) chapter 5, the
normative grammar the parser implements. The EBNF notation follows
`Capa-EBNF.md` section 2: `[ ]` optional, `{ }` zero-or-more repetition,
`|` alternative, `"..."` literal terminal, UPPERCASE for lexical
categories (see [03-lexis-and-layout.md](03-lexis-and-layout.md)).

Depends on: [03-lexis-and-layout.md](03-lexis-and-layout.md).

---

## 1. Program and top-level items

A program is one source file: zero or more top-level items, terminated
by `EOF`. The order between `import` and declarations is flexible.

```ebnf
program  = { top_item } EOF

top_item = import_decl
         | function_decl
         | type_decl
         | typestate_decl
         | trait_decl
         | impl_decl
         | capability_decl
         | extern_component_decl
         | const_decl
```

Source: [`capa/parser/_items.py`](../capa/parser/_items.py). Every block
(the body of `fun`, `if`, `while`, `for`, `match`, `trait`, `impl`,
`capability`, a sum type) opens with a `NEWLINE` followed by `INDENT`;
**there is no header `:`** (a deliberate divergence from Python).

## 2. Imports

```ebnf
import_decl      = "import" module_path
                   ( import_selectors | [ "as" IDENT ] ) NEWLINE
module_path      = IDENT { "." IDENT }
import_selectors = "(" import_selector { "," import_selector } [ "," ] ")"
import_selector  = IDENT [ "as" IDENT ]
```

`import foo.bar` loads another Capa module under the namespace `bar`
(with `as` to rename it). `import foo.bar (a, b as c)` brings in only
the named `pub` items; it is mutually exclusive with the whole-module
`as` alias and must name at least one symbol. Capability flow crosses
module boundaries with the same discipline as in-module calls (a
function in another module that receives `Fs` still has to be called by
a holder of `Fs`). See
[08-functions-closures-modules.md](08-functions-closures-modules.md).

## 3. Functions

```ebnf
function_decl  = { doc_comment } { attribute NEWLINE } [ "pub" ] "fun" IDENT
                 [ generic_params ] "(" [ param_list ] ")" [ "->" type ] block

attribute      = "@" IDENT "(" [ attribute_arg { "," attribute_arg } [ "," ] ] ")"
attribute_arg  = IDENT ":" STRING
generic_params = "<" IDENT { "," IDENT } ">"
param_list     = param { "," param } [ "," ]
param          = [ "consume" ] [ "borrow" ] ( IDENT ":" type | "self" )
```

The return type is optional; if omitted, the function returns `Unit`,
and a `return expr` in its body is then a type error (`return: expected
(), got Int`). `consume` marks the parameter as taken by ownership
(linearity, see
[14-linearity-consume-typestates.md](14-linearity-consume-typestates.md));
`borrow` marks a function-typed parameter as invoke-only. Both are
restrictions the **analyzer** enforces, not the parser.

**Attributes.** The grammar accepts any identifier and any
`key: "value"` pairs, but the analyzer restricts the v1 catalogue to
**six**: `security`, `deprecated`, `audited`, `vex`, `strict_ifc`,
`constant_time` (schema in
[`capa/analyzer/_items.py`](../capa/analyzer/_items.py) line 43,
`_ATTRIBUTE_SCHEMA`). The first four carry documentation/supply-chain
metadata; `strict_ifc` and `constant_time` are behavioural and are
written without arguments (`@strict_ifc()`, `@constant_time()`). The
`@secret`/`@public` labels and the `declassify` operation are language
constructs, distinct from these attributes. Attribute argument values
must be string literals, so the metadata is statically inspectable.

## 4. Types and typestates

```ebnf
type_decl       = [ "pub" ] [ "linear" ] "type" IDENT [ generic_params ] type_body
type_body       = struct_body | sum_body
struct_body     = "{" [ struct_field { "," struct_field } [ "," ] ] "}"
struct_field    = IDENT ":" type
sum_body        = "=" NEWLINE INDENT sum_variant { sum_variant } DEDENT
sum_variant     = IDENT [ variant_payload ] NEWLINE
variant_payload = "(" type { "," type } [ "," ] ")"

typestate_decl  = [ "pub" ] "typestate" IDENT [ struct_body ]
                  NEWLINE INDENT state_name { state_name } DEDENT
state_name      = IDENT NEWLINE
```

Struct (named fields, between `{ }`) and sum type (variants, after `=`
and indented) are syntactically distinct by design. Struct fields carry
no visibility modifier: `pub` applies only to top-level items. The
`linear` qualifier (valid only on the struct form) marks the type as
must-consume. Four variant names are **reserved** and rejected in
semantic analysis: `Ok`, `Err`, `Some`, `None` (built-in
`Result`/`Option` constructors; the set is
`_RESERVED_VARIANT_NAMES` in
[`capa/analyzer/_declarations.py`](../capa/analyzer/_declarations.py)
line 38). For example, declaring a variant `Ok(Int)` produces:

```
reserved.capa:2:5: error: variant 'Ok' is reserved (collides with the built-in Result::Ok constructor). Rename this variant. Common alternatives: Compliant, Success, Hit, Ready.
```

Detail in [05-base-and-composite-types.md](05-base-and-composite-types.md)
and [07-pattern-matching.md](07-pattern-matching.md).

A typestate value is written `Name[State]` in type position, is
constructed with `Name[State] { ... }`, and transitions with
`become(value, State)` (section 9.1). See
[14-linearity-consume-typestates.md](14-linearity-consume-typestates.md).

## 5. Traits, impl, capabilities

```ebnf
trait_decl         = [ "pub" ] "trait" IDENT [ generic_params ]
                     NEWLINE INDENT { trait_member } DEDENT
trait_member       = function_signature [ uses_clause ] NEWLINE
function_signature = "fun" IDENT [ generic_params ] "(" [ param_list ] ")" [ "->" type ]
uses_clause        = "uses" "[" [ IDENT { "," IDENT } [ "," ] ] "]"

impl_decl          = "impl" IDENT [ type_args ] [ state_index ]
                     [ "for" IDENT [ type_args ] [ state_index ] ]
                     NEWLINE INDENT { function_decl } DEDENT

capability_decl    = [ "pub" ] "capability" IDENT [ generic_params ]
                     NEWLINE INDENT { capability_member } DEDENT
capability_member  = function_signature [ uses_clause ] NEWLINE

extern_component_decl = [ "pub" ] "extern" "component" IDENT "from" STRING
                        NEWLINE INDENT { function_signature NEWLINE } DEDENT
```

The `uses_clause` (optional, after the return type of a trait or
capability method) declares the capability atoms the method may exercise
(`uses [Net]`, or `uses []` for pure); `uses` is contextual. A
user-defined capability is implemented as a trait (`impl X for Type`);
the analyzer relaxes two structural rules only for the cap-bearing
struct (it may hold built-in capabilities as fields, and a regular
function may return it). See
[13-user-defined-capabilities.md](13-user-defined-capabilities.md).

An `extern component` declares a typed FOREIGN Wasm Component Model
boundary. The declaration is parsed and type-checked, the component is
recorded in the SBOM as an authority-unknown element, and on the Wasm
backend a call to it is dispatched at runtime into a sandboxed child
instance whose Component Model linker registers only the capability
interfaces the call grants
([`capa/runtime/_foreign.py`](../capa/runtime/_foreign.py), pinned by
`tests/test_foreign_component_f2a.py` and its siblings). Detail in
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md).

## 6. Constants

```ebnf
const_decl = [ "pub" ] "const" IDENT ":" type "=" expression NEWLINE
```

Evaluated at compile time; the expression must be const (a subset with
no function calls, no mutation, and no operations that depend on
capabilities).

## 7. Types (type position)

The type grammar is separate from the expression grammar. Source:
[`capa/parser/_types.py`](../capa/parser/_types.py).

```ebnf
type          = [ flow_label ] ( function_type | tuple_type | named_type )
flow_label    = "@" ( "secret" | "public" )
named_type    = ( qualified_name | "Self" ) [ type_args ] [ state_index ]
type_args     = "<" type { "," type } ">"
state_index   = "[" IDENT "]"
tuple_type    = "(" ")"                                (* Unit *)
              | "(" type "," ")"                        (* 1-tuple *)
              | "(" type "," type { "," type } [ "," ] ")"
function_type = "Fun" "(" [ type { "," type } ] ")" "->" type
qualified_name = IDENT { "." IDENT }
```

`List`, `Option`, `Result`, `Map`, `Fun` are not keywords: they are type
constructors (`List<Int>` is a `named_type` with type_args;
`Fun(Int) -> Int` is the dedicated `function_type` production). The
`flow_label` `@secret`/`@public` prefixes any type and is honoured
everywhere a type appears (fields, parameters, returns, bindings,
type-args). The parser disambiguates `@secret`/`@public` (a label, not
followed by `(` in type position) from `@name(...)` (an attribute before
a declaration) by position and lookahead. See
[15-ifc-model-and-labels.md](15-ifc-model-and-labels.md).

## 8. Statements

Source: [`capa/parser/_statements.py`](../capa/parser/_statements.py).

```ebnf
block      = NEWLINE INDENT { statement } DEDENT

statement  = let_stmt | var_stmt | assign_stmt
           | if_stmt | while_stmt | for_stmt | match_stmt
           | return_stmt | break_stmt | continue_stmt
           | expression_stmt

let_stmt   = "let" pattern [ ":" type ] "=" expression NEWLINE
var_stmt   = "var" IDENT [ ":" type ] "=" expression NEWLINE
assign_stmt = lvalue assign_op expression NEWLINE
assign_op  = "=" | "+=" | "-=" | "*=" | "/=" | "%="

if_stmt    = "if" expression block { "elif" expression block } [ "else" block ]
while_stmt = "while" expression block
for_stmt   = "for" pattern "in" expression block
match_stmt = "match" match_scrutinee match_body

return_stmt   = "return" [ expression ] NEWLINE
break_stmt    = "break" NEWLINE
continue_stmt = "continue" NEWLINE
expression_stmt = expression NEWLINE
```

`let` admits pattern destructuring (`let (a, b) = pair`); `var` admits
only `IDENT` (mutability only makes sense for a simple variable).
`if`/`while`/`for` are **statements, not expressions**; for a value use
the ternary `if c then a else b` (section 9). `match` is both: statement
and expression (the same production). The target of `assign_stmt`
parses as a `postfix_expr` whose outer operation must be a name, a field
access, or an index; anything else is rejected at parse time.

```ebnf
match_body = NEWLINE INDENT match_arm { match_arm } DEDENT     (* multi-line *)
           | "{" inline_arm { "," inline_arm } [ "," ] "}"     (* inline *)
match_arm  = match_arm_pattern [ "if" expression ] "->" ( expression NEWLINE | block )
inline_arm = match_arm_pattern [ "if" expression ] "->" expression
```

The inline form `{ p -> e, ... }` exists for expression position
(single-line); the indented form admits block bodies. Both accept guards
(`if`) and or-patterns. See
[09-expressions-and-control.md](09-expressions-and-control.md).

## 9. Expressions and precedence

Source: [`capa/parser/_expressions.py`](../capa/parser/_expressions.py).
The layers, from lowest precedence (binds weakest) to highest:

```ebnf
expression   = ternary_expr
ternary_expr = if_expr | or_expr
if_expr      = "if" or_expr "then" expression "else" expression
or_expr      = and_expr { "or" and_expr }
and_expr     = not_expr { "and" not_expr }
not_expr     = "not" not_expr | compare_expr
compare_expr = range_expr [ compare_op range_expr ]        (* non-associative *)
range_expr   = bit_or_expr [ ( ".." | "..=" ) bit_or_expr ] (* non-associative *)
bit_or_expr  = bit_xor_expr { "|" bit_xor_expr }
bit_xor_expr = bit_and_expr { "^" bit_and_expr }
bit_and_expr = shift_expr { "&" shift_expr }
shift_expr   = add_expr { ( "<<" | ">>" ) add_expr }
add_expr     = mul_expr { ( "+" | "-" ) mul_expr }
mul_expr     = unary_expr { ( "*" | "/" | "%" ) unary_expr }
unary_expr   = "-" unary_expr | postfix_expr
postfix_expr = primary_expr { postfix_op }
postfix_op   = "." IDENT | "(" [ arg_list ] ")" | "[" expression "]" | "?"
arg_list     = argument { "," argument } [ "," ]
argument     = [ IDENT ":" ] expression                    (* named argument *)
```

Precedence table (weakest to strongest; `Capa-EBNF.md` section 6.1):

| Level | Operators | Associativity |
|---|---|---|
| 1 | `if-then-else` (ternary) | Right |
| 2 | `or` | Left |
| 3 | `and` | Left |
| 4 | `not` (unary) | - |
| 5 | `==` `!=` `<` `<=` `>` `>=` | Non-associative |
| 6 | `..` `..=` | Non-associative |
| 7 | `\|` (bitwise or) | Left |
| 8 | `^` (bitwise xor) | Left |
| 9 | `&` (bitwise and) | Left |
| 10 | `<<` `>>` | Left |
| 11 | `+` `-` (binary) | Left |
| 12 | `*` `/` `%` | Left |
| 13 | `-` (unary) | Right |
| 14 | `.` `()` `[]` `?` (postfix) | Left |

Notes: comparisons **do not chain** (`1 < x < 10` is a syntax error; use
`1 < x and x < 10`). The ternary requires both `then` and `else`; `then`
is the disambiguator between the `if` statement (followed by a block)
and the `if` expression. Named arguments (`f(name: "Ana")`) are allowed,
positionals first. The `?` operator (level 14) propagates `Result`. A
range expression evaluates to a value of type `Range<Int>`, a type
distinct from `List<Int>` (see
[05-base-and-composite-types.md](05-base-and-composite-types.md)).

Rejection of chained comparisons:

```
$ python -m capa --check chain.capa      # body: return 1 < x < 10
chain.capa:2:18: error: comparison operators are non-associative; use parentheses or boolean operators to combine
   2 |     return 1 < x < 10
                        ^
```

### 9.1 Primaries and lambdas

```ebnf
primary_expr = literal_expr | ident_expr | paren_expr | tuple_expr
             | list_expr | struct_expr | become_expr | lambda_expr
literal_expr = INT_LIT | FLOAT_LIT | STRING_LIT | CHAR_LIT
             | ("true"|"false") | "(" ")"
paren_expr   = "(" expression ")"
tuple_expr   = "(" expression "," ")"
             | "(" expression "," expression { "," expression } [ "," ] ")"
list_expr    = "[" [ expression { "," expression } [ "," ] ] "]"
struct_expr  = qualified_name [ state_index ] "{" struct_init { "," struct_init } [ "," ] "}"
struct_init  = IDENT ":" expression
become_expr  = "become" "(" expression "," IDENT ")"
lambda_expr  = "fun" "(" [ param_list ] ")" [ "->" type ] "=>" lambda_body
lambda_body  = expression | NEWLINE INDENT { statement } DEDENT
```

DIVERGENCE. Against the EBNF (which lists `BOOL_LIT`/`UNIT_LIT`): there
is no `BOOL_LIT` token, `true`/`false` are keywords, and `()` is
`LPAREN RPAREN` (see [03-lexis-and-layout.md](03-lexis-and-layout.md)
section 5.5). The `paren_expr` versus `tuple_expr` distinction is made
by the comma (`(x)` is a parenthesized expression, `(x,)` is a
one-element tuple). A lambda starts with `fun` and uses `=>` for the
body (`xs.map(fun (x) => x + 1)`); capabilities captured by a closure
are borrowed (the analyzer rejects `consume` on a capture). `{...}` in
expression position is always a struct literal in 1.0 (map literals and
block expressions are deferred).

## 10. Patterns

Source: [`capa/parser/_patterns.py`](../capa/parser/_patterns.py).
Patterns are used in `let`, `for` and `match`, with uniform syntax.

```ebnf
pattern           = literal_pattern | wildcard_pattern | binding_pattern
                  | tuple_pattern | ctor_pattern | struct_pattern
literal_pattern   = INT_LIT | FLOAT_LIT | STRING_LIT | CHAR_LIT | ("true"|"false")
wildcard_pattern  = "_"
binding_pattern   = IDENT
tuple_pattern     = "(" pattern { "," pattern } [ "," ] ")"
ctor_pattern      = IDENT [ "(" [ pattern { "," pattern } ] ")" ]
struct_pattern    = IDENT "{" field_pattern { "," field_pattern } "}"
field_pattern     = IDENT [ ":" pattern ]
match_arm_pattern = pattern { "|" pattern }         (* or-pattern, match-arm only *)
```

Or-patterns (`A | B | C -> body`) are valid only at the match-arm level;
the analyzer requires every alternative to bind exactly the same set of
names, with compatible types:

```
orpat.capa:7:16: error: or-pattern: alternative 1 binds different names than alternative 0 (missing x; extra y)
   7 |         A(x) | B(y) -> 0
                      ^
```

See [07-pattern-matching.md](07-pattern-matching.md).

## 11. Integrated example (verified)

A program exercising a sum type, `match`, generics, the ternary, `for`
over an inclusive range, `Option` and interpolation, run on both
backends:

```capa
// gram.capa
type Shape =
    Circle(Float)
    Rect(Float, Float)

fun area(s: Shape) -> Float
    return match s
        Circle(r) -> 3.14159 * r * r
        Rect(w, h) -> w * h

fun sign(n: Int) -> String
    return if n > 0 then "+" else if n < 0 then "-" else "0"

fun first<T>(xs: List<T>) -> Option<T>
    for x in xs
        return Some(x)
    return None

fun main(stdio: Stdio)
    stdio.println("area circle = ${area(Circle(2.0))}")
    stdio.println("area rect   = ${area(Rect(3.0, 4.0))}")
    stdio.println("sign(-5)    = ${sign(-5)}")
    var total = 0
    for i in 1..=5
        total += i
    stdio.println("sum 1..=5   = ${total}")
    let got = match first([10, 20, 30])
        Some(v) -> v
        None -> -1
    stdio.println("first       = ${got}")
```

```
$ python -m capa --run gram.capa
area circle = 12.56636
area rect   = 12.0
sign(-5)    = -
sum 1..=5   = 15
first       = 10
$ python -m capa --run --wasm gram.capa
area circle = 12.56636
area rect   = 12.0
sign(-5)    = -
sum 1..=5   = 15
first       = 10
```

The two backends produce identical output.

## 12. Conformance notes and deferred forms

The grammar is designed for recursive descent with a maximum lookahead
of two tokens (LL(2)), and every valid program has a single derivation
(the classic ambiguities, dangling-else and `<`/type-args, resolve by
indentation and by position; `Capa-EBNF.md` chapter 7). Forms
deliberately **deferred** past 1.0 and absent from this grammar
(`Capa-EBNF.md` section 1.5): bounds on type-params (`<T: Display>`,
with `where` reserved), supertraits, default method bodies in traits,
generic `impl<T>` blocks, named variant payload fields, map literals and
block expressions in expression position, struct-pattern rest
(`{a, ..}`) and turbofish (`::<T>`).

---

## Links

- [03-lexis-and-layout.md](03-lexis-and-layout.md): the tokens this
  grammar consumes.
- [05-base-and-composite-types.md](05-base-and-composite-types.md)
  through [09-expressions-and-control.md](09-expressions-and-control.md):
  the semantics of each production group.
- [07-pattern-matching.md](07-pattern-matching.md): patterns and
  exhaustiveness.
- [18-compiler-pipeline.md](18-compiler-pipeline.md): where the parser
  sits in the phases.
- [`Capa-EBNF.md`](../Capa-EBNF.md) (repository root): the complete
  normative grammar.
