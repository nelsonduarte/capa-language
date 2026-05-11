# Grammar Specification

# Capa

## Lexical structure and syntactic grammar in EBNF

Technical specification document — companion to the white paper
Version 1.0 — May 2026

## Table of Contents

- 1. Introduction and Purpose
- 2. EBNF Notation Conventions
- 3. Lexical Structure
- 4. Whitespace Handling and Significant Indentation
- 5. Syntactic Grammar
- 6. Operator Precedence and Associativity
- 7. Resolved Ambiguities
- 8. Annotated Example Program
- Appendix A — Complete List of Reserved Words
- Appendix B — Complete List of Operators and Punctuation

---

## 1. Introduction and Purpose

### 1.1 Positioning of this document

This document is the second in the set of specifications for the Capa language. The first document (the technical white paper) presented the justification, design principles, informal syntax and roadmap. This second document formalises, in EBNF notation, the complete lexical structure and syntactic grammar of version 1.0 of the language.

The purpose is threefold. First, to serve as a normative reference for the compiler implementation: the lexer and the parser must accept exactly the language described here, no more and no less. Second, to provide a solid basis for external static analysis — formatters, linters, documentation generators, language servers — without the need for each tool to reconstruct its own understanding of the syntax. Third, to make Capa teachable: this document is the material that allows a student or an independent reader to exhaustively understand the shape of the language.

### 1.2 Structure of the document

The document is divided into eight chapters and three appendices. Chapter 2 establishes the EBNF notation used, with examples. Chapters 3 and 4 cover the lexical level — what constitutes a token and how the lexer handles indentation, line breaks and whitespace. Chapter 5 is the core: the syntactic grammar, from the complete program down to atomic expressions. Chapters 6 and 7 deal with transverse questions (precedence, associativity, resolved ambiguities). Chapter 8 presents a complete annotated Capa program, rule by rule. The appendices exhaustively list the reserved words and the operators.

### 1.3 Quality criteria

The grammar presented satisfies the following quality criteria, considered non-negotiable by the design team:

- **Unambiguous:** every valid Capa program has one and only one derivation in the grammar. Inherent ambiguities (precedence, dangling else) are resolved by explicit rules documented in Chapter 7.
- **Decidable by an LL(2) parser:** the grammar is designed so that it can be implemented by a recursive descent parser with maximum lookahead of two tokens. This drastically reduces the complexity of the implementation and the probability of subtle parser bugs.
- **Stable:** version 1.0 is considered stable. Future extensions (refinement types, structured concurrency, macros) will enter through the addition of new productions, never by modification of existing ones.
- **Pedagogically accessible:** the order in which rules are presented follows a didactic progression — from the most general (program) to the most specific (literals), and from the most common to the most rare.

### 1.4 What this grammar does not cover

It is important to delimit the scope. This grammar describes the syntax of the language; it does not describe its semantics. In particular, the following are not in this document:

- The static typing rules (which types are compatible with which others, how inference works).
- The capability propagation rules (R1 to R4 from the white paper).
- The operational semantics of the various statements and expressions.
- The details of Python code generation in Phase 1.
- The rules of the module system (resolution of imports, visibility between crates).

These aspects will be the subject of separate documents in the course of implementation. The present document confines itself to what can be said about the form of a program before any semantic analysis.

---

## 2. EBNF Notation Conventions

### 2.1 EBNF variant used

This specification uses a variant of EBNF (Extended Backus-Naur Form) inspired by ISO/IEC 14977, but simplified for legibility. The operators and their semantics are as follows.

| Construct | Meaning | Example |
|---|---|---|
| `name = production` | Defines the rule `name` | `digit = "0" | "1" | ... | "9"` |
| `A | B` | Alternative: A or B | `bool = "true" | "false"` |
| `[ A ]` | Optional: zero or one occurrence of A | `[ "-" ] digit` |
| `{ A }` | Repetition: zero or more occurrences of A | `{ digit }` |
| `( A )` | Grouping | `( "+" | "-" ) digit` |
| `"text"` | Literal terminal (exact sequence) | `"fun"` |
| `UPPERCASE` | Lexical category (token) | `IDENT`, `NEWLINE` |
| `(* text *)` | Non-normative comment | `(* explanatory note *)` |

### 2.2 Typographic conventions

To facilitate reading, the rules are presented in fenced code blocks. Within these blocks, non-terminal identifiers, literal terminals (keywords, punctuation) and EBNF operators appear together; non-normative comments appear within `(* ... *)`.

Example:

```ebnf
bool_literal = "true" | "false"

digit = "0" | "1" | "2" | "3" | "4"
      | "5" | "6" | "7" | "8" | "9"

int_literal = digit { digit | "_" }   (* allows separators: 1_000_000 *)
```

### 2.3 Lexical categories vs. syntactic categories

It is useful to distinguish two levels. Lexical categories (written in UPPERCASE) are produced by the lexer and consumed by the parser as atomic tokens. Examples: `IDENT` (an identifier), `INT_LIT` (an integer literal), `NEWLINE` (a logical line break), `INDENT` and `DEDENT` (block markers).

Syntactic categories (written in lower case with underscores) are produced by the parser from tokens. Examples: `expression`, `statement`, `function_decl`.

This separation has an important practical consequence: the lexical rules (Chapter 3) and the syntactic rules (Chapter 5) do not mix. An identifier is always the `IDENT` token, never a sequence of letters in the syntactic grammar.

### 2.4 Additional conventions

- **Whitespace between elements:** in the syntactic grammar, non-significant whitespace and line breaks are consumed automatically between tokens (except in contexts where `NEWLINE` or `INDENT`/`DEDENT` are significant).
- **Optional trailing punctuation:** trailing commas in lists and structures are optional and indicated by `[ "," ]` in the grammar.
- **Right recursion:** where possible, the rules are written with right recursion or iteration with `{ ... }` to facilitate implementation by a recursive descent parser.

---

## 3. Lexical Structure

This chapter describes, in sufficient detail for implementation, the set of tokens that constitute the vocabulary of the language. The lexer consumes the source text and produces a sequence of tokens; it is this sequence, and not the original text, that the syntactic parser sees.

### 3.1 Character set

The source text of Capa is encoded in UTF-8. Comments and string literals may contain any valid Unicode codepoint. Identifiers are restricted to ASCII characters in version 1.0 (with possible future extension to UAX #31).

### 3.2 Comments

Capa supports line comments and block comments. Line comments start with `//` and run to the end of the line. Block comments start with `/*` and end with `*/` and may be nested (a difference from C/Java but consistent with Rust and Swift).

```ebnf
line_comment = "//" { any_char_except_newline } NEWLINE

block_comment = "/*" { block_comment_content } "*/"

block_comment_content = block_comment      (* nesting allowed *)
                      | any_char_except_block_delimiter
```

Comments are consumed by the lexer and never reach the parser. Exception: documentation comments (which start with `///` for a line or `/**` for a block) are preserved to be associated with the immediately following declaration and used by `capa-doc`.

### 3.3 Identifiers

```ebnf
IDENT = ident_start { ident_continue }

ident_start = letter | "_"

ident_continue = letter | digit | "_"

letter = "a" | "b" | ... | "z" | "A" | "B" | ... | "Z"

digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
```

Additional restriction: an identifier cannot equal a reserved word (see Section 3.5). This restriction is checked in the lexer, which classifies as `KEYWORD` those tokens that correspond to reserved words.

Practical notes. A leading underscore is allowed (`_x` is a valid identifier), and by convention indicates an intent of non-use. Identifiers starting with a digit are impossible by construction. Identifiers in Capa are case-sensitive: `user` and `User` are distinct identifiers.

### 3.4 Literals

#### 3.4.1 Integer literals

```ebnf
INT_LIT = dec_int | hex_int | oct_int | bin_int

dec_int = digit { digit | "_" }

hex_int = "0x" hex_digit { hex_digit | "_" }

oct_int = "0o" oct_digit { oct_digit | "_" }

bin_int = "0b" bin_digit { bin_digit | "_" }

hex_digit = digit | "a" | ... | "f" | "A" | ... | "F"

oct_digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7"

bin_digit = "0" | "1"
```

The interspersed underscores are purely visual (`1_000_000` is equivalent to `1000000`) and cannot appear at the beginning or end of the number, nor two consecutively. This restriction is enforced by the lexer.

Valid examples: `0`, `42`, `-7` (the sign is part of the expression, not of the literal), `1_000_000`, `0xFF`, `0xCAFE_BABE`, `0o755`, `0b1010_1010`.

#### 3.4.2 Floating-point literals

```ebnf
FLOAT_LIT = dec_int "." digit { digit | "_" } [ exponent ]
          | dec_int exponent

exponent = ( "e" | "E" ) [ "+" | "-" ] digit { digit | "_" }
```

Valid examples: `3.14`, `0.5`, `1e10`, `6.022e23`, `1_000.5`, `2.5E-3`.

#### 3.4.3 String literals

Strings in Capa are immutable and encoded in UTF-8. They support simple interpolation with the `${...}` syntax (see Section 3.4.6).

```ebnf
STRING_LIT = "\"" { string_char } "\""

string_char = any_char_except_quote_or_backslash
            | escape_seq
            | interpolation

escape_seq = "\\" ( "n" | "r" | "t" | "\\" | "\"" | "0" | unicode_esc )

unicode_esc = "u" "{" hex_digit { hex_digit } "}"   (* up to 6 hex digits *)

interpolation = "${" expression "}"
```

Valid examples: `"hello"`, `"line 1\nline 2"`, `"emoji: \u{1F600}"`, `"x = ${x}, y = ${y}"`.

#### 3.4.4 Raw string literals

Raw strings start with `r` followed by quotes and do not interpret escape sequences or interpolation. They are especially useful for regex and Windows paths.

```ebnf
RAW_STRING_LIT = "r\"" { any_char_except_quote } "\""

  (* variants with # to include quotes: r#"..."#, r##"..."##, ... *)
```

> **Not in 1.0.** The grammar reserves the syntax, but the current lexer does not yet recognise raw strings. Programs that need a literal backslash should escape it (`"\\"`). Raw strings will land in a later version.

#### 3.4.5 Character literals

```ebnf
CHAR_LIT = "'" char_char "'"

char_char = any_char_except_quote_or_backslash
          | escape_seq
```

A `Char` in Capa is a Unicode codepoint (32 bits), not a byte. Examples: `'a'`, `'\n'`, `'\u{1F600}'`.

#### 3.4.6 Boolean and Unit literals

```ebnf
BOOL_LIT = "true" | "false"

UNIT_LIT = "(" ")"
```

### 3.5 Reserved words

The following words are reserved by the language and cannot be used as identifiers. The complete list is given in Appendix A; the categorisation is shown here.

| Category | Words |
|---|---|
| Declarations | `fun`, `type`, `trait`, `impl`, `capability`, `const`, `pub`, `import`, `as` |
| Control flow | `if`, `then`, `elif`, `else`, `match`, `while`, `for`, `in`, `break`, `continue`, `return` |
| Variables | `let`, `var` |
| Capability discipline | `consume` |
| Literal values | `true`, `false` |
| Logical operators | `and`, `or`, `not` |
| Self and types | `self`, `Self` |
| Reserved for future use | `async`, `await`, `yield`, `defer`, `where`, `mut` |

Words reserved for future use have no meaning in version 1.0, but the lexer rejects them as identifiers. This proactive reservation makes it possible to introduce the corresponding features in later versions without breaking existing code.

### 3.6 Operators and punctuation

The operator and punctuation tokens are recognised by the lexer using the maximal munch rule (always the longest possible token). The complete list is in Appendix B; it is summarised here.

| Category | Symbols |
|---|---|
| Arithmetic | `+`, `-`, `*`, `/`, `%` |
| Comparison | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| Logical | `and`, `or`, `not` (words); `&&` and `\|\|` do not exist |
| Assignment | `=`, `+=`, `-=`, `*=`, `/=`, `%=` |
| Structural | `.`  `,`  `;`  `:`  `->`  `=>`  `?`  `..` |
| Pattern | `\|`  (* or-pattern separator, only in match arms *) |
| Delimiters | `( )`  `[ ]`  `{ }`  `< >` (in type args) |
| Special | `_`  (* underscore as wildcard in patterns *) |

> **DESIGN DECISION: AND/OR/NOT INSTEAD OF &&/||/!**
>
> Capa adopts `and`, `or`, `not` as keywords instead of the C-style symbols `&&` / `||` / `!`. The justification is twofold: it brings the language closer to Python (which the target audience knows), and it eliminates the confusion between logical operators and bitwise operators (which are reserved for a future extension in the form `bit_and`, `bit_or`, etc., avoiding visual ambiguity).

---

## 4. Whitespace Handling and Significant Indentation

Capa, like Python, uses significant indentation to delimit blocks. This chapter describes in detail how the lexer treats spaces, tabs and line breaks, and how it produces the `NEWLINE`, `INDENT` and `DEDENT` tokens that the parser consumes.

### 4.1 Spaces and tabs

At the start of a logical line, the sequence of spaces (and only spaces) determines the indentation level of that line. Tabs are forbidden at the start of a line — the lexer rejects the program with a lexical error if it encounters a tab starting a line. This radical prohibition avoids whole classes of subtle bugs in environments that mix tabs and spaces.

Outside the start of a line, spaces and tabs are consumed with no effect (except inside strings, of course). Canonical indentation is four spaces; any positive multiple is accepted, but the increase from one level to the next must be consistent within the same block.

### 4.2 Logical line breaks

A logical line break corresponds, in most cases, to a physical line break in the source text. There are two exceptions:

- **Implicit continuation by brackets:** a line break inside a pair of delimiters (parentheses, square brackets, braces) does not produce `NEWLINE`. This allows lists, function calls and long expressions to be broken across multiple physical lines without the need for explicit continuation.
- **Explicit continuation by backslash:** a line terminated by `\` immediately before the break is continued on the following line. This form is discouraged in idiomatic code but supported for extreme cases.

Lines containing only spaces or only comments do not produce `NEWLINE` — they are ignored by the lexer.

```ebnf
NEWLINE = line_terminated_by_break_not_inside_brackets_and_not_continued
```

### 4.3 INDENT and DEDENT

After each `NEWLINE`, the lexer compares the indentation level of the following line with the current level. The rules are:

- **Indentation equal to the current level:** no additional token is produced.
- **Indentation greater than the current level:** produces an `INDENT` token. The new level is pushed onto the level stack.
- **Indentation less than the current level:** produces one or more `DEDENT` tokens, one for each level popped, until the current level equals that of the line. If no level on the stack matches exactly, the lexer rejects the program with an inconsistent indentation error.

At the end of the file, the lexer produces as many `DEDENT` tokens as needed to empty the indentation stack.

> **PRACTICAL IMPLEMENTATION**
>
> This `INDENT`/`DEDENT` logic is the same as Python's (PEP 8 / lexical analysis). Reference implementations can be studied in CPython, Lark or ANTLR. The Capa lexer can reuse this well-known algorithm without innovation.

### 4.4 Concrete example

The source program:

```capa
fun classify(x: Int) -> String
    if x < 0
        return "negative"
    return "non-negative"
```

is tokenised as (showing only the skeleton, ignoring IDENTs and operators):

```
fun ... NEWLINE
INDENT
    if ... NEWLINE
    INDENT
        return ... NEWLINE
    DEDENT
    return ... NEWLINE
DEDENT
```

Note that `INDENT` and `DEDENT` are produced automatically by the lexer based on changes in indentation level. The parser consumes these tokens to delimit blocks.

### 4.5 Blank lines and comments

Blank lines and lines containing only comments are ignored for the purposes of indentation calculation — the lexer skips them and considers the next non-empty line. This rule prevents comments or blank lines in the middle of a block from breaking the structure.

---

## 5. Syntactic Grammar

This is the central chapter of the document. It presents Capa's complete grammar in EBNF, organised from the highest level (complete program) to the lowest (atomic expressions). Each section informally introduces the constructs, presents the EBNF rules, and where necessary discusses relevant design decisions.

### 5.1 Program and top-level declarations

A Capa program is a source code file. It has zero or more imports, followed by zero or more top-level declarations. The order between `import` and declarations is flexible — imports may appear at any point, although the convention is to group them at the start.

```ebnf
program = { top_item } EOF

top_item = import_decl
         | function_decl
         | type_decl
         | trait_decl
         | impl_decl
         | capability_decl
         | const_decl

import_decl = "import" module_path [ "as" IDENT ] NEWLINE

module_path = IDENT { "." IDENT }
```

> **Status of `import` in 1.0.** The grammar accepts `import` syntactically, but the semantic analyzer rejects every occurrence with an error directing the user to `py_import(unsafe, "...")` instead. The reason is the capability discipline: transpiling `import` directly to a Python `import` would let any function in the program call into the imported module's globals without an `Unsafe` capability, punching a hole through the entire system. The `import` form is reserved for a future Capa module system; until that lands, the only legitimate crossing of the Python boundary is the `py_import` / `py_invoke` pair (see `docs/stdlib.md`), both of which require `Unsafe`.

### 5.2 Function declarations

Functions are the dominant unit of abstraction in Capa. A function declaration has optional visibility, the keyword `fun`, a name, optional type parameters, a parameter list, an optional return type, and a block as its body.

```ebnf
function_decl = [ "pub" ] "fun" IDENT [ generic_params ]
    "(" [ param_list ] ")"
    [ "->" type ]
    block

generic_params = "<" generic_param { "," generic_param } ">"

generic_param = IDENT [ ":" trait_bound { "+" trait_bound } ]

trait_bound = qualified_name [ type_args ]

param_list = param { "," param } [ "," ]

param = [ "consume" ] IDENT ":" type
      | "self"                          (* method receiver, type implicit *)
```

The optional `consume` qualifier marks the parameter as taking ownership of the passed value (typically a capability). After a call to such a function, the caller can no longer use the argument it passed. This is enforced by the semantic analyzer's linearity check, not the grammar; see the Capabilities chapter of the white paper for details.

Relevant notes. The return type is syntactically optional; if omitted, the type is inferred as `Unit` (the function does not return a useful value) — except in public functions, where a later semantic phase requires the explicit annotation. The trailing comma in `param_list` is allowed to facilitate clean diffs.

The absence of a `":"` between the function header and the block is a deliberate divergence from Python. The rule is: a header on a `NEWLINE`, followed by an `INDENT` that opens the block. This rule applies uniformly to all constructs with a block (`if`, `while`, `for`, `match`, `function_decl`).

### 5.3 Type declarations

Capa has two kinds of type declaration: structures (with named fields) and sum types (with variants). The syntax is distinguished by the initial separator: braces for structures, equals sign followed by indented variants for sum types.

```ebnf
type_decl = [ "pub" ] "type" IDENT [ generic_params ] type_body

type_body = struct_body
          | sum_body

struct_body = "{" [ struct_field { "," struct_field } [ "," ] ] "}"

struct_field = [ "pub" ] IDENT ":" type

sum_body = "=" NEWLINE INDENT sum_variant { sum_variant } DEDENT

sum_variant = IDENT [ variant_payload ] NEWLINE

variant_payload = "(" variant_field { "," variant_field } [ "," ] ")"

variant_field = [ IDENT ":" ] type
```

> **DECISION: CLEAR SEPARATION BETWEEN STRUCT AND SUM**
>
> Other languages (Rust, Swift) unify the two forms under `enum`/`type`. Capa keeps them separate because, in pedagogical experience, students easily confuse `struct {...}` with `enum X { Variant(struct {...}) }`. Forcing distinct syntax for the two concepts makes code more readable and teaching more direct.

### 5.4 Trait declarations

A trait defines a set of function signatures (and, optionally, default implementations) that types may implement. Capa follows Rust's model: traits are nominal interfaces, and the implementation is declared separately from the type.

```ebnf
trait_decl = [ "pub" ] "trait" IDENT [ generic_params ]
    [ ":" trait_bound { "+" trait_bound } ]   (* supertraits *)
    NEWLINE INDENT { trait_member } DEDENT

trait_member = function_signature NEWLINE
             | function_decl                  (* default implementation *)

function_signature = "fun" IDENT [ generic_params ]
    "(" [ param_list ] ")"
    [ "->" type ]
```

### 5.5 impl declarations

An `impl` declaration associates a set of methods with a concrete type. There are two forms: a plain `impl` (methods belonging to the type itself) and a trait `impl` (which satisfies the signatures declared by the trait).

```ebnf
impl_decl = "impl" [ generic_params ]
    [ qualified_name [ type_args ] "for" ] type
    NEWLINE INDENT { function_decl } DEDENT
```

When the `qualified_name for` part is omitted, the `impl` defines methods of the type itself (with no associated trait). This is the most common form for types specific to the application.

### 5.6 Capability declarations

Standard capabilities are provided by the runtime and not declared in user code. But the user can declare domain-specific capabilities, which behave structurally as traits, but with special semantics — they can only be constructed from other capabilities (see Chapter 4 of the white paper).

```ebnf
capability_decl = [ "pub" ] "capability" IDENT [ generic_params ]
    NEWLINE INDENT { capability_member } DEDENT

capability_member = function_signature NEWLINE
```

A user-defined capability is implemented exactly like a trait: `impl X for Type`, where `X` is the capability and `Type` is the concrete implementor. The implementor's value is then accepted anywhere `X` is expected (nominal subtyping).

To make the encapsulation pattern from WhitePaper §4.6 workable, the analyzer relaxes two of the otherwise-strict structural rules **only for the cap-bearing struct**:

- The struct that implements a user-defined capability **may hold built-in capabilities as fields** (e.g. `type SmtpMailer { server: String, net: Net }`). The struct's *value* still has to follow the capability discipline as a whole — aliasing it via `let dup = mailer` is rejected, the same as for built-in caps.
- A regular function **may return a user-defined capability** (factory pattern: `fun make_smtp_mailer(net: Net, ...) -> SmtpMailer`). Built-in caps still cannot be returned, so the chain from `main` to any cap value remains visible in signatures at every link.

```capa
capability SendEmail
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>

type SmtpMailer { server: String, net: Net }

impl SendEmail for SmtpMailer
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>
        return Ok(())

fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer
    return SmtpMailer { server: server, net: net.restrict_to(server) }

fun send_welcome(mailer: SendEmail, to: String) -> Result<Unit, IoError>
    return mailer.send(to, "Welcome", "Hello!")
```

### 5.7 Constant declarations

```ebnf
const_decl = [ "pub" ] "const" IDENT ":" type "=" expression NEWLINE
```

Constants are evaluated at compile time. The expression must be a const expression — a subset of the expression grammar that excludes function calls (except `const fn` in a future version), mutation, and operations that depend on capabilities.

### 5.8 Types

The grammar for types is separate from the grammar for expressions. Types may be qualified names (with optional generic arguments), function types, tuple types, or references to `Self`.

```ebnf
type = function_type
     | tuple_type
     | named_type

named_type = qualified_name [ type_args ]
           | "Self"

type_args = "<" type { "," type } ">"

tuple_type = "(" ")"                                  (* Unit *)
           | "(" type "," ")"                          (* 1-tuple *)
           | "(" type "," type { "," type } [ "," ] ")"

function_type = "Fun" "(" [ type { "," type } ] ")" "->" type

qualified_name = IDENT { "." IDENT }
```

Note that `List`, `Option`, `Result`, `Map`, and `Fun` are not keywords — they are merely generic types / built-in type constructors defined by the language and the standard library. The syntax `List<Int>` is an ordinary `named_type` with type arguments; `Fun(Int, Int) -> Int` is the dedicated `function_type` production. This uniformity simplifies the grammar (and keeps `fun`, the lowercase keyword, distinct from `Fun`, the uppercase type constructor).

### 5.9 Block and statements

A block is a sequence of statements delimited by `INDENT` and `DEDENT`. Statements are executable units: variable declarations, assignments, control flow, and expressions evaluated for their effect.

```ebnf
block = NEWLINE INDENT { statement } DEDENT

statement = let_stmt
          | var_stmt
          | assign_stmt
          | if_stmt
          | while_stmt
          | for_stmt
          | match_stmt
          | return_stmt
          | break_stmt
          | continue_stmt
          | expression_stmt

let_stmt = "let" pattern [ ":" type ] "=" expression NEWLINE

var_stmt = "var" IDENT [ ":" type ] "=" expression NEWLINE

assign_stmt = lvalue assign_op expression NEWLINE

assign_op = "=" | "+=" | "-=" | "*=" | "/=" | "%="

lvalue = IDENT { "." IDENT | "[" expression "]" }
```

Notes. `let` allows destructuring pattern matching (`let (a, b) = pair`); `var` allows only `IDENT`, because the concept of mutability only makes sense for a simple variable. `assign_stmt` admits any `lvalue` (field access or indexing) as a target; the type checker validates that the target is mutable.

### 5.10 Control flow statements

```ebnf
if_stmt = "if" expression block
        { "elif" expression block }
        [ "else" block ]

while_stmt = "while" expression block

for_stmt = "for" pattern "in" expression block

match_stmt = "match" match_scrutinee match_body

match_body = NEWLINE INDENT match_arm { match_arm } DEDENT     (* multi-line *)
           | "{" inline_arm { "," inline_arm } [ "," ] "}"     (* inline *)

match_arm = match_arm_pattern [ "if" expression ]
    "->" ( expression NEWLINE | block )

inline_arm = match_arm_pattern [ "if" expression ] "->" expression

(* The scrutinee parses as an expression with the struct-literal
   heuristic disabled. See "Ambiguity 7.6" below. *)
match_scrutinee = expression

return_stmt = "return" [ expression ] NEWLINE

break_stmt = "break" NEWLINE

continue_stmt = "continue" NEWLINE

expression_stmt = expression NEWLINE
```

Important design decision: `if`, `while`, `for` are statements, not expressions. A programmer who wants to use a control structure to produce a value uses the ternary `if cond then a else b` (Section 5.12.2).

`match` is **both** a statement and an expression — the same production serves both roles. In statement position the value is discarded; in expression position (RHS of `let`/`var`/`return`, inside string interpolation, as an argument to a function call written across the multi-line form, etc.) the value flows out. The inline `{ p -> e, ... }` form exists specifically for expression position and is single-line by design — multi-line block bodies are reserved for the indented form. Both forms accept guards and or-patterns.

```capa
let s = match x { 0 -> "zero", _ -> "other" }

let urgency = match priority
    High if not done -> "urgent"
    High -> "high (done)"
    Medium -> "normal"
    Low -> "deferrable"

stdio.println("got ${match x { 0 -> \"zero\", _ -> \"nonzero\" }}")
```

> **WHY NOT IF-AS-EXPRESSION LIKE RUST**
>
> The choice to keep `if` as a statement goes against the more recent trend in language design. The justification is pedagogical: Capa's target audience comes from Python and JavaScript, where `if` is a statement. The if-as-expression construct demands additional care in ergonomics (last expression as value) that adds a subtle rule. Capa prefers the simple rule of a dedicated ternary.

### 5.11 Patterns

Patterns are used in `let`, in `for`, and in `match`. The syntax is uniform across the three contexts.

```ebnf
pattern = literal_pattern
        | wildcard_pattern
        | binding_pattern
        | tuple_pattern
        | ctor_pattern
        | struct_pattern

literal_pattern = INT_LIT | FLOAT_LIT | STRING_LIT | CHAR_LIT | BOOL_LIT

wildcard_pattern = "_"

binding_pattern = IDENT

tuple_pattern = "(" pattern { "," pattern } [ "," ] ")"

ctor_pattern = qualified_name [ "(" [ pattern { "," pattern } ] ")" ]

struct_pattern = qualified_name "{" field_pattern { "," field_pattern }
    [ "," "..." ] "}"

field_pattern = IDENT [ ":" pattern ]

(* Or-patterns are only valid at the match-arm level, not as nested
   patterns. See the match_arm production in 5.10. *)
match_arm_pattern = pattern { "|" pattern }
```

Notes. A `binding_pattern` (a single identifier) binds the value to the name throughout the scope of the match arm or `let`. The wildcard `_` matches any value without binding anything.

Or-patterns at match-arm level (`A | B | C -> body`) match if *any* alternative matches. The analyzer enforces two consistency rules at the binding level:

- Every alternative must bind exactly the same set of names.
- Each shared name must have a compatible type across all alternatives.

`Add(n) | Sub(n) | Mul(n) -> n` is valid (every alternative binds `n: Int`). `Some(x) | None -> ...` is rejected (`None` does not bind `x`). `AsInt(x) | AsStr(x) -> ...` is rejected (the types of `x` differ).

### 5.12 Expressions

Expressions are presented in layers, from lowest precedence to highest. This form avoids ambiguities and enables direct implementation by a recursive descent parser.

#### 5.12.1 Generic expression

```ebnf
expression = lambda_expr
           | ternary_expr

lambda_expr = "fun" "(" [ param_list ] ")" [ "->" type ] "=>" lambda_body

lambda_body = expression                  (* single-expression body *)
            | NEWLINE INDENT { statement } DEDENT   (* block body *)
```

Notes. The leading `fun` keyword makes lambdas trivially distinguishable from `paren_expr` — the parser does not need lookahead or backtracking (this supersedes the older Python-style `(params) -> expr` form). The return-type annotation is optional and inferred from the body when omitted.

The block body shape allows multi-statement closures with explicit `return`:

```capa
let log = fun (x: Int) -> Int =>
    stdio.println("got ${x}")
    return x * 10
```

Closures capture their lexical environment. Captured capabilities are *borrowed* (the analyzer rejects `consume` on a capture, since a closure may run multiple times but a capability may only be consumed once — the same distinction as Rust's `Fn` vs `FnOnce`). Capabilities accepted as parameters of the closure itself are not captures and may be consumed.

#### 5.12.2 Ternary expression and logical operators

```ebnf
ternary_expr = if_expr
             | or_expr

if_expr = "if" or_expr "then" expression "else" expression

or_expr = and_expr { "or" and_expr }

and_expr = not_expr { "and" not_expr }

not_expr = "not" not_expr
         | compare_expr
```

The ternary `if cond then e1 else e2` is the only form of "if as expression" in Capa. The `then` keyword is the disambiguator: an `if` followed by an indented block is a statement (Section 5.10); an `if` followed by `then` is an expression. Both `then` and `else` are required (there is no one-sided expression form).

```capa
let cat = if n > 0 then "+" else if n < 0 then "-" else "0"
```

The else-branch may itself be another `if_expr`, giving the natural right-associative chaining shown above.

#### 5.12.3 Comparisons and arithmetic

```ebnf
compare_expr = add_expr [ compare_op add_expr ]

compare_op = "==" | "!=" | "<" | "<=" | ">" | ">="

add_expr = mul_expr { ( "+" | "-" ) mul_expr }

mul_expr = unary_expr { ( "*" | "/" | "%" ) unary_expr }

unary_expr = ( "-" | "+" ) unary_expr
           | postfix_expr
```

Comparisons in Capa do not chain: `1 < x < 10` is a syntax error (because `<` is not associative under this grammar). To chain, write `1 < x and x < 10`. This restriction avoids subtle ambiguities.

#### 5.12.4 Postfix: calls, indexing, access

```ebnf
postfix_expr = primary_expr { postfix_op }

postfix_op = "." IDENT                   (* field / method access *)
           | "(" [ arg_list ] ")"        (* function call *)
           | "[" expression "]"          (* indexing *)
           | "?"                          (* Result propagation *)

arg_list = argument { "," argument } [ "," ]

argument = [ IDENT ":" ] expression      (* optional name *)
```

Named arguments (in the spirit of Swift and Kotlin) allow a function to be called by passing arguments by name instead of by position: `f(name: "Ana", age: 30)`. Version 1.0 allows mixing positional and named, with positional first.

#### 5.12.5 Primary expressions

```ebnf
primary_expr = literal_expr
             | ident_expr
             | paren_expr
             | tuple_expr
             | list_expr
             | map_expr
             | struct_expr
             | block_expr

literal_expr = INT_LIT | FLOAT_LIT | STRING_LIT | CHAR_LIT
             | BOOL_LIT | UNIT_LIT

ident_expr = qualified_name

paren_expr = "(" expression ")"

tuple_expr = "(" expression "," ")"                          (* 1-tuple *)
           | "(" expression "," expression
               { "," expression } [ "," ] ")"

list_expr = "[" [ expression { "," expression } [ "," ] ] "]"

map_expr = "{" [ map_entry { "," map_entry } [ "," ] ] "}"

map_entry = expression ":" expression

struct_expr = qualified_name "{" struct_init
    { "," struct_init } [ "," ] "}"

struct_init = IDENT ":" expression
            | ".." expression                                (* spread *)

block_expr = block                                            (* block as expression; value = last expression *)
```

Relevant notes. The distinction between `paren_expr` and `tuple_expr` is made by the presence of a comma: `(x)` is an expression in parentheses, `(x,)` is a one-element tuple. This convention is identical to Python's and Rust's.

The ambiguity between `map_expr` (map literal with braces) and `block_expr` (block with braces) is resolved by the parser by context: braces are interpreted as a map when they appear in expression position and contain at least one `map_entry`, and as a block otherwise. Details in Section 7.2.

### 5.13 Documentation comments

Documentation comments (`///` for a line, `/** ... */` for a block) are syntactically comments — the lexer recognises them. But, unlike normal comments, they are preserved and associated with the immediately following declaration. The syntactic grammar does not model them explicitly; the parser attaches them to the AST as metadata.

> **Not in 1.0.** The lexer currently treats `///` and `/**` exactly like regular line/block comments and discards them. Reservation of the syntax is deliberate so that future versions can attach doc strings to declarations without breaking source compatibility.

---

## 6. Operator Precedence and Associativity

The grammar in Chapter 5 encodes precedence through stratification of the rules (`or_expr` → `and_expr` → `not_expr` → ...). This section presents the complete precedence table for quick reference, and explicitly enumerates the associativities.

### 6.1 Precedence table

The table is ordered from lowest precedence (at the top, binding most loosely) to highest (at the bottom, binding most tightly).

| Level | Operators | Associativity |
|---|---|---|
| 1 (lowest) | `if-else` (ternary) | Right |
| 2 | `or` | Left |
| 3 | `and` | Left |
| 4 | `not` (unary) | — |
| 5 | `==`  `!=`  `<`  `<=`  `>`  `>=` | Non-associative |
| 6 | `+`  `-`  (binary) | Left |
| 7 | `*`  `/`  `%` | Left |
| 8 | `+`  `-`  (unary) | Right |
| 9 (highest) | `.`  `()`  `[]`  `?`  (postfix) | Left |

### 6.2 Notes on associativity

- **Non-associativity of comparisons:** `1 < x < 10` does not compile in Capa. This decision avoids the confusion between the Python interpretation (implicit chaining) and the C interpretation (left-to-right evaluation of `bool` type). To chain, use `and` explicitly.
- **Right associativity of the ternary:** `a if c1 else b if c2 else d` associates as `a if c1 else (b if c2 else d)`. This is the convention of Python and most languages.
- **Postfix as a sequence:** `obj.method(arg)[0]?` applies left-to-right: `((obj.method(arg))[0])?`.

### 6.3 The `?` operator (Result propagation)

The `?` operator deserves specific mention. When applied to an expression of type `Result<T, E>`, it unwraps `Ok(T)` (yielding the value `T`) or immediately returns from the enclosing function with `Err(E)`. Syntactically, `?` is a postfix at precedence level 9, binding more tightly than any binary operator.

Example: `read(path)?.parse()?` evaluates `read(path)`, applies `?`, then accesses the `parse` method, and applies `?` again. Each `?` can cause an early return from the function.

---

## 7. Resolved Ambiguities

This section documents the points in the grammar where a naïve reading could produce more than one derivation, and the rule adopted to resolve the ambiguity. Each case is presented with an example, the correct derivation, and the justification.

### 7.1 Dangling else

The classical case: in `if x if y A else B`, does the `else` clause bind to the inner `if` or the outer one? Capa resolves this ambiguity trivially because `if` is a statement and uses significant indentation: the indentation level of the `else` determines which `if` it belongs to. There can be no ambiguity.

```capa
// else binds to the inner if
if x
    if y
        A
    else
        B

// else binds to the outer if
if x
    if y
        A
else
    B
```

### 7.2 Braces: block vs. map literal

In expression position, `{ ... }` may be interpreted as a map literal (a list of `key: value` pairs) or as a block. The rule is the following:

- If the content of the braces is empty (`{}`), it is an empty map literal.
- If the first significant token inside the braces is an `expression` followed by `:`, it is a map literal.
- Otherwise, it is a block expression.

This rule is decidable with two-token lookahead, satisfying the LL(2) parser implementation constraint.

### 7.3 `<` and `>` as comparison or type args

In `Vec<Int>`, the symbols `<` and `>` delimit type arguments. In `x < y`, they are comparison operators. The distinction depends on the syntactic context:

- In type position (after `let x:`, after `->`, inside another `type_args`), `<` opens `type_args`.
- In expression position, `<` is a comparison operator. The exception is when preceded by a `qualified_name` and followed by a `type` — in that case the parser considers the possibility of an explicit generic function call `f<Int>(x)`.

The solution adopted is the turbofish, in the Rust spirit: to force interpretation as type arguments in an expression, use `::<T>`. This convention is visually strange but avoids the need for unlimited backtracking in the parser.

```capa
// No ambiguity: we are in type position
let xs: List<Int> = []

// Ambiguous without turbofish (the parser first tries as comparison)
let result = parse::<Int>("42")
```

### 7.4 One-element tuple vs. expression in parentheses

Already mentioned in 5.12.5: the comma resolves it. `(x)` is an expression; `(x,)` is a one-element tuple. This convention is unambiguous and is directly encoded in the grammar.

### 7.5 Lambda vs. paren_expr

In the current grammar there is no ambiguity: a lambda always starts with the `fun` keyword (`fun (params) -> Ret => body`), and a parenthesised expression starts with `(`. The two are trivially distinguishable with a single-token lookahead.

This is a deliberate design choice over a Python-style `(params) -> expr` lambda — which would force the parser into backtracking (every `(` could start either a paren expression or a lambda, and you only know at the closing `)` followed by `->`). Reusing the `fun` keyword keeps lookahead constant.

### 7.6 Inline match vs. struct literal as scrutinee

The inline form `match X { ... }` collides syntactically with the struct-literal heuristic (`PascalCaseIdent { field: value, ... }`). Without intervention, the parser would read `match Color { Red -> 1 }` as `match (Color { Red -> 1 })` — a match whose scrutinee is a struct literal whose first field name is `Red` — and then fail at the `->`.

The rule adopted is the same one Rust uses for its `if`/`while`/`match` scrutinees: while parsing the scrutinee of a `match`, the struct-literal heuristic is **suppressed**. Inside that window, a PascalCase identifier followed by `{` always opens inline match arms, never a struct literal.

To use a struct literal as the scrutinee, wrap it in parentheses:

```capa
// Inline match against a variant constant
let s = match Red { Red -> "r", Green -> "g", Blue -> "b" }

// Match against a struct literal — parens force struct-literal interpretation
match (Point { x: 1.0, y: 2.0 })
    Point { x, y } -> stdio.println("${x}, ${y}")
```

This restriction only applies in the scrutinee position. Struct literals work normally everywhere else, including inside arm bodies and inside the match's argument expression once parentheses are present.

---

## 8. Annotated Example Program

This chapter presents a complete Capa program, with a progressive derivation through the rules of the grammar. The program is deliberately compact but exercises the most frequent constructs: type declarations, functions, traits, capabilities, control flow, patterns, and effectful expressions.

### 8.1 The program

```capa
// task_manager.capa — canonical example to illustrate the grammar

type Priority =
    Low
    Medium
    High

type Task {
    id: Int,
    title: String,
    priority: Priority,
    completed: Bool
}

trait Persistable
    fun save(self, fs: Fs, path: String) -> Result<Unit, IoError>
    fun load(fs: Fs, path: String) -> Result<Self, IoError>

impl Persistable for Task
    fun save(self, fs: Fs, path: String) -> Result<Unit, IoError>
        return fs.write(path, self.title)

    fun load(fs: Fs, path: String) -> Result<Task, IoError>
        let content = fs.read(path)?
        return Ok(Task {
            id: 0,
            title: content,
            priority: Low,
            completed: false
        })

fun classify_urgency(t: Task) -> String
    return match t.priority
        High if not t.completed -> "urgent"
        High -> "high (completed)"
        Medium -> "normal"
        Low -> "deferrable"

fun main(stdio: Stdio)
    let tasks = [
        Task { id: 1, title: "Review paper", priority: High, completed: false },
        Task { id: 2, title: "Buy bread", priority: Low, completed: false }
    ]
    for t in tasks
        let urgency = classify_urgency(t)
        stdio.println("${t.title}: ${urgency}")
```

### 8.2 Line-by-line syntactic analysis

The following is, in compact form, the derivation of the most relevant elements of the program in terms of the grammar rules.

Lines 3-6 declare a sum type: `type_decl` with `sum_body`. The production is `"type" IDENT sum_body`, where `sum_body` begins with `"=" NEWLINE INDENT` followed by three `sum_variant`s (`Low`, `Medium`, `High`), each without `variant_payload`.

Lines 8-13 declare a struct: `type_decl` with `struct_body`. The syntactic difference between the two is that `sum_body` begins with `"="` and `struct_body` begins with `"{"`. The parser distinguishes them with a single lookahead token.

Lines 15-17 declare a trait with two `function_signature`s (no body, ending in `NEWLINE`). The `load` function does not have a `self` parameter and has `Self` in its return type — a feature indicating an associated function on the type (not an instance method).

Lines 19-29 are an `impl_decl` that satisfies the `Persistable` trait for the `Task` type. Each function in the body is a complete `function_decl`. Line 24 (`let content = fs.read(path)?`) illustrates the `?` operator applied to the return of a postfix call — the inferred return type of the enclosing function (`Result<Task, IoError>`) is what makes the propagation well-typed.

Lines 31-36 declare a function `classify_urgency` whose body is a single `return match` (a `return_stmt` whose value is a `match_stmt` derived as an expression). Note the guard on the first arm (`High if not t.completed -> ...`): the syntax allows matches to be filtered by an additional condition, with no need to nest an `if` inside the block.

Lines 38-44 declare the function `main` with the `Stdio` capability. The body illustrates a multi-line list literal, a `for_stmt` with a single identifier pattern, and string interpolation. Note that `main` does not take `Fs` here even though the impl block uses it — the must-use rule (Capability Flow, layer v2) would reject an unused capability parameter. Capabilities only travel down through the call graph as they are actually needed.

### 8.3 Token sequence (summary)

For the first ten significant tokens of the `main` function, the sequence produced by the lexer is:

```
KEYWORD("fun")
IDENT("main")
PUNCT("(")
IDENT("fs")
PUNCT(":")
IDENT("Fs")
PUNCT(",")
IDENT("stdio")
PUNCT(":")
IDENT("Stdio")
PUNCT(")")
NEWLINE
INDENT
...
```

---

## Appendix A — Complete List of Reserved Words

The following words are reserved by the Capa 1.0 language and cannot be used as identifiers in any context.

| Word | Category | Status |
|---|---|---|
| `fun` | Function declaration | In use |
| `type` | Type declaration | In use |
| `trait` | Trait declaration | In use |
| `impl` | Implementation | In use |
| `capability` | Capability declaration | In use |
| `const` | Constant | In use |
| `pub` | Public visibility | In use |
| `import` | Module import | In use |
| `as` | Import alias | In use |
| `let` | Immutable binding | In use |
| `var` | Mutable binding | In use |
| `if` | Conditional | In use |
| `then` | Ternary `if-then-else` discriminator | In use |
| `elif` | Chained conditional | In use |
| `else` | Alternative | In use |
| `match` | Pattern matching | In use |
| `while` | Conditional iteration | In use |
| `for` | Iteration over collection | In use |
| `in` | Iteration operator | In use |
| `break` | Loop exit | In use |
| `continue` | Next iteration | In use |
| `return` | Function return | In use |
| `true` | Boolean literal | In use |
| `false` | Boolean literal | In use |
| `and` | Logical conjunction | In use |
| `or` | Logical disjunction | In use |
| `not` | Logical negation | In use |
| `self` | Current instance | In use |
| `Self` | Type of the current instance | In use |
| `consume` | Ownership-transfer parameter qualifier | In use |
| `async` | Asynchronous function | Reserved for future use |
| `await` | Awaiting a future | Reserved for future use |
| `yield` | Generators | Reserved for future use |
| `defer` | Deferred execution | Reserved for future use |
| `where` | Type constraints | Reserved for future use |
| `mut` | Explicit mutability | Reserved for future use |

---

## Appendix B — Complete List of Operators and Punctuation

The following tokens are recognised by the lexer using the maximal munch rule. The "Notes" column indicates how ambiguous sequences are disambiguated.

| Symbol | Category | Notes |
|---|---|---|
| `+` | Arithmetic / unary | Binary addition or unary plus |
| `-` | Arithmetic / unary | Binary subtraction or unary minus |
| `*` | Arithmetic | Multiplication |
| `/` | Arithmetic | Division |
| `%` | Arithmetic | Remainder |
| `==` | Comparison | Equality |
| `!=` | Comparison | Inequality |
| `<` | Comparison / type args | Resolved by context |
| `<=` | Comparison | Less than or equal |
| `>` | Comparison / type args | Resolved by context |
| `>=` | Comparison | Greater than or equal |
| `=` | Assignment | In `assign_stmt` |
| `+=` | Compound assignment | `x += y` is sugar for `x = x + y` |
| `-=` | Compound assignment | Analogous |
| `*=` | Compound assignment | Analogous |
| `/=` | Compound assignment | Analogous |
| `%=` | Compound assignment | Analogous |
| `->` | Structural | Return type; match arm |
| `=>` | Structural | Lambda body separator (`fun (...) -> R => body`) |
| `?` | Postfix | Result propagation |
| `..` | Structural | Spread in patterns and structs |
| `\|` | Pattern separator | Or-pattern alternatives in match arms |
| `.` | Structural | Field / method access; module path |
| `,` | Punctuation | Separator in lists, args, fields |
| `:` | Punctuation | Type annotation; map entry |
| `;` | Reserved | No use in 1.0; reserved |
| `(` | Delimiter | Opens param/arg list, paren expr, lambda |
| `)` | Delimiter | Closes the above |
| `[` | Delimiter | Opens list, indexing |
| `]` | Delimiter | Closes the above |
| `{` | Delimiter | Opens struct/map/block |
| `}` | Delimiter | Closes the above |
| `_` | Wildcard | In patterns; identifier allowed if not isolated |

---

— End of document —
