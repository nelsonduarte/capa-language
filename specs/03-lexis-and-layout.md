# 03. Lexis, indentation and literals

> **What this chapter covers.** The lexical level: character set,
> comments, identifiers, the 41 reserved words, the literals
> (integers, floats, normal and raw strings, chars), string
> interpolation, the operator/punctuation tokens, and the indentation
> rules (NEWLINE/INDENT/DEDENT/EOF). An exact reference, traced to the
> lexer.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). The lexer sources are byte-identical between the
previous measurement commit (`1834554`) and `8e2c609` (verified with
`git diff`); every transcript was re-run at `8e2c609` on 2026-09-11,
`python -m capa` importing the checkout under specification. Primary
sources: [`capa/tokens.py`](../capa/tokens.py),
[`capa/lexer/_tokens.py`](../capa/lexer/_tokens.py),
[`capa/lexer/_literals.py`](../capa/lexer/_literals.py),
[`capa/lexer/_comments.py`](../capa/lexer/_comments.py),
[`capa/lexer/_indent.py`](../capa/lexer/_indent.py), and
[`Capa-EBNF.md`](../Capa-EBNF.md) chapters 3 and 4.

Depends on: [01-overview.md](01-overview.md).

---

## 1. The lexical pipeline

The lexer consumes the source text (UTF-8) and produces a token
sequence; the parser sees that sequence, not the original text. A
token's type is the `TokenKind` enum
([`capa/tokens.py`](../capa/tokens.py) line 18); each token carries
its `kind`, the exact `text`, an already-processed `value` (for
literals), and start/end positions (`Token`, line 222).

The CLI's default action on a file is to **print the token stream**.
The `--no-layout` flag omits the layout tokens
(NEWLINE/INDENT/DEDENT/EOF).

The token stream of a short program:

```capa
// tiny.capa
fun f(x: Int) -> Int
    if x < 0
        return 0
    return x
```

```
$ python -m capa tiny.capa
   2:1    KW_FUN          'fun'
   2:5    IDENT           'f'
   2:6    LPAREN          '('
   2:7    IDENT           'x'
   2:8    COLON           ':'
   2:10   IDENT           'Int'
   2:13   RPAREN          ')'
   2:15   ARROW           '->'
   2:18   IDENT           'Int'
   2:21   NEWLINE         '\n'
   3:1    INDENT          '    '
   3:5    KW_IF           'if'
   3:8    IDENT           'x'
   3:10   LT              '<'
   3:12   INT_LIT         '0'  → 0
   3:13   NEWLINE         '\n'
   4:1    INDENT          '        '
   4:9    KW_RETURN       'return'
   4:16   INT_LIT         '0'  → 0
   4:17   NEWLINE         '\n'
   5:1    DEDENT
   5:5    KW_RETURN       'return'
   5:12   IDENT           'x'
   5:13   NEWLINE         '\n'
   6:1    DEDENT
   6:1    EOF
```

Note the `→ 0` column: for an `INT_LIT`, the token carries the
already-converted value (`Token.value`).

## 2. Character set and identifiers

The source text is UTF-8. Comments and strings may contain any valid
Unicode codepoint. Identifiers are **not** restricted to ASCII in 1.0:
the lexer admits as a start any character for which Python's
Unicode-aware `str.isalpha` is true, or `_`; and as a continuation any
character accepted by `str.isalnum`, or `_`. This includes Unicode
letters (`café`, `año`, `π`).

Scope note. This is wider than the UAX #31 profile; a future version
may narrow it.

```ebnf
IDENT       = ident_start { ident_continue }
ident_start = ident_letter | "_"
```

Practical rules: a leading underscore is valid (`_x`) and by
convention signals intentional non-use; identifiers are
case-sensitive (`user` and `User` are distinct); an identifier cannot
equal a reserved word (section 4).

## 3. Comments

Four forms, handled in
[`capa/lexer/_comments.py`](../capa/lexer/_comments.py):

| Form | Start | End | Nestable | Effect |
|---|---|---|---|---|
| Line comment | `//` | end of line | n/a | discarded |
| Block comment | `/*` | `*/` | yes | discarded |
| Line doc | `///` | end of line | n/a | `DOC_COMMENT` token |
| Block doc | `/**` | `*/` | yes (outer pair) | `DOC_COMMENT` token |

Plain comments (`//`, `/* */`) are consumed by the lexer and never
reach the parser (they are kept in a `comments` sidecar the formatter
consults to preserve them). Block comments nest
(`_skip_block_comment`), which distinguishes them from C/Java.

Documentation comments are preserved: `///` emits a `DOC_COMMENT`
with one leading space stripped; `/** ... */` emits `DOC_COMMENT` with
the Javadoc-style `*` margin stripped. Important edge cases: `////`
(four or more slashes) and `/*` without the second star remain plain
comments and are discarded; `/**/` is still an ordinary empty comment
(the second position is `/`, not `*`). The parser attaches each
pending doc comment to the immediately following
`fun`/`type`/`trait`/`capability` or `impl` method; a doc comment not
followed by such a declaration is a parse error. The `--doc` generator
renders them.

## 4. Reserved words

The `KEYWORDS` table ([`capa/tokens.py`](../capa/tokens.py) line 152)
has **41 entries** (measured:
`python -c "from capa.tokens import KEYWORDS; print(len(KEYWORDS))"`
prints 41):

| Category | Words |
|---|---|
| Declarations | `fun` `type` `trait` `impl` `capability` `extern` `const` `pub` `import` `as` |
| Types/linearity | `linear` `typestate` `become` |
| Control flow | `if` `then` `elif` `else` `match` `while` `for` `in` `break` `continue` `return` |
| Bindings | `let` `var` |
| Capability discipline | `consume` `borrow` |
| Logical literals | `true` `false` |
| Logical operators | `and` `or` `not` |
| Self and types | `self` `Self` |
| Reserved, unused in 1.0 | `async` `await` `yield` `defer` `where` `mut` |

The last six (`async`, `await`, `yield`, `defer`, `where`, `mut`) are
recognized by the lexer but rejected by the parser, reserved for
future extensions. The other 35 are active in 1.0 (`consume` and
`borrow` are active parameter qualifiers; see
[08-functions-closures-modules.md](08-functions-closures-modules.md)
section 3).

A reserved word cannot be an identifier:

```capa
// resvw.capa
fun main(stdio: Stdio)
    let where = 3
    stdio.println("${where}")
```

```
$ python -m capa --check resvw.capa
resvw.capa:3:9: error: expected pattern, got KW_WHERE
   3 |     let where = 3
               ^
```

**Contextual keywords (not reserved).** The spellings `secret`,
`public` (flow labels after `@` in type position), `component`,
`from` (in `extern component`), and `uses` (the trait/capability
clause) are **not** in `KEYWORDS`: the lexer emits them as `IDENT` and
the parser recognizes them by position. They remain valid identifiers
elsewhere.

## 5. Literals

### 5.1 Integers (`INT_LIT`)

Four bases; underscores as visual separators (not at the start/end,
not doubled). The base marker is case-insensitive.

```ebnf
INT_LIT = dec_int | hex_int | oct_int | bin_int
dec_int = digit { digit | "_" }
hex_int = ( "0x" | "0X" ) hex_digit { hex_digit | "_" }
oct_int = ( "0o" | "0O" ) oct_digit { oct_digit | "_" }
bin_int = ( "0b" | "0B" ) bin_digit { bin_digit | "_" }
```

Capa's `Int` is signed 64-bit. The lexer checks the **magnitude**: the
literal scans the magnitude (the `-` is a separate unary operator),
and a magnitude strictly greater than `2**63` (the value of
`abs(i64::MIN)`) is rejected at lex time
([`capa/lexer/_literals.py`](../capa/lexer/_literals.py)). A decimal
literal with more than 19 digits is rejected by length before even
converting.

### 5.2 Floats (`FLOAT_LIT`)

```ebnf
FLOAT_LIT = dec_int "." digit { digit | "_" } [ exponent ]
          | dec_int exponent
exponent  = ( "e" | "E" ) [ "+" | "-" ] digit { digit | "_" }
```

A `.` only starts the fractional part when followed by a digit;
`5.method()` reads `5` followed by `.method`.

### 5.3 Strings (`STRING_LIT`), normal and raw

Strings are immutable, UTF-8. **Normal** strings (`"..."`) interpret
escapes and recognize `${...}` interpolation. **Raw** strings
(`r"..."`) interpret nothing: backslashes are literal and `${...}` is
not interpolation. Both emit the same `TokenKind.STRING_LIT` (there is
no separate raw kind). A raw string cannot contain `"`; use a normal
string with `\"` for that. The hash-delimited form `r#"..."#` does not
exist in 1.0.

Supported escapes: `\n` `\r` `\t` `\\` `\"` `\'` `\0` (NUL), and
`\u{HEX}` (1 to 6 hex digits, codepoint at most U+10FFFF). C-style
octal escapes (`\033`) and byte escapes (`\x1b`) do **not** exist; a
`\0` followed by a digit is rejected with a diagnostic pointing at
`\u{...}`; any other character after `\` is an "unknown escape
sequence" error.

Octal escape rejection:

```capa
// esc.capa
fun main(stdio: Stdio)
    stdio.println("\033[31m")
```

```
$ python -m capa --check esc.capa
esc.capa:3:22: error: octal escape '\03...' is not supported; use '\u{HEX}' for arbitrary code points, or '\0' alone for NUL
   3 |     stdio.println("\033[31m")
                            ^
```

Unknown escape:

```
$ python -m capa --check esc2.capa      # body: stdio.println("\q")
esc2.capa:3:21: error: unknown escape sequence: \q
```

### 5.4 Chars (`CHAR_LIT`)

```ebnf
CHAR_LIT = "'" ( char_char | escape_seq ) "'"
```

A `Char` is a Unicode codepoint, not a byte: `'a'`, `'\n'`,
`'\u{1F600}'`.

### 5.5 Booleans and Unit

There is no `BOOL_LIT`: `true` and `false` are the keywords
`KW_TRUE` / `KW_FALSE` ([`capa/tokens.py`](../capa/tokens.py) line
72). The Unit value `()` is not a literal token either: it is
`LPAREN` followed by `RPAREN`.

### 5.6 String interpolation

A normal string admits `${ expression }`: the expression is evaluated
and formatted in place. The lexer records the position of the first
character inside each `${` so diagnostics about errors inside the
interpolation point at the right source. A value without a
`to_string` method cannot be interpolated (measured in
[09-expressions-and-control.md](09-expressions-and-control.md)
section 7).

Literals and interpolation, run on both backends:

```capa
// lits.capa
fun main(stdio: Stdio)
    let dec = 1_000_000
    let hex = 0xFF
    let oct = 0o755
    let bin = 0b1010
    let f = 6.022e23
    let s = "tab\there, newline next\nx=${dec}"
    let r = r"raw \n not escaped ${dec}"
    let c = '\u{1F600}'
    let b = true
    stdio.println("dec=${dec} hex=${hex} oct=${oct} bin=${bin}")
    stdio.println("f=${f}")
    stdio.println(s)
    stdio.println(r)
    stdio.println("char=${c} bool=${b}")
```

```
$ python -m capa --run lits.capa
dec=1000000 hex=255 oct=493 bin=10
f=6.022e+23
tab	here, newline next
x=1000000
raw \n not escaped 1000000
char=😀 bool=true
$ python -m capa --run --wasm lits.capa
dec=1000000 hex=255 oct=493 bin=10
f=6.022e+23
tab	here, newline next
x=1000000
raw \n not escaped 1000000
char=😀 bool=true
```

The two backends produce identical output, including the
exponent-formatted float (`6.022e+23`) and the codepoint outside the
BMP (`😀`).

## 6. Operators and punctuation

Recognized by maximal munch (the longest possible token). Full list in
the `TokenKind` of [`capa/tokens.py`](../capa/tokens.py).

| Category | Tokens |
|---|---|
| Arithmetic | `+` `-` `*` `/` `%` |
| Bitwise/shift (over `Int`) | `&` `^` `<<` `>>` (and `\|`, which also separates or-patterns) |
| Comparison | `==` `!=` `<` `<=` `>` `>=` |
| Assignment | `=` `+=` `-=` `*=` `/=` `%=` |
| Structural | `.` `,` `:` `;` `->` `=>` `?` `..` `..=` `@` |
| Delimiters | `( )` `[ ]` `{ }` |
| Special | `_` (isolated wildcard), `\|` (or-pattern) |

There are no `&&`, `||`, `!`: the logical connectives are the words
`and`, `or`, `not` (a design decision, `Capa-EBNF.md` section 3.6).
The bitwise-over-`Int` operators exist as `&`, `|`, `^`, `<<`, `>>`.
The `;` is reserved (token `SEMI`) but has no syntactic use in 1.0.

## 7. Whitespace and significant indentation

Capa uses significant indentation. The lexer synthesizes the layout
tokens ([`capa/lexer/_indent.py`](../capa/lexer/_indent.py)).

### 7.1 Start of line

The sequence of **spaces** (and only spaces) at the start of a logical
line determines its indentation level. **Tabs are forbidden** at the
start of a line: the lexer rejects the program. The convention is 4
spaces; any positive multiple is accepted, but the increment must be
consistent within the same block.

Leading-tab rejection:

```
$ python -m capa --check tabbed.capa      # line 2 starts with a TAB
tabbed.capa:2:1: error: tabs are not allowed at the start of a line; use spaces only (4 by convention)
   2 | 	stdio.println("x")
       ^
```

### 7.2 Logical line breaks

A physical break is a `NEWLINE`, with two exceptions:

- **Implicit continuation by delimiters**: a break inside a `( )`,
  `[ ]` or `{ }` pair produces no `NEWLINE`. This allows splitting
  lists, calls and long expressions across physical lines.
- **Explicit continuation by backslash**: a line ending in `\`
  immediately before the break continues on the next line.
  Discouraged, but supported.

Lines with only spaces or only comments produce no `NEWLINE`: they are
ignored, and they do not count for indentation either (a comment or
blank line in the middle of a block does not split it).

### 7.3 INDENT and DEDENT

After each `NEWLINE`, the lexer compares the next line's indentation
with the current level: equal produces no token; greater produces
`INDENT` (and pushes the level); smaller produces one or more
`DEDENT` (one per popped level) until it matches; if no level on the
stack matches exactly, it is an inconsistent-indentation error. At end
of file, the lexer produces the `DEDENT`s needed to empty the stack,
then an `EOF`. Unlike Python, **there is no `:`** between a block
header and the `INDENT`: a header on a `NEWLINE`, followed by the
`INDENT` that opens the block. See the token stream in section 1.

---

## Links

- [04-grammar.md](04-grammar.md): the syntactic grammar that consumes
  these tokens.
- [09-expressions-and-control.md](09-expressions-and-control.md): the
  precedence of section 6's operators.
- [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md): the
  contextual `@secret`/`@public` labels of section 4.
- [`Capa-EBNF.md`](../Capa-EBNF.md): the normative lexis (chapters 3
  and 4).
