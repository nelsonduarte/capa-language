# Phase 2 design: CommentMap attachment pass

Phase 2 of the Capa formatter v3 (AST round-trip with comment
preservation). Phase 1 (lexer comment sidecar) landed
2026-05-26. Phase 2 builds the comment-to-AST attachment pass.
Phase 3 (pretty-printer consuming the CommentMap) is scoped
out of this document.

## Intro

Phase 1 gave the Lexer a sidecar `self.comments: list[Comment]`
containing every plain `//` and `/* */` comment, with `Pos`
start+end and raw `text` ([capa/tokens.py](../capa/tokens.py),
[capa/lexer/_comments.py](../capa/lexer/_comments.py)). Doc
comments (`///`, `/**`) are unaffected: they still flow as
`DOC_COMMENT` tokens and are attached by the existing
`_consume_doc_comments_opt` path
([capa/parser/_items.py](../capa/parser/_items.py)). The token
stream the parser sees is identical to v1.

Phase 2 builds a `CommentMap`: a side-table that ties each
`Comment` to a position in the AST, so the Phase 3 pretty-
printer can re-emit comments in the right place during an
AST round-trip. The design below assumes the AST is the one
produced today by `Parser(...).parse_module()`, no new fields
on `Node`, and the existing convention of `dict[int, X]` keyed
by `id(node)` already used by analyzer/transpiler.

## 1. Comment categories

Three categories, decided per comment by a single linear pass
over the sorted token stream and the sorted comment list:

- **Trailing**: there is at least one non-NEWLINE token T whose
  `T.end.line == comment.start.line` AND
  `T.end.offset <= comment.start.offset`. In other words: code
  exists on the same line BEFORE the comment opener. The owner
  is the AST node that token T belongs to (resolved in 2).
- **Standalone**: the comment is alone on its line(s) (no code
  before it on its starting line; nothing else on the lines it
  spans). Owner: "the next statement / item" (the first AST
  node whose `pos.offset > comment.end.offset`).
- **Floating**: a standalone comment for which there is no next
  AST node at the same or deeper enclosing scope before the
  enclosing block / module ends. Owner: the enclosing `Block`
  or `Module`, attached as a trailing comment on that
  container.

The rule for trailing-vs-standalone is purely positional:
trailing iff
`prev_token is not None and prev_token.end.line == comment.start.line and prev_token.kind not in {NEWLINE, INDENT, DEDENT}`.
For block comments that span multiple lines, the relevant
`prev_token` is the most recent code token whose `end.line`
matches the comment's `start.line`; this naturally handles
`x = 1 /* aside */ + 2` (trailing on the `1`) and
`/* doc-style\n   block */ fun foo()` (standalone before
`fun`).

## 2. Attachment anchor

Every comment attaches to exactly one AST node. The "owner" is
chosen by walking up from the precise positional match to the
smallest node that fully contains the natural emission point.
Concretely:

- **Standalone before a top-level item** (`fun foo()`,
  `type Foo`, `import X`): owner is the `Item` itself, slot
  `leading`. A run of consecutive standalone comments separated
  by no blank line collapses into one ordered list of comments
  on the same owner.
- **Standalone before a statement inside a block**: owner is
  the `Stmt`, slot `leading`. The "section-divider" `// =====`
  blocks attach as `leading` on the following `FunDecl`.
- **Standalone at the very top of a file**, before any item:
  owner is the `Module`, slot `leading`.
- **Standalone at the end of a `Block` with no following
  statement** (final comment in a function body): owner is the
  `Block`, slot `trailing`. Same rule for the end of `Module`.
- **Trailing on a `let`/`var`/`return`/assign/expression
  line**: owner is the `Stmt`, slot `trailing`.
- **Trailing on the header line of `if`/`while`/`for`/`fun`/
  `type`/`impl`**: owner is the compound node itself, slot
  `trailing_header`. A separate slot is needed because the
  pretty-printer emits the header and the body separately, and
  a comment on `fun foo() // exposed` must land at the end of
  the header line, not before the body.
- **Mid-expression block comments** (the only mid-expression
  form that survives lexing, see 4): owner is the smallest
  containing `Expr` node, slot `interior`. Phase 3 may collapse
  interior comments to a single trailing emission on the
  parent statement; that decision is deferred but the
  structural slot is reserved now so we do not lose data.

**Storage shape**: a separate `CommentMap` object keyed by
`id(node)`, NOT new fields on `Node`. Three reasons. First, it
matches the existing `analyzer.types: dict[int, Ty]` and
`transpiler.types: dict[int, Ty]` pattern, so a developer who
knows one side-table knows them all. Second, it leaves every
existing equality/test that compares synthetic-AST-to-parsed-
AST untouched (adding a field would change `__eq__`/`dump`
output, breaking the analyzer test corpus). Third, the
formatter is the only consumer; the side-table can be discarded
once Phase 3 emits.

```
@dataclass
class AttachedComments:
    leading: list[Comment] = field(default_factory=list)
    trailing: list[Comment] = field(default_factory=list)
    trailing_header: list[Comment] = field(default_factory=list)
    interior: list[Comment] = field(default_factory=list)

class CommentMap:
    def __init__(self) -> None:
        self._by_id: dict[int, AttachedComments] = {}
    def get(self, node: Node) -> AttachedComments | None: ...
    def set(self, node: Node, slot: str, comment: Comment) -> None: ...
```

## 3. Algorithm

Inputs: `tokens: list[Token]` (Phase-1 unchanged),
`comments: list[Comment]` (already in source order, the lexer
appends as it consumes), `module: A.Module`.

```
build(module, tokens, comments) -> CommentMap:
  1. Build a flat, source-ordered list of (node, kind) for every AST
     node, computed by one recursive walk. Each entry records
     (pos.offset, end.offset, node, role). end.offset for a node is
     the offset of the last token consumed by that node (we already
     have it implicitly via the next sibling's pos.offset; for the
     last child we use the parent's end). Stored once in a NodeIndex.
  2. Walk `comments` in order. For each comment c:
     a. Binary-search the token list for the largest token T with
        T.end.offset <= c.start.offset. Decide trailing vs standalone
        using rule (1).
     b. If trailing: binary-search NodeIndex for the smallest node
        whose [pos.offset, end.offset] contains T.end.offset. Walk up
        to the enclosing Stmt or Item; that is the owner. Slot is
        `trailing` (or `trailing_header` if the owner is a compound
        node and the comment line equals the header line).
     c. If standalone: binary-search NodeIndex for the smallest node
        whose pos.offset > c.end.offset (next-node lookup). Slot is
        `leading`. If no such node exists at the enclosing scope, walk
        up to the enclosing Block / Module and set slot `trailing`
        (this is the floating case).
  3. Return the CommentMap.
```

Complexity: building NodeIndex is O(N) in AST nodes. Each
comment costs one binary search over tokens (O(log T)) and one
over the NodeIndex (O(log N)), plus a constant-bounded walk up
to the enclosing Stmt/Item. Total:
**O((T + N) + C log(T + N))**, which is the linear target up
to log factors and far cheaper than re-parsing.

## 4. Special cases

- **Mid-expression `//`**: rejected by the parser today
  (line comment forces NEWLINE; parser fails on missing RHS).
  Safe to assume CommentMap never sees a well-formed AST that
  contains a mid-expression line comment.
- **Mid-expression `/* */`**: accepted. The block comment is
  in `lexer.comments` but does NOT appear in the token stream.
  CommentMap classifies it as trailing on the containing
  `Expr` via slot `interior`.
- **Start of file, no preceding token**: any comment with
  `start.offset < tokens[0].end.offset` and standalone
  classification attaches to the `Module` `leading`.
- **End of file, no following token**: standalone comments
  after the last item attach to the `Module` `trailing`. If
  the last item is a `FunDecl` and the comment sits at the
  same indentation as a body statement, it attaches to the
  `Block` `trailing` of that function body, not the Module.
- **Doc comments (`///`, `/**`)**: already consumed via
  `_consume_doc_comments_opt` and stored as
  `doc: Optional[str]` on each item. CommentMap does NOT see
  them because they are `TokenKind.DOC_COMMENT`, not entries
  in `self.comments`. The two paths are disjoint by
  construction; nothing to coordinate.

## 5. API

**Location**: `capa/formatter/_comments.py`, inside a new
`capa/formatter/` package. Phase 1+2+3 will exceed the
700-line single-file ceiling stated in the project style
note, so the natural seam is to promote `capa/formatter.py`
to `capa/formatter/__init__.py` and split:

- `__init__.py` (entry points: `format_source`,
  `is_formatted`)
- `_lines.py` (v1+v2 line-level pipeline)
- `_comments.py` (this phase)
- `_emit.py` (Phase 3 pretty-printer)

The CommentMap is a formatter-internal artefact; it does not
belong in `capa/lexer/` (the lexer should not know about AST
nodes) or at the top level (no other consumer).

**Public surface**:

```python
# capa/formatter/_comments.py
from capa import capa_ast as A
from capa.tokens import Comment, Token

@dataclass
class AttachedComments: ...

class CommentMap:
    def __init__(self) -> None: ...
    def get(self, node: A.Node) -> AttachedComments | None: ...
    def __contains__(self, node: A.Node) -> bool: ...
    def __iter__(self): ...

def build_comment_map(
    module: A.Module,
    tokens: list[Token],
    comments: list[Comment],
) -> CommentMap:
    """Attach every plain comment to its owning AST node."""
```

The class plus free factory function mirrors
`Lexer(...).lex()` / `Parser(...).parse_module()`. The class
is useful so Phase 3 can pass the map around as one value;
the free function is the only construction path (no
incremental mutation API), which keeps Phase 2 testable in
isolation.

## 6. Testability

Minimum unit-test set (in `tests/test_comment_map.py`):

1. **Module leading**: file that begins with a comment block,
   asserts those comments live on `Module.leading` and the
   first item has no leading comments.
2. **Item leading (section divider)**: `// ====\nfun foo()`
   shape, asserts attach to the `FunDecl`.
3. **Stmt trailing**: `let x = 1  // increment`, asserts
   owner is the `LetStmt`, slot `trailing`.
4. **Block floating**: function whose last body line is a
   comment with no following statement, asserts owner is the
   body `Block`, slot `trailing`.
5. **Compound header trailing**: `if cond  // checked once\n
   body`, asserts owner is the `IfStmt`, slot
   `trailing_header`, NOT leading on the first body stmt.
6. **Module trailing**: comment at end-of-file after the last
   item, asserts owner is the `Module`, slot `trailing`.
7. **Interior block comment**:
   `let x = 1 /* aside */ + 2`, asserts owner is the `BinOp`
   (or its `left`), slot `interior`.
8. **Doc comments are not in the map**: file with both
   `/// doc` on a `fun foo` and a plain `// note` before it
   asserts the doc lands in `FunDecl.doc` (existing
   behaviour) and only the plain comment lands in
   CommentMap.

A round-trip stub test ("CommentMap has exactly
`len(lexer.comments)` entries; every Comment appears in
exactly one slot") is also worth adding as a structural
invariant.

## 7. Risk and unknowns

The "nearest enclosing node" lookup for standalone comments
before a top-level item that itself has a doc comment.
A file like

```
// section divider
/// real doc for foo
fun foo()
    ...
```

needs the `// section divider` to attach as `leading` on
`FunDecl foo` (so the pretty-printer emits it BEFORE the
doc), while `/// real doc for foo` stays in `FunDecl.doc`.
The risk: the algorithm in (3) will see the next AST node as
`FunDecl.pos`, which points at `fun`, not at the doc
comment, so the `// section divider` could be misclassified
as standalone-with-no-target and get pushed onto the
`Module`. De-risk: include this exact shape as a 9th unit
test, and have `build_comment_map` adjust the next-node
offset for `FunDecl`/`TypeStruct`/`TypeSum`/`TraitDecl` to
the position of their first `DOC_COMMENT` token if one
preceded the keyword (look it up in the token stream). The
adjustment is mechanical (one helper that scans backwards
from the item's `pos.offset` through DOC_COMMENT tokens) and
isolated to the comment-map builder; getting it wrong only
breaks formatter output, not semantics. Adding this test up
front prevents Phase 3 from being designed around a wrong
assumption.

## Phase 2 verification (empirical findings from probes)

- Mid-expression `//` is rejected by the parser today (line
  comment forces NEWLINE; parser fails on missing RHS).
- Mid-expression `/* */` IS accepted; the block comment is
  in `lexer.comments` but invisible to the parser.
  CommentMap must handle it (`interior` slot).
- Trailing line comments on statement lines pass cleanly
  through lex+parse.
