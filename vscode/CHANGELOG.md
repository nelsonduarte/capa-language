# Changelog

## 0.10.0

- Python-style automatic indentation. Pressing Enter after a block header
  now indents the next line. The previous `indentationRules` were too
  loose: the increase pattern was anchored with `^.*`, so any line that
  merely contained a keyword (`fun`, `if`, `for`, `type`, `match`, ...)
  anywhere, including inside string literals, inline lambdas, one-line
  `if ... then ... else` expressions, and identifiers that happen to
  contain a keyword as a substring, would indent the following line. The
  decrease pattern was a blank line, which made no sense.
- The increase pattern is now anchored to the start of the line (after
  the current indentation and an optional `pub `) and only fires on real
  block headers: a named `fun` definition (not a `fun (...)` lambda), a
  `type` struct or sum-type opener, `impl` / `trait` / `capability` /
  `typestate` / `linear`, the `if` / `elif` / `else` / `while` / `for` /
  `match` statements (and `return` / `let` match-expressions), a
  `match` arm whose body is on the next line (the line ends with `->`),
  and a multi-line lambda whose body starts on the next line (the line
  ends with `=>`). One-line `if ... then ... else` expressions and inline
  lambdas (which carry their body after `=>` on the same line) no longer
  trigger indentation. The `if` / `elif` / `while` / `for` exclusion of
  one-line `then` expressions now ignores a `then` that appears only
  inside a `//` line comment.
- The decrease pattern now aligns `else` and `elif` back to their `if`
  instead of keying off blank lines.

## 0.9.0

- The extension now ships the Capa logo as its marketplace icon
  (the hooded figure), shown in the VSCode extensions list.
- `.capa` files now display the Capa icon in the explorer when the
  active icon theme supports language icons (the default VSCode theme
  does). A purple-on-transparent variant is used for the dark theme and
  a higher-contrast purple variant for the light theme.

## 0.8.0

- Highlight the typestate, information-flow, linearity, and
  constant-time surface: `typestate`, `linear`, and `become` keywords,
  the `declassify` built-in, and the `@strict_ifc` / `@constant_time`
  attributes plus the `@secret` / `@public` information-flow labels.
- First VSCode Marketplace release.

## 0.7.0

- TextMate grammar for the core language: keywords, primitive types,
  built-in capabilities and generic types, variant constructors,
  built-in functions, literals (with `${...}` interpolation), operators,
  and reserved-for-future keywords.
