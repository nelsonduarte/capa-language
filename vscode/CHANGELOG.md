# Changelog

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
