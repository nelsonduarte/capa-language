# config_loader

The 12-factor microservice config-loading pattern.

## What the library does

Loads application configuration in three layers:

1. Read a base JSON file from disk (Fs).
2. Overlay any `APP_*` environment variables on top (Env).
3. If the result has a `flags_url`, fetch a remote feature-flag
   patch and merge it (Net).

Exposes a single public function with the signature
`load_config(path: str) -> dict`.

## Authority surface

`Fs + Env + Net` exercised inside one function; signature
declares none of them.

## Why representative

This exact pattern appears in essentially every cloud-deployed
Python service that does config layering: read a base file,
overlay environment, optionally pull remote toggles. The
naive shape conflates three capabilities under one
`load_config(path)` name; an auditor reading the signature
cannot tell which authorities the function exercises.

The Capa transliteration splits the same logic into five
functions (`parse_config_text`, `has_field`, `set_field`,
`load_local_config`, `apply_env_overrides`,
`fetch_remote_overrides`, `load_full_config`, `main`) and
declares the capability of each in its parameter list.

This pair is the headline example documented in
[`docs/empirical_micro.md`](../../../docs/empirical_micro.md).
The copy under this study harness is identical to
`examples/empirical_config_naive.py` +
`examples/empirical_config.capa`; carrying it inside the
study layout lets the aggregate harness include it without
special-casing the path.
