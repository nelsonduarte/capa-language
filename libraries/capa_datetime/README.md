# capa-datetime

Pure-Capa datetime decomposition, formatting, and parsing.
Zero capabilities. Operates on `Float` seconds-since-Unix-epoch
(UTC), which is exactly what Capa's built-in `Clock.now_secs()`
returns. A caller that wants the current year asks `Clock` for
the current time, then passes the result through this library.

## Status

v0.1 (seed library). The surface covers the decomposition,
format, and parse operations a typical program needs. Out of
scope for v1: time zones (everything is UTC), leap seconds,
fractional seconds in formatted output, pre-1970 dates.

## Quick start

```capa
import capa_datetime.datetime

fun main(stdio: Stdio, clock: Clock)
    let now = clock.now_secs()
    stdio.println("now is ${format_iso8601(now)}")

    let c = to_components(now)
    stdio.println("it is the year ${c.year}")
```

The full runnable example is [`example.capa`](./example.capa);
it shows decomposition, round-trip through components, ISO 8601
parsing (success + failure), and a live read from `Clock`.

## API surface

### Types (from `capa_datetime.datetime`)

```capa
pub type Components {
    year: Int,
    month: Int,    // 1-12
    day: Int,      // 1-31
    hour: Int,     // 0-23
    minute: Int,   // 0-59
    second: Int    // 0-59 (no leap seconds)
}

pub type ParseError =
    InvalidFormat(String)
```

### Functions

- `pub fun to_components(secs: Float) -> Components`
- `pub fun from_components(c: Components) -> Float`
- `pub fun format_iso8601(secs: Float) -> String`
  &nbsp;&nbsp;Returns `"YYYY-MM-DDTHH:MM:SSZ"`.
- `pub fun format_date(secs: Float) -> String`
  &nbsp;&nbsp;Returns `"YYYY-MM-DD"`.
- `pub fun format_time(secs: Float) -> String`
  &nbsp;&nbsp;Returns `"HH:MM:SS"`.
- `pub fun parse_iso8601(s: String) -> Result<Float, ParseError>`
  &nbsp;&nbsp;Accepts the basic form `YYYY-MM-DDTHH:MM:SSZ` exactly.

## How it works

`to_components` uses Howard Hinnant's days-from-civil algorithm
in reverse (proleptic Gregorian, pure integer math). The
implementation runs entirely in Capa: no Python boundary, no
external library, no Unsafe.

The time-of-day fields are extracted from the seconds count by
straightforward modular arithmetic.

`from_components` is the inverse: Hinnant's civil-from-days
algorithm forward, plus the time-of-day reconstitution.

`format_*` are simple string interpolation over the
decomposed Components, with zero-padded `pad2`/`pad4` helpers.

`parse_iso8601` is a fixed-position parser: the input string
must be exactly 20 characters and match the layout
`YYYY-MM-DDTHH:MM:SSZ` character-for-character. Each numeric
field is extracted by `substring` and validated via
`parse_int`. Any deviation returns `InvalidFormat` with a
positional message pointing at the offending byte.

## Audit claim

The library declares no capabilities. A program using
capa-datetime declares only the capabilities its other code
needs:

```
to_components:   []
from_components: []
format_iso8601:  []
format_date:     []
format_time:     []
parse_iso8601:   []
show_timestamp:  ['Stdio']   (example helper)
main:            ['Stdio', 'Clock']
```

The `Clock` in `main` is there because the example asks for
the current time; a program that operates on stored
timestamps would not need it.

## Honest limitations (v1)

- **Everything is UTC**. There is no timezone awareness. A
  caller in Lisbon adds 3600 seconds manually if it wants
  local-time output during summer.
- **No leap seconds**. The second field is 0-59; UTC's
  occasional 23:59:60 is collapsed into 23:59:59.
- **Pre-1970 dates do not work correctly**. The Hinnant
  reverse pass assumes a non-negative days-since-epoch. Pass
  in a negative `secs` and you will get nonsensical
  Components. This is a known limitation; a v2 iteration
  would gate the input on `secs >= 0` or extend the algorithm
  to the floor-div case.
- **No fractional seconds in formatted output**. The
  components struct drops sub-second precision; the
  millisecond / microsecond fields a future iteration would
  add are out of scope here.
- **ISO 8601 parsing is strict-form-only**. The basic shape
  `YYYY-MM-DDTHH:MM:SSZ` is the only one accepted. No
  fractional seconds, no offsets other than `Z`, no
  date-only form, no extended-vs-basic toggle.
