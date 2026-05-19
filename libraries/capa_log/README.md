# capa-log

Levelled logging on top of the `Stdio` capability. A function
that takes `log: Logger` declares only that authority; the
underlying stream and filtering are invisible past the factory
that built the logger.

## Status

v0.1 (seed library). The surface covers what a typical program
needs to filter and emit log records. Out of scope for v1: file
output, timestamps, structured fields (key/value pairs), JSON
output, multi-sink fan-out.

## Quick start

```capa
import capa_log.log
import capa_log.stdio_logger

fun greet(log: Logger, name: String)
    log.info("hello, ${name}")

fun main(stdio: Stdio)
    let log = make_stdio_logger(stdio, INFO)
    greet(log, "world")
```

Output:
```
[INFO] hello, world
```

The full runnable example is [`example.capa`](./example.capa);
it demonstrates default vs verbose loggers and every level.

## API surface

### Levels (from `capa_log.log`)

```capa
pub const DEBUG: Int = 0
pub const INFO:  Int = 1
pub const WARN:  Int = 2
pub const ERROR: Int = 3

pub fun level_name(level: Int) -> String
```

### Capability (from `capa_log.log`)

```capa
pub capability Logger
    fun log(self, level: Int, message: String) -> Unit
    fun debug(self, message: String) -> Unit
    fun info(self, message: String) -> Unit
    fun warn(self, message: String) -> Unit
    fun error(self, message: String) -> Unit
```

### Stdio implementor (from `capa_log.stdio_logger`)

```capa
pub type StdioLogger { stdio: Stdio, min_level: Int }

pub fun make_stdio_logger(stdio: Stdio, min_level: Int) -> StdioLogger
pub fun make_verbose_logger(stdio: Stdio) -> StdioLogger

impl Logger for StdioLogger
```

`min_level` is the lowest level that prints. Records strictly
below `min_level` are dropped. Use `make_verbose_logger` as a
shorthand for `make_stdio_logger(stdio, DEBUG)`.

## How it works

The library is two files. `log.capa` defines the capability and
the level constants; nothing in it touches I/O. `stdio_logger.capa`
defines the concrete implementor, a cap-bearing struct
(`StdioLogger { stdio: Stdio, min_level: Int }`) whose `impl Logger`
performs the actual `stdio.println` call.

Format is fixed in v1: `[LEVEL] message`. A v2 iteration would
add a configurable formatter or a structured-field API.

## Audit claim

The library declares no capabilities at the surface. A program
using capa-log shows the following manifest signal:

```
make_stdio_logger:   ['Stdio']
make_verbose_logger: ['Stdio']
level_name:          []
StdioLogger.log:     ['Logger']
StdioLogger.debug:   ['Logger']
StdioLogger.info:    ['Logger']
StdioLogger.warn:    ['Logger']
StdioLogger.error:   ['Logger']

run_pipeline:        ['Logger']    (uses log.info / log.warn / log.error)
main:                ['Stdio']     (constructs the logger, calls run_pipeline)
```

The handover happens in `make_stdio_logger`: that single
function takes `Stdio` and returns a value typed only by
`Logger`. Application code past that boundary never sees `Stdio`.

## Honest limitations (v1)

- **No timestamps**. A log line is `[LEVEL] message`, nothing
  more. Adding wall-clock timestamps would require a `Clock`
  field on the implementor; planned for v2.
- **No file or network sinks**. Only `StdioLogger` exists.
  Writing a `FileLogger` is straightforward (same shape with
  `fs: Fs` and a `path: String`); not in v1.
- **No structured records**. Messages are `String`. A future
  iteration could accept `Map<String, JsonValue>` for JSON
  output.
- **Single global format**. The `[LEVEL] message` format is
  hard-coded in `StdioLogger.log`. No `format` callback hook.
- **No level objects**. Levels are bare `Int` constants; this
  keeps the surface small but means there is no compiler-
  enforced way to stop a caller passing `42` as a level.
