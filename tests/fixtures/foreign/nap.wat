(module
  (import "capa:host/clock" "sleep" (func $sleep (param i32 f64)))
  (memory (export "memory") 1)
  (func (export "nap") (param $secs f64) (result i64)
    (call $sleep (i32.const 0) (local.get $secs))
    (i64.const 0)))
