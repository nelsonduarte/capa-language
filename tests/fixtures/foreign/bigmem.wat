(module
  (memory (export "memory") 5000)
  (func (export "run") (param $x i64) (result i64) local.get $x))
