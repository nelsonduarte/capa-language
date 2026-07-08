(module
  (memory (export "memory") 1)
  (func (export "run") (param $x i64) (result i64)
    (loop $l br $l) unreachable))
