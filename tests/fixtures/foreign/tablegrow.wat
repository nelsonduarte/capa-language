(module
  (memory (export "memory") 1)
  (table 1 funcref)
  (func (export "grow") (param $n i64) (result i64)
    (i64.extend_i32_s
      (table.grow 0 (ref.null func) (i32.wrap_i64 (local.get $n))))))
