(module
  ;; NESTED-aggregate cap child (feature #4 F2c-2): proves the host-bound
  ;; Net is the caller's ATTENUATED cap AND that a cap coexists with
  ;; NESTED aggregate marshalling. Imports capa:host/net only.
  (import "capa:host/net" "allows" (func $allows (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "example.com")
  (global $bump (mut i32) (i32.const 1024))
  (func $realloc (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bump i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bump local.get $p)
  ;; submit(list<list<s64>>) -> s64: sum of every inner element +
  ;; (allows("example.com") ? 1000 : 0). Outer element stride 8 (each
  ;; inner list is an 8-byte (ptr, len) pair).
  (func $submit (export "submit") (param $ptr i32)(param $len i32)(result i64)
    (local $i i32)(local $j i32)(local $acc i64)
    (local $ip i32)(local $il i32)
    (block $do (loop $lo
      (br_if $do (i32.ge_u (local.get $i)(local.get $len)))
      (local.set $ip (i32.load (i32.add (local.get $ptr)(i32.mul (local.get $i)(i32.const 8)))))
      (local.set $il (i32.load offset=4 (i32.add (local.get $ptr)(i32.mul (local.get $i)(i32.const 8)))))
      (local.set $j (i32.const 0))
      (block $di (loop $li
        (br_if $di (i32.ge_u (local.get $j)(local.get $il)))
        (local.set $acc (i64.add (local.get $acc)
          (i64.load (i32.add (local.get $ip)(i32.mul (local.get $j)(i32.const 8))))))
        (local.set $j (i32.add (local.get $j)(i32.const 1)))(br $li)))
      (local.set $i (i32.add (local.get $i)(i32.const 1)))(br $lo)))
    (if (call $allows (i32.const 0)(i32.const 8)(i32.const 11))
      (then (local.set $acc (i64.add (local.get $acc)(i64.const 1000)))))
    (local.get $acc)))
