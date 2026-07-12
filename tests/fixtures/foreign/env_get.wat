(module
  (import "capa:host/env" "get"
    (func $get (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "MISSING")
  (global $bump (mut i32) (i32.const 1024))
  (func $realloc (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bump i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bump local.get $p)
  ;; Call env.get(handle, name) and marshal option<string> to a plain
  ;; returned string: the value on Some, the literal "MISSING" on None
  ;; (a denied key looks like an unset variable, per the Env contract).
  (func $get_env (export "get-env") (param $nptr i32) (param $nlen i32) (result i32)
    (local $area i32) (local $ret i32) (local $sptr i32) (local $slen i32)
    ;; 12-byte return area for option<string>.
    (local.set $area (call $realloc (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 12)))
    ;; handle is ignored by the host closure (captured attenuated cap).
    (call $get (i32.const 0) (local.get $nptr) (local.get $nlen) (local.get $area))
    (if (i32.eq (i32.load8_u (local.get $area)) (i32.const 1))
      (then
        (local.set $sptr (i32.load offset=4 (local.get $area)))
        (local.set $slen (i32.load offset=8 (local.get $area))))
      (else
        (local.set $sptr (i32.const 8))
        (local.set $slen (i32.const 7))))
    (local.set $ret (call $realloc (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $ret) (local.get $sptr))
    (i32.store offset=4 (local.get $ret) (local.get $slen))
    (local.get $ret)))
