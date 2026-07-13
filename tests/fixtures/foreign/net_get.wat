(module
  (import "capa:host/net" "get"
    (func $get (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "ERR")
  (global $bump (mut i32) (i32.const 1024))
  (func $realloc (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bump i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bump local.get $p)
  ;; Call net.get(handle, url) and marshal result<string, io-error> to a
  ;; plain returned string -- the Ok body on success, the literal "ERR"
  ;; marker on the Err arm. The handle is ignored by the host closure (it
  ;; uses the captured attenuated cap).
  (func $fetch (export "fetch") (param $uptr i32) (param $ulen i32) (result i32)
    (local $area i32) (local $ret i32) (local $sptr i32) (local $slen i32)
    ;; 20-byte return area for result<string, io-error>.
    (local.set $area (call $realloc (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 20)))
    (call $get (i32.const 0) (local.get $uptr) (local.get $ulen) (local.get $area))
    (if (i32.eqz (i32.load8_u (local.get $area)))
      (then
        (local.set $sptr (i32.load offset=4 (local.get $area)))
        (local.set $slen (i32.load offset=8 (local.get $area))))
      (else
        (local.set $sptr (i32.const 8))
        (local.set $slen (i32.const 3))))
    (local.set $ret (call $realloc (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $ret) (local.get $sptr))
    (i32.store offset=4 (local.get $ret) (local.get $slen))
    (local.get $ret)))
