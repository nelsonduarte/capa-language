(module
  (import "capa:host/fs" "read"
    (func $read (param i32 i32 i32 i32)))
  (import "capa:host/fs" "restrict-to"
    (func $restrict (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "ERR")
  (data (i32.const 16) "/")
  (global $bump (mut i32) (i32.const 1024))
  (func $realloc (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bump i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bump local.get $p)
  ;; Shared body: call fs.read(handle, path) and marshal result<string,
  ;; io-error> to a plain returned string -- the Ok bytes on success,
  ;; the literal "ERR" marker on the Err arm.
  (func $do_read (param $pptr i32) (param $plen i32) (result i32)
    (local $area i32) (local $ret i32) (local $sptr i32) (local $slen i32)
    ;; 20-byte return area for result<string, io-error>.
    (local.set $area (call $realloc (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 20)))
    ;; handle is ignored by the host closure (captured attenuated cap).
    (call $read (i32.const 0) (local.get $pptr) (local.get $plen) (local.get $area))
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
    (local.get $ret))
  (func $read_it (export "read-it") (param $pptr i32) (param $plen i32) (result i32)
    (call $do_read (local.get $pptr) (local.get $plen)))
  ;; Attempt to WIDEN the grant first: ask the host for a fresh handle
  ;; rooted at "/" via restrict-to, then read. The host closure returns
  ;; a dummy 0 handle and ignores it, so this cannot widen past the
  ;; caller's attenuated Fs -- an out-of-prefix path is still denied.
  (func $widen_read (export "widen-read") (param $pptr i32) (param $plen i32) (result i32)
    (drop (call $restrict (i32.const 0) (i32.const 16) (i32.const 1)))
    (call $do_read (local.get $pptr) (local.get $plen))))
