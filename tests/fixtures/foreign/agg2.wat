(module
  ;; NESTED-aggregate foreign child (feature #4 F2c-2). Each export
  ;; echoes / reconstructs its argument through the canonical ABI so a
  ;; wrong host-side Capa-heap offset corrupts the observed round trip.
  ;; The child only ever sees the canonical-ABI representation; the
  ;; Capa-heap <-> Python marshalling lives entirely on the parent host.
  ;; 200 pages (12.8 MiB) of static linear memory: enough for the ``gen``
  ;; export to build a large list IN THE CHILD so the resulting write-back
  ;; into a TIGHTLY-capped parent memory is what OOMs (a clean host error),
  ;; not the child. The bump allocator never calls memory.grow, so the
  ;; declared size is the child's whole heap.
  (memory (export "memory") 200)
  (global $bp (mut i32) (i32.const 1024))
  (func $ra (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bp i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bp local.get $p)

  ;; list-point(list<point>) -> list<point>: echo the (data_ptr, len)
  ;; pair. Each element is a 32-byte canonical point record; the adapter
  ;; re-reads the element array from the returned pointer.
  (func $list_point (export "list-point") (param $ptr i32)(param $len i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $ptr))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; bag-echo(bag) -> bag. bag canonical record (size 32):
  ;;   items: list<s64>  ptr@0,  len@4
  ;;   name:  string     ptr@8,  len@12
  ;;   tag:   option<s64> disc@16, payload@24
  (func $bag_echo (export "bag-echo")
      (param $ip i32)(param $il i32)(param $np i32)(param $nl i32)
      (param $td i32)(param $tv i64)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 32)))
    (i32.store          (local.get $r)(local.get $ip))
    (i32.store offset=4  (local.get $r)(local.get $il))
    (i32.store offset=8  (local.get $r)(local.get $np))
    (i32.store offset=12 (local.get $r)(local.get $nl))
    (i32.store offset=16 (local.get $r)(local.get $td))
    (i64.store offset=24 (local.get $r)(local.get $tv))
    (local.get $r))

  ;; list-pair(list<tuple<s64,string>>) -> echo. Element = 16-byte
  ;; canonical tuple (s64@0, string ptr@8, len@12).
  (func $list_pair (export "list-pair") (param $ptr i32)(param $len i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $ptr))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; list-list(list<list<s64>>) -> echo. Element = 8-byte (ptr,len).
  (func $list_list (export "list-list") (param $ptr i32)(param $len i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $ptr))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; deep(list<option<list<point>>>) -> echo.
  (func $deep (export "deep") (param $ptr i32)(param $len i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $ptr))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; opt-point(option<point>) -> option<point>. WIT option: none=0, some=1.
  ;; arg flatten: disc i32, x i64, flag i32, ratio f64, lp i32, ll i32.
  ;; return canonical (size 40): disc@0, point@8 (x@8,flag@16,ratio@24,lp@32,ll@36).
  (func $opt_point (export "opt-point")
      (param $d i32)(param $x i64)(param $flag i32)(param $ratio f64)
      (param $lp i32)(param $ll i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 40)))
    (i32.store (local.get $r)(local.get $d))
    (if (local.get $d)
      (then
        (i64.store offset=8  (local.get $r)(local.get $x))
        (i32.store offset=16 (local.get $r)(local.get $flag))
        (f64.store offset=24 (local.get $r)(local.get $ratio))
        (i32.store offset=32 (local.get $r)(local.get $lp))
        (i32.store offset=36 (local.get $r)(local.get $ll))))
    (local.get $r))

  ;; res-point(result<point,string>) -> result<point,string>. WIT
  ;; result: ok=0, err=1. arg flatten (joined slots):
  ;;   disc i32, s0 i64, s1 i32, s2 f64, s3 i32, s4 i32
  ;;   Ok(point): s0=x, s1=flag, s2=ratio, s3=lp, s4=ll
  ;;   Err(string): s0=ptr (zero-extended), s1=len
  ;; return canonical (size 40): disc@0; Ok point@8; Err string ptr@8,len@12.
  (func $res_point (export "res-point")
      (param $d i32)(param $s0 i64)(param $s1 i32)(param $s2 f64)
      (param $s3 i32)(param $s4 i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 40)))
    (i32.store (local.get $r)(local.get $d))
    (if (i32.eqz (local.get $d))
      (then
        (i64.store offset=8  (local.get $r)(local.get $s0))
        (i32.store offset=16 (local.get $r)(local.get $s1))
        (f64.store offset=24 (local.get $r)(local.get $s2))
        (i32.store offset=32 (local.get $r)(local.get $s3))
        (i32.store offset=36 (local.get $r)(local.get $s4)))
      (else
        (i32.store offset=8  (local.get $r)(i32.wrap_i64 (local.get $s0)))
        (i32.store offset=12 (local.get $r)(local.get $s1))))
    (local.get $r))

  ;; shape-echo(shape) -> shape. variant shape { dot, circle(s64),
  ;; label(string), rect(tuple<s64,s64>) }. arg flatten (joined):
  ;;   disc i32, s0 i64, s1 i64
  ;;   circle(n): disc=1, s0=n
  ;;   label(str): disc=2, s0=ptr, s1=len
  ;;   rect(a,b): disc=3, s0=a, s1=b
  ;; return canonical (size 24): disc@0, payload@8.
  (func $shape_echo (export "shape-echo")
      (param $d i32)(param $s0 i64)(param $s1 i64)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 24)))
    (i32.store (local.get $r)(local.get $d))
    (if (i32.eq (local.get $d)(i32.const 1))
      (then (i64.store offset=8 (local.get $r)(local.get $s0)))
      (else (if (i32.eq (local.get $d)(i32.const 2))
        (then
          (i32.store offset=8  (local.get $r)(i32.wrap_i64 (local.get $s0)))
          (i32.store offset=12 (local.get $r)(i32.wrap_i64 (local.get $s1))))
        (else (if (i32.eq (local.get $d)(i32.const 3))
          (then
            (i64.store offset=8  (local.get $r)(local.get $s0))
            (i64.store offset=16 (local.get $r)(local.get $s1))))))))
    (local.get $r))

  ;; gen(n) -> list<s64>: [0, 1, ..., n-1]. Used to force a large but
  ;; bounded parent write-back (memory-cap OOM surfaces as WasmHostError).
  (func $gen (export "gen") (param $n i64)(result i32)
    (local $len i32)(local $data i32)(local $i i32)(local $r i32)
    (local.set $len (i32.wrap_i64 (local.get $n)))
    (local.set $data (call $ra (i32.const 0)(i32.const 0)(i32.const 8)
      (i32.mul (local.get $len)(i32.const 8))))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i)(local.get $len)))
      (i64.store (i32.add (local.get $data)(i32.mul (local.get $i)(i32.const 8)))
        (i64.extend_i32_u (local.get $i)))
      (local.set $i (i32.add (local.get $i)(i32.const 1)))(br $l)))
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $data))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; mk-gadget(code, active) -> gadget: construct a canonical gadget
  ;; record (code@0, active@8, size 16). On the PARENT side Gadget
  ;; implements a multi-impl trait, so the host writes an 8-byte
  ;; trait-dispatch header + type-id in front of the fields (the WRITE-back
  ;; path for has_header; the child neither sees nor cares about it).
  (func $mk_gadget (export "mk-gadget") (param $code i64)(param $active i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 16)))
    (i64.store (local.get $r)(local.get $code))
    (i32.store offset=8 (local.get $r)(local.get $active))
    (local.get $r)))
