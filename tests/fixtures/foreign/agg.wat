(module
  (memory (export "memory") 1)
  (global $bp (mut i32) (i32.const 1024))
  (func $ra (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    global.get $bp i32.const 7 i32.add i32.const -8 i32.and local.set $p
    local.get $p local.get 3 i32.add global.set $bp local.get $p)

  ;; bump-point(point) -> point
  ;; arg flatten: x:i64, flag:i32, ratio:f64, label:(ptr i32,len i32)
  ;; return point memory: x@0, flag@8, ratio@16, label.ptr@24, label.len@28 (size 32)
  (func $bump_point (export "bump-point")
      (param $x i64)(param $flag i32)(param $ratio f64)(param $lp i32)(param $ll i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 32)))
    (i64.store (local.get $r)(i64.add (local.get $x)(i64.const 1)))
    (i32.store offset=8 (local.get $r)(i32.eqz (local.get $flag)))
    (f64.store offset=16 (local.get $r)(f64.add (local.get $ratio)(f64.const 1)))
    (i32.store offset=24 (local.get $r)(local.get $lp))
    (i32.store offset=28 (local.get $r)(local.get $ll))
    (local.get $r))

  ;; list-inc(list<s64>) -> list<s64>: each +1
  (func $list_inc (export "list-inc") (param $ptr i32)(param $len i32)(result i32)
    (local $i i32)(local $data i32)(local $r i32)
    (local.set $data (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.mul (local.get $len)(i32.const 8))))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i)(local.get $len)))
      (i64.store (i32.add (local.get $data)(i32.mul (local.get $i)(i32.const 8)))
        (i64.add (i64.load (i32.add (local.get $ptr)(i32.mul (local.get $i)(i32.const 8))))(i64.const 1)))
      (local.set $i (i32.add (local.get $i)(i32.const 1)))(br $l)))
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $data))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; list-tag(list<string>) -> list<string>: pass through (echo)
  ;; string element stride 8 (ptr@0, len@4)
  (func $list_tag (export "list-tag") (param $ptr i32)(param $len i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $ptr))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; list-not(list<bool>) -> list<bool>: negate each; element stride 1
  (func $list_not (export "list-not") (param $ptr i32)(param $len i32)(result i32)
    (local $i i32)(local $data i32)(local $r i32)
    (local.set $data (call $ra (i32.const 0)(i32.const 0)(i32.const 1)(local.get $len)))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i)(local.get $len)))
      (i32.store8 (i32.add (local.get $data)(local.get $i))
        (i32.eqz (i32.load8_u (i32.add (local.get $ptr)(local.get $i)))))
      (local.set $i (i32.add (local.get $i)(i32.const 1)))(br $l)))
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 4)(i32.const 8)))
    (i32.store (local.get $r)(local.get $data))
    (i32.store offset=4 (local.get $r)(local.get $len))
    (local.get $r))

  ;; tup-bump(tuple<s64,string>) -> tuple<s64,string>: n+1, echo string
  ;; return memory: n@0, string.ptr@8, string.len@12 (size 16)
  (func $tup_bump (export "tup-bump") (param $n i64)(param $sp i32)(param $sl i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 16)))
    (i64.store (local.get $r)(i64.add (local.get $n)(i64.const 1)))
    (i32.store offset=8 (local.get $r)(local.get $sp))
    (i32.store offset=12 (local.get $r)(local.get $sl))
    (local.get $r))

  ;; opt-inc(option<s64>) -> option<s64>: Some(x)->Some(x+1); None->None
  ;; arg flatten: disc i32, payload i64. return memory: disc@0, payload@8 (size 16)
  (func $opt_inc (export "opt-inc") (param $disc i32)(param $val i64)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 16)))
    (i32.store (local.get $r)(local.get $disc))
    (i64.store offset=8 (local.get $r)(i64.add (local.get $val)(i64.const 1)))
    (local.get $r))

  ;; res-inc(result<s64,string>) -> result<s64,string>: Ok(x)->Ok(x+1); Err echo
  ;; arg flatten: disc i32, joined i64, errl i32
  ;; return memory: disc@0; Ok s64@8; Err string ptr@8, len@12 (size 16)
  (func $res_inc (export "res-inc") (param $disc i32)(param $j i64)(param $errl i32)(result i32)
    (local $r i32)
    (local.set $r (call $ra (i32.const 0)(i32.const 0)(i32.const 8)(i32.const 16)))
    (i32.store (local.get $r)(local.get $disc))
    (if (i32.eqz (local.get $disc))
      (then (i64.store offset=8 (local.get $r)(i64.add (local.get $j)(i64.const 1))))
      (else
        (i32.store offset=8 (local.get $r)(i32.wrap_i64 (local.get $j)))
        (i32.store offset=12 (local.get $r)(local.get $errl))))
    (local.get $r))

  ;; sum-hdr(gadget) -> s64: code + (active?1:0)
  (func $sum_hdr (export "sum-hdr") (param $code i64)(param $active i32)(result i64)
    (i64.add (local.get $code)(i64.extend_i32_u (i32.and (local.get $active)(i32.const 1))))))
