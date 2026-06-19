/**
 * @name Capability reachability per function (Capa empirical study T2b)
 * @description For every function defined in the source, the set of
 *   capability axes (Fs/Net/Clock/Env/Random/Proc/Stdio) it can reach,
 *   computed as: the function itself contains a sink for the axis, OR
 *   any function transitively reachable from it through CodeQL's call
 *   graph reaches a sink for the axis. This is the good-faith dataflow
 *   treatment: it uses CodeQL's curated sink models (Concepts) for the
 *   axes CodeQL models, the API graph for the rest, and BOTH the
 *   points-to call graph and the dataflow-dispatch call graph for
 *   interprocedural propagation, so it resolves every call target
 *   CodeQL can resolve (including constant function tables via points-to).
 * @kind table
 * @id capa/capability-reachability
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.objects.ObjectAPI

/**
 * A call node resolved through the API graph for a given module member
 * (or any of several members). This is CodeQL's strongest name-based
 * resolution: it tracks the imported module/object through assignments
 * and aliases, not just lexical `module.attr(...)` text.
 */
private API::CallNode apiCall(string mod, string member) {
  result = API::moduleImport(mod).getMember(member).getACall()
}

private API::CallNode apiCallNested(string mod, string sub, string member) {
  result = API::moduleImport(mod).getMember(sub).getMember(member).getACall()
}

/**
 * Holds if `call` is a sink for capability `axis`. Uses CodeQL's curated
 * Concepts where they exist (Fs via FileSystemAccess, Net via
 * Http::Client::Request, Proc via SystemCommandExecution) UNIONED with
 * API-graph sinks for those axes and for the axes CodeQL has no concept
 * for (Clock/Env/Random/Stdio). Unioning the concept with explicit API
 * sinks only ever ADDS detections, never removes them, so it cannot
 * weaken the treatment.
 */
private predicate sinkCall(DataFlow::Node call, string axis) {
  // ---- Fs : filesystem access ----
  call instanceof FileSystemAccess and axis = "Fs"
  or
  call = API::builtin("open").getACall() and axis = "Fs"
  or
  call = apiCall("io", ["open"]) and axis = "Fs"
  or
  call = apiCall("os", ["walk", "listdir", "scandir", "remove", "mkdir",
                        "makedirs", "rmdir", "rename", "stat"]) and axis = "Fs"
  or
  exists(string m |
    m = ["read_text", "write_text", "read_bytes", "write_bytes", "open",
         "iterdir", "glob", "rglob", "mkdir", "unlink"] and
    call = API::moduleImport("pathlib").getMember("Path").getReturn().getMember(m).getACall()
  ) and axis = "Fs"
  or
  call = apiCall("shutil", ["copy", "copyfile", "copytree", "move", "rmtree"])
    and axis = "Fs"
  or
  call = apiCall("glob", ["glob", "iglob"]) and axis = "Fs"
  or
  // ---- Net : network access ----
  call instanceof Http::Client::Request and axis = "Net"
  or
  call = apiCallNested("urllib", "request", ["urlopen", "Request"]) and axis = "Net"
  or
  call = apiCall("socket", ["socket", "create_connection"]) and axis = "Net"
  or
  call = apiCall("http", ["client"]) and axis = "Net"
  or
  call = API::moduleImport("requests").getMember(["get", "post", "put",
            "delete", "head", "patch", "request"]).getACall() and axis = "Net"
  or
  call = API::moduleImport("httpx").getMember(["get", "post", "put",
            "delete", "head", "patch", "request"]).getACall() and axis = "Net"
  or
  // ---- Proc : subprocess / process spawning ----
  call instanceof SystemCommandExecution and axis = "Proc"
  or
  call = apiCall("subprocess", ["run", "call", "Popen", "check_call",
                                "check_output"]) and axis = "Proc"
  or
  call = apiCall("os", ["system", "popen", "execv", "execve", "spawnv"])
    and axis = "Proc"
  or
  // ---- Clock : wall clock / monotonic time / sleep ----
  call = apiCall("time", ["time", "monotonic", "perf_counter", "time_ns",
                          "localtime", "gmtime", "sleep"]) and axis = "Clock"
  or
  call = API::moduleImport("datetime").getMember("datetime")
            .getMember(["now", "utcnow", "today"]).getACall() and axis = "Clock"
  or
  // ---- Env : environment variables ----
  call = apiCall("os", ["getenv", "getenvb", "putenv"]) and axis = "Env"
  or
  // os.environ.get(...) / os.environ[...] -- the attribute read itself
  exists(DataFlow::Node environ |
    environ = API::moduleImport("os").getMember("environ").getAValueReachableFromSource() and
    call.asExpr().(Subscript).getObject() = environ.asExpr()
  ) and axis = "Env"
  or
  call = API::moduleImport("os").getMember("environ")
            .getMember(["get", "items", "keys", "values", "copy"]).getACall()
    and axis = "Env"
  or
  // ---- Random : CSPRNG / PRNG draws ----
  call = apiCall("secrets", ["choice", "token_hex", "token_bytes",
                             "token_urlsafe", "randbelow", "randbits"])
    and axis = "Random"
  or
  call = apiCall("random", ["random", "randint", "choice", "choices",
                            "shuffle", "sample", "uniform", "getrandbits"])
    and axis = "Random"
  or
  call = apiCall("os", ["urandom"]) and axis = "Random"
  or
  call = apiCall("uuid", ["uuid4", "uuid1"]) and axis = "Random"
  or
  // ---- Stdio : standard output ----
  call = API::builtin("print").getACall() and axis = "Stdio"
}

/**
 * A "real" named function: a `def`/method/lambda the call graph can
 * name and propagate through, as opposed to the synthetic scopes
 * CodeQL creates for comprehensions and generator expressions
 * (`genexpr`, `listcomp`, `setcomp`, `dictcomp`). A sink that sits
 * lexically inside a comprehension must be attributed to the enclosing
 * real function, because that is the unit the ground truth and the
 * call graph use (e.g. `secrets.choice(...) for _ in ...` inside
 * `_random_id`).
 */
private predicate isSyntheticScope(Function f) {
  f.getName() in ["genexpr", "listcomp", "setcomp", "dictcomp"]
}

/**
 * The nearest enclosing REAL named function of a sink call: start at
 * the sink's own scope and walk out over any synthetic comprehension
 * scopes until a real function is reached.
 */
private Function enclosingFunc(DataFlow::Node call) {
  exists(Scope s |
    (s = call.asExpr().getScope() or s = call.asCfgNode().getScope()) and
    result = s.getEnclosingScope*() and
    not isSyntheticScope(result) and
    // the first real function reached on the way out: every scope
    // strictly between `s` and `result` is synthetic.
    forall(Function mid |
      mid = s.getEnclosingScope*() and
      result = mid.getEnclosingScope+()
    |
      isSyntheticScope(mid)
    )
  )
}

/**
 * The interprocedural call-graph edge used for propagation. We take the
 * UNION of two of CodeQL's call resolvers to be maximally generous:
 *
 *  (1) the points-to call graph (`FunctionObject.getACallee`), which
 *      resolves a callee through points-to and therefore follows a
 *      constant function table `D = {"k": handler}; D[k]()` to its
 *      enumerated values; and
 *  (2) the dataflow-dispatch call graph (`DataFlow::Node.getACall` on
 *      the callable's calls), which resolves callees the dataflow engine
 *      can prove.
 *
 * `caller` directly calls `callee` if either resolver says so.
 */
private predicate callsDirect(Function caller, Function callee) {
  // (1) points-to call graph: a call node in `caller` whose callee
  // points to a CallableValue whose body is `callee`. Points-to
  // resolves the value through assignments and CONSTANT containers,
  // so `D = {"k": handler}; D[k](arg)` resolves to `handler` here.
  exists(CallNode c, CallableValue cv |
    c.getScope() = caller and
    cv.getACall() = c and
    cv.getScope() = callee
  )
  or
  // (2) dataflow-dispatch call graph: a call the dataflow engine
  // resolves to `callee`'s definition.
  exists(DataFlow::CallCfgNode c |
    c.getScope() = caller and
    c.getFunction().asExpr() = callee.getDefinition()
  )
}

/** A function reaches `axis` if it or a transitive callee hosts a sink. */
private predicate reaches(Function f, string axis) {
  exists(DataFlow::Node call |
    sinkCall(call, axis) and enclosingFunc(call) = f
  )
  or
  exists(Function callee |
    callsDirect(f, callee) and reaches(callee, axis)
  )
}

from Function f, string axis
where
  reaches(f, axis) and
  exists(f.getLocation().getFile().getRelativePath()) and
  f.getLocation().getFile().getRelativePath().matches("%naive.py")
select f.getName() as function, axis, f.getLocation().getStartLine() as line
