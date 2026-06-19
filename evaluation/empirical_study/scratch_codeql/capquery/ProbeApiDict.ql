/**
 * @name Probe: does the dataflow/API graph resolve dict-value calls
 * @kind table
 * @id capa/probe-api-dict
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

// For each call in dispatch, what callable does the new dataflow call
// graph resolve the called function to?
from DataFlow::CallCfgNode call, string caller, string resolved
where
  caller = call.getScope().getName() and
  caller in ["dispatch", "run_action", "emit", "run_pipeline"] and
  (
    exists(Function f | call.getFunction().asExpr() = f.getDefinition() and resolved = "df:" + f.getName())
    or
    not exists(Function f | call.getFunction().asExpr() = f.getDefinition()) and resolved = "df:NONE"
  )
select caller, call.getLocation().getStartLine() as line, resolved
