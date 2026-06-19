/**
 * @name Probe: what does the dispatcher call resolve to
 * @kind table
 * @id capa/probe-dispatch
 */

import python
import semmle.python.objects.ObjectAPI
import semmle.python.dataflow.new.DataFlow

// Every call node inside a function named "dispatch" / "run_action" /
// "emit" / "run_pipeline", and what points-to + dataflow think it calls.
from CallNode c, string caller, string resolved
where
  caller = c.getScope().getName() and
  caller in ["dispatch", "run_action", "emit", "run_pipeline"] and
  (
    exists(CallableValue cv | cv.getACall() = c and resolved = "pointsto:" + cv.getScope().getName())
    or
    not exists(CallableValue cv | cv.getACall() = c) and resolved = "pointsto:NONE"
  )
select caller, c.getLocation().getStartLine() as line, c.toString() as callnode, resolved
