/**
 * @name Probe: does points-to track the handler values at all
 * @kind table
 * @id capa/probe-subscript
 */

import python
import semmle.python.objects.ObjectAPI

// For each Value that is a reference somewhere, report references that
// land on the `handler` name or the HANDLERS subscript in dispatch.
from Value v, ControlFlowNode ref, string what
where
  ref = v.getAReference() and
  (
    ref.(NameNode).getId() = "handler" and what = "handler-var-ref"
    or
    ref.(NameNode).getId() = "HANDLERS" and what = "HANDLERS-ref"
    or
    ref instanceof SubscriptNode and what = "subscript-ref"
  )
select what, ref.getLocation().getStartLine() as line, v.toString() as value
