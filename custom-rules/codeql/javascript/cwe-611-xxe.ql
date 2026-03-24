/**
 * @name XML External Entity (XXE) Injection
 * @description Detects XML parsing without disabling external entities
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id js/cwe-611-xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import javascript
import semmle.javascript.security.dataflow.XxeQuery
import DataFlow::PathGraph

from Xxe::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "XXE vulnerability due to $@.", source.getNode(),
  "user-provided value"
