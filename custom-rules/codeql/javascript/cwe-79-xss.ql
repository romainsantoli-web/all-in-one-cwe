/**
 * @name DOM-based XSS via innerHTML/document.write
 * @description Detects user-controlled data flowing into innerHTML or document.write
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @id js/cwe-79-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssQuery
import DataFlow::PathGraph

from DomBasedXss::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to $@.", source.getNode(),
  "user-provided value"
