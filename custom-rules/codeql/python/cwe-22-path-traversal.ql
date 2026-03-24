/**
 * @name Path Traversal (Python)
 * @description Detects user-controlled file paths without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id py/cwe-22-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import DataFlow::PathGraph

from PathInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Path traversal vulnerability due to $@.", source.getNode(),
  "user-provided value"
