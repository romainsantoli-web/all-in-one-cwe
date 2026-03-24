/**
 * @name SQL Injection from user input
 * @description Detects string concatenation or template literals in SQL queries
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id js/cwe-89-sqli
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability due to $@.", source.getNode(),
  "user-provided value"
