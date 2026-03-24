/**
 * @name SQL Injection (Python)
 * @description Detects user input in SQL queries via string formatting
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id py/cwe-89-sqli
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability due to $@.", source.getNode(),
  "user-provided value"
