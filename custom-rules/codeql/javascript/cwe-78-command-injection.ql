/**
 * @name OS Command Injection
 * @description Detects user input in exec/spawn/system calls
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.5
 * @id js/cwe-78-command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript
import semmle.javascript.security.dataflow.CommandInjectionQuery
import DataFlow::PathGraph

from CommandInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection vulnerability due to $@.", source.getNode(),
  "user-provided value"
