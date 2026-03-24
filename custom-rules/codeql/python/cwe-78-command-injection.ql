/**
 * @name OS Command Injection (Python)
 * @description Detects user input flowing into os.system, subprocess, etc.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.5
 * @id py/cwe-78-command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import DataFlow::PathGraph

from CommandInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection vulnerability due to $@.", source.getNode(),
  "user-provided value"
