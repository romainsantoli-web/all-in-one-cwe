/**
 * @name Unsafe Deserialization
 * @description Detects deserialization of untrusted data (eval, Function, unserialize)
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id js/cwe-502-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionQuery
import DataFlow::PathGraph

from CodeInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsafe deserialization/code injection via $@.", source.getNode(),
  "user-provided value"
