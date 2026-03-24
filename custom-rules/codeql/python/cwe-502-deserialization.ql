/**
 * @name Unsafe Deserialization (Python)
 * @description Detects pickle.loads, yaml.unsafe_load, marshal.loads on untrusted data
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id py/cwe-502-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import semmle.python.security.dataflow.UnsafeDeserializationQuery
import DataFlow::PathGraph

from UnsafeDeserialization::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsafe deserialization via $@.", source.getNode(),
  "user-provided value"
