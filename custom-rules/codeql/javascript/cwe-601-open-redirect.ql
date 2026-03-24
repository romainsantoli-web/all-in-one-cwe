/**
 * @name Open Redirect
 * @description Detects user-controlled values in HTTP redirects
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @id js/cwe-601-open-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import javascript
import semmle.javascript.security.dataflow.ServerSideUrlRedirectQuery
import DataFlow::PathGraph

from ServerSideUrlRedirect::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Open redirect vulnerability due to $@.", source.getNode(),
  "user-provided value"
