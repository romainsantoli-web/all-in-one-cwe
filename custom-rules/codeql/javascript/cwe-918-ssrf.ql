/**
 * @name Server-Side Request Forgery (SSRF)
 * @description Detects user-controlled URLs in HTTP requests
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id js/cwe-918-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.RequestForgeryQuery
import DataFlow::PathGraph

from RequestForgery::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Server-side request forgery due to $@.", source.getNode(),
  "user-provided value"
