/**
 * @name Server-Side Request Forgery (Python)
 * @description Detects user-controlled URLs in requests.get, urllib, httpx, etc.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id py/cwe-918-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import DataFlow::PathGraph

from FullServerSideRequestForgery::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SSRF vulnerability due to $@.", source.getNode(),
  "user-provided value"
