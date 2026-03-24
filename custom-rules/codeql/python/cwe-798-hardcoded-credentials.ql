/**
 * @name Hard-coded Credentials (Python)
 * @description Detects hard-coded passwords, API keys, and secrets in Python source
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id py/cwe-798-hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import python
import semmle.python.security.dataflow.HardcodedCredentialsQuery

from HardcodedCredentials::Configuration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Hard-coded credential from $@.", source, "this source"
