/**
 * @name Hard-coded Credentials
 * @description Detects hard-coded passwords, API keys, and tokens in source code
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id js/cwe-798-hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import javascript
import semmle.javascript.security.dataflow.HardcodedCredentialsQuery

from HardcodedCredentials::Configuration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Hard-coded credential from $@.", source, "this source"
