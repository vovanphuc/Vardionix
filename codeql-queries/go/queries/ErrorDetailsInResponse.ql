/**
 * @name Sensitive configuration data in error response
 * @description Including database hosts, credentials, or secret keys in HTTP error
 *              responses discloses internal infrastructure to attackers.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @id go/error-details-in-response
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-200
 */

import go

from CallExpr jsonCall, SelectorExpr fieldAccess
where
  // Find calls to c.JSON() in Gin framework
  jsonCall.getTarget().(Method).getName() = "JSON" and
  // Look for gin.H{} map literal arguments containing field accesses to config structs
  exists(MapLit mapLit |
    mapLit = jsonCall.getAnArgument().(CompositeLit) and
    exists(KeyValueExpr kv |
      kv = mapLit.getAnElement() and
      fieldAccess = kv.getValue() and
      fieldAccess.getSelector().getName().regexpMatch("(?i)(dbhost|dbuser|dbpassword|secretkey|secret|password|host|dsn|connectionstring)")
    )
  )
select jsonCall,
  "Error response includes sensitive configuration data (" + fieldAccess.getSelector().getName() + ") that discloses internal infrastructure."
