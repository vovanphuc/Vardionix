/**
 * @name CORS reflected origin with credentials
 * @description Reflecting the Origin header in Access-Control-Allow-Origin
 *              while also setting Access-Control-Allow-Credentials to true
 *              allows any site to make authenticated cross-origin requests.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id go/cors-reflected-origin
 * @tags security
 *       external/cwe/cwe-942
 *       external/cwe/cwe-346
 */

import go

from CallExpr setCall
where
  // Find Header().Set("Access-Control-Allow-Origin", <value>)
  setCall.getTarget().(Method).getName() = "Set" and
  setCall.getArgument(0).getStringValue() = "Access-Control-Allow-Origin" and
  // The value argument flows from a GetHeader("Origin") call
  exists(CallExpr getHeader |
    getHeader.getTarget().(Method).getName() = "GetHeader" and
    getHeader.getArgument(0).getStringValue() = "Origin" and
    DataFlow::localFlow(DataFlow::exprNode(getHeader), DataFlow::exprNode(setCall.getArgument(1)))
  )
select setCall,
  "Access-Control-Allow-Origin is set by reflecting the request Origin header, enabling cross-origin attacks with credentials."
