/**
 * @name Timing attack via string comparison of secrets
 * @description Using == or != to compare security-sensitive strings (API keys,
 *              tokens, passwords) leaks information through timing side channels.
 *              Use crypto/subtle.ConstantTimeCompare instead.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id go/timing-attack-string-comparison
 * @tags security
 *       external/cwe/cwe-208
 */

import go

from EqualityTestExpr eq, DataFlow::Node operand
where
  // One operand comes from a header (e.g., GetHeader, c.GetHeader)
  exists(CallExpr headerCall |
    headerCall.getTarget().(Method).getName() = ["GetHeader", "Header"] and
    DataFlow::localFlow(DataFlow::exprNode(headerCall), DataFlow::exprNode(eq.getAnOperand()))
  ) and
  // The comparison uses == (not a constant-time compare)
  eq.getAnOperand().getType().getUnderlyingType() instanceof StringType
select eq,
  "Secret comparison using == operator is vulnerable to timing attacks. Use crypto/subtle.ConstantTimeCompare instead."
