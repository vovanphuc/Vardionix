/**
 * @name Sensitive data in JWT payload or algorithm none
 * @description Storing PII (SSN, credit scores) in JWT payloads or using
 *              algorithm "none" allows attackers to read sensitive data
 *              and forge tokens.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id js/jwt-sensitive-payload
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-312
 */

import javascript

from ObjectExpr obj
where
  // Find JWT header objects with alg: "none"
  exists(Property algProp |
    algProp = obj.getAProperty() and
    algProp.getName() = "alg" and
    algProp.getInit().getStringValue() = "none"
  ) and
  exists(Property typProp |
    typProp = obj.getAProperty() and
    typProp.getName() = "typ" and
    typProp.getInit().getStringValue() = "JWT"
  )
select obj,
  "JWT header uses algorithm 'none', allowing token forgery without signature verification."
