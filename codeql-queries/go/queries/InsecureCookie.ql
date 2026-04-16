/**
 * @name Insecure cookie without Secure or HttpOnly flags
 * @description Setting cookies with Secure=false or HttpOnly=false exposes
 *              session tokens to interception (over HTTP) and theft (via XSS).
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id go/insecure-cookie-flags
 * @tags security
 *       external/cwe/cwe-614
 *       external/cwe/cwe-1004
 */

import go

from CallExpr setCookie
where
  // Gin's c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
  setCookie.getTarget().(Method).getName() = "SetCookie" and
  setCookie.getNumArgument() = 7 and
  (
    // secure parameter (index 5) is false
    setCookie.getArgument(5).(Ident).getName() = "false"
    or
    // httpOnly parameter (index 6) is false
    setCookie.getArgument(6).(Ident).getName() = "false"
  )
select setCookie,
  "Cookie is set without Secure and/or HttpOnly flags, exposing session tokens to interception and XSS-based theft."
