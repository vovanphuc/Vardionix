/**
 * @name User-controlled regular expression (ReDoS)
 * @description Compiling a regex pattern from user input without validation
 *              allows attackers to craft patterns that cause catastrophic
 *              backtracking (ReDoS), leading to denial of service.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id go/user-controlled-regex
 * @tags security
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-400
 */

import go

from CallExpr compileCall, CallExpr sourceCall
where
  // regexp.Compile or regexp.MustCompile with user input
  (
    compileCall.getTarget().hasQualifiedName("regexp", "Compile") or
    compileCall.getTarget().hasQualifiedName("regexp", "MustCompile")
  ) and
  // The pattern argument flows from user input (PostForm, Query, etc.)
  exists(DataFlow::Node src, DataFlow::Node sink |
    sourceCall.getTarget().(Method).getName() = ["PostForm", "Query", "GetPostForm", "Param", "GetQuery"] and
    src = DataFlow::exprNode(sourceCall) and
    sink = DataFlow::exprNode(compileCall.getArgument(0)) and
    DataFlow::localFlow(src, sink)
  )
select compileCall,
  "User-controlled regex pattern passed to regexp.Compile enables ReDoS attacks."
