/**
 * @name Command injection through Express middleware chain
 * @description User input stored in req properties by middleware and later
 *              used in a shell command enables OS command injection.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.5
 * @precision medium
 * @id js/middleware-command-injection
 * @tags security
 *       external/cwe/cwe-78
 */

import javascript

from CallExpr shellCall
where
  // Find exec/execSync calls
  (
    exists(DataFlow::SourceNode cp, string fn |
      (fn = "exec" or fn = "execSync") and
      cp = DataFlow::moduleMember("child_process", fn) and
      cp.flowsToExpr(shellCall.getCallee())
    )
    or
    shellCall.getCallee().(VarAccess).getName() = "exec"
  ) and
  // The command argument is built from middleware-stored properties
  // Pattern: variable assigned from (req as any).reportConfig / req.jobConfig
  exists(VarAccess cmdVar, VarDef def, Expr rhs |
    cmdVar = shellCall.getArgument(0) and
    def.getAVariable() = cmdVar.getVariable() and
    rhs = def.(VariableDeclarator).getInit() and
    // The RHS is a template literal or concatenation that references props from a middleware config var
    exists(VarAccess cfgAccess, VarDef cfgDef |
      cfgAccess.getParentExpr+() = rhs and
      cfgDef.getAVariable() = cfgAccess.getVariable() and
      // The config variable was assigned from (req as any).reportConfig or req.jobConfig
      exists(PropAccess mwProp |
        mwProp.getParentExpr*() = cfgDef.(VariableDeclarator).getInit() and
        (
          mwProp.getPropertyName() = "reportConfig" or
          mwProp.getPropertyName() = "jobConfig" or
          mwProp.getPropertyName() = "taskConfig"
        )
      )
    )
  )
select shellCall,
  "Shell command uses data from middleware-stored request property, enabling command injection through the middleware chain."
