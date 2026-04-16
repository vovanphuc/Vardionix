/**
 * @name Mass assignment via unfiltered JSON binding
 * @description Binding user-controlled JSON directly to a struct that contains
 *              privileged fields (role, is_admin, verified) allows attackers to
 *              escalate privileges by including those fields in the request body.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id go/mass-assignment-json-binding
 * @tags security
 *       external/cwe/cwe-915
 */

import go

from CallExpr bindCall, StructType st
where
  // Find calls to BindJSON, ShouldBindJSON, Bind, etc.
  bindCall.getTarget().(Method).getName() = ["BindJSON", "ShouldBindJSON", "Bind", "ShouldBind"] and
  // The argument is the address of a struct
  exists(Type argType |
    argType = bindCall.getArgument(0).getType().getUnderlyingType() and
    (
      argType instanceof PointerType and
      st = argType.(PointerType).getBaseType().getUnderlyingType()
      or
      st = argType
    )
  ) and
  // The struct has fields that look like privilege escalation targets
  exists(string fieldName |
    st.getField(fieldName).getType() instanceof Type and
    fieldName.regexpMatch("(?i)(role|admin|is_admin|isadmin|verified|is_verified|permission|privilege|superuser|staff)")
  )
select bindCall,
  "JSON binding to struct with privileged fields (" +
    concat(string fn |
      st.getField(fn).getType() instanceof Type and
      fn.regexpMatch("(?i)(role|admin|is_admin|isadmin|verified|is_verified|permission|privilege|superuser|staff)")
    |
      fn, ", "
    ) +
    ") allows mass assignment attacks."
