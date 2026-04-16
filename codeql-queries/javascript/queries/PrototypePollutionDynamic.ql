/**
 * @name Prototype pollution via dynamic property assignment
 * @description Iterating over object keys and dynamically assigning nested
 *              properties without filtering __proto__, constructor, or
 *              prototype keys enables prototype pollution attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id js/prototype-pollution-dynamic-property
 * @tags security
 *       external/cwe/cwe-1321
 */

import javascript

from ForInStmt forIn, AssignExpr assign, IndexExpr lhs
where
  // Inside the for-in loop body, there is an assignment to a bracket-notation property
  assign.getContainer() = forIn.getContainer() and
  lhs = assign.getLhs() and
  // The base of the bracket access is not the iteration variable itself
  // (it's writing into a target object, not reading from source)
  lhs instanceof IndexExpr and
  // No guard against __proto__ or constructor in the enclosing function
  not exists(Comparison cmp |
    cmp.getContainer() = forIn.getContainer() and
    (
      cmp.getAnOperand().toString().regexpMatch(".*__proto__.*") or
      cmp.getAnOperand().toString().regexpMatch(".*constructor.*")
    )
  )
select assign,
  "Dynamic property assignment in for-in loop without __proto__/constructor guard enables prototype pollution."
