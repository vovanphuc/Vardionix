/**
 * @name Second-order path traversal via database lookup
 * @description Reading a filename or path from the database and using it
 *              directly in file operations without validation enables
 *              second-order path traversal when attackers previously stored
 *              malicious paths in the database.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id py/second-order-path-traversal
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-426
 */

import python

from Call sendFileCall, Subscript dbResult
where
  // Find calls to send_file or open with a path containing DB results
  (
    sendFileCall.getFunc().(Name).getId() = "send_file"
    or
    sendFileCall.getFunc().(Attribute).getName() = "send_file"
  ) and
  // A subscript on a fetchone() result is used in the argument
  exists(Call fetchCall |
    fetchCall.getFunc().(Attribute).getName() = "fetchone" and
    dbResult.getObject() = fetchCall and
    // The DB result subscript flows to the send_file argument
    // (directly or through os.path.join)
    exists(Call joinCall |
      (
        joinCall.getFunc().(Attribute).getName() = "join" and
        dbResult = joinCall.getAnArg()
      )
      and
      joinCall = sendFileCall.getAnArg()
    )
    or
    // Direct use via variable assignment
    exists(Name var, AssignStmt assign |
      assign.getValue() = dbResult and
      assign.getATarget() = var and
      exists(Name varUse |
        varUse.getId() = var.getId() and
        varUse.getParentNode+() = sendFileCall
      )
    )
  )
select sendFileCall,
  "File served using a path from database lookup without validation, enabling second-order path traversal."
