/**
 * @name Unsafe YAML deserialization
 * @description Calling yaml.load() from js-yaml without specifying a safe
 *              schema allows arbitrary JavaScript execution through YAML tags.
 *              Use yaml.safeLoad() or specify schema: yaml.SAFE_SCHEMA.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id js/unsafe-yaml-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import javascript

from CallExpr yamlLoad, PropAccess callee
where
  callee = yamlLoad.getCallee() and
  callee.getPropertyName() = "load" and
  // The base variable is named "yaml" (from require/import of js-yaml)
  (
    callee.getBase().(VarAccess).getVariable().getName() = "yaml"
    or
    exists(DataFlow::SourceNode yamlMod |
      yamlMod = DataFlow::moduleImport("js-yaml") and
      yamlMod.flowsToExpr(callee.getBase())
    )
  ) and
  // No safe schema argument
  (
    yamlLoad.getNumArgument() = 1
    or
    yamlLoad.getNumArgument() >= 2 and
    not exists(ObjectExpr opts |
      opts = yamlLoad.getArgument(1) and
      exists(Property p | p = opts.getAProperty() and p.getName() = "schema")
    )
  )
select yamlLoad,
  "Unsafe yaml.load() call without safe schema allows arbitrary code execution via YAML deserialization."
