/**
 * @name Debug mode enabled in production Flask application
 * @description Running a Flask application with debug=True or setting
 *              app.config["DEBUG"] = True exposes the Werkzeug debugger,
 *              which allows arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id py/flask-debug-mode
 * @tags security
 *       external/cwe/cwe-215
 *       external/cwe/cwe-489
 */

import python

from Call call, string detail
where
  (
    // Pattern 1: app.run(debug=True)
    exists(Attribute attr, Keyword kw |
      attr = call.getFunc() and
      attr.getName() = "run" and
      kw = call.getAKeyword() and
      kw.getArg() = "debug" and
      kw.getValue().(NameConstant).getId() = "True"
    ) and
    detail = "app.run(debug=True)"
  )
  or
  (
    // Pattern 2: app.run(..., debug=True) — also catch Flask(__name__).run()
    exists(Keyword kw |
      kw = call.getAKeyword() and
      kw.getArg() = "debug" and
      kw.getValue().(NameConstant).getId() = "True" and
      call.getFunc().(Attribute).getName() = "run"
    ) and
    detail = "Flask app.run(debug=True)"
  )
select call,
  "Flask debug mode is enabled (" + detail + "), exposing the Werkzeug debugger in production which allows remote code execution."
