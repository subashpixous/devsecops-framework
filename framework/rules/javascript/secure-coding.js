// Rule fixtures for framework/rules/javascript/secure-coding.yml
//
// Semgrep test convention: `ruleid:` asserts the rule must fire on the next
// line, `ok:` asserts it must not. The negative cases encode each rule's stated
// precision commitment -- notably that logging an error is correct handling.

const cp = require("child_process");
const fs = require("fs");
const jwt = require("jsonwebtoken");

function errorDisclosureCases(app, logger) {
  app.get("/a", (req, res) => {
    try {
      risky();
    } catch (err) {
      // ruleid: devsecops-framework.secure-coding.javascript.error-message-to-response
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/b", (req, res) => {
    try {
      risky();
    } catch (err) {
      // Correct handling: logged server-side, generic message returned.
      // ok: devsecops-framework.secure-coding.javascript.error-message-to-response
      logger.error(err);
      res.status(500).json({ error: "internal error" });
    }
  });
}

function domXssCases(el, userValue) {
  // ruleid: devsecops-framework.secure-coding.javascript.dom-xss-sink
  el.innerHTML = userValue;

  // ok: devsecops-framework.secure-coding.javascript.dom-xss-sink
  el.textContent = userValue;
}

function dynamicExecutionCases(expression) {
  // ruleid: devsecops-framework.secure-coding.javascript.dynamic-code-execution
  eval(expression);

  // ok: devsecops-framework.secure-coding.javascript.dynamic-code-execution
  JSON.parse(expression);
}

function commandCases(hostname) {
  // ruleid: devsecops-framework.secure-coding.javascript.command-execution
  cp.exec(`ping -c 1 ${hostname}`);

  // ok: devsecops-framework.secure-coding.javascript.command-execution
  cp.execFile("ping", ["-c", "1", hostname]);
}

function tlsCases() {
  // ruleid: devsecops-framework.secure-coding.javascript.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

  // ok: devsecops-framework.secure-coding.javascript.tls-verification-disabled
  process.env.NODE_EXTRA_CA_CERTS = "/etc/ssl/internal-ca.pem";
}

function jwtCases(token, key) {
  // ruleid: devsecops-framework.secure-coding.javascript.jwt-verification-bypass
  const claims = jwt.decode(token);

  // ok: devsecops-framework.secure-coding.javascript.jwt-verification-bypass
  const verified = jwt.verify(token, key, { algorithms: ["RS256"] });
  return [claims, verified];
}

function corsCases(cors, app) {
  // ruleid: devsecops-framework.secure-coding.javascript.cors-reflect-origin-with-credentials
  app.use(cors({ origin: true, credentials: true }));

  // ok: devsecops-framework.secure-coding.javascript.cors-reflect-origin-with-credentials
  app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
}

function pathCases(userFile) {
  // ruleid: devsecops-framework.secure-coding.javascript.path-traversal-sink
  fs.readFileSync(`/var/data/${userFile}`);

  // ok: devsecops-framework.secure-coding.javascript.path-traversal-sink
  fs.readFileSync("/var/data/fixed-report.csv");
}

function redirectCases(app) {
  app.get("/r", (req, res) => {
    // ruleid: devsecops-framework.secure-coding.javascript.open-redirect
    res.redirect(req.query.next);
  });

  app.get("/s", (req, res) => {
    // ok: devsecops-framework.secure-coding.javascript.open-redirect
    res.redirect("/dashboard");
  });
}
