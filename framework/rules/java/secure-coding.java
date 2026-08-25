// Rule fixtures for framework/rules/java/secure-coding.yml
//
// `ruleid:` asserts the rule must fire on the next line; `ok:` asserts it must
// not. The negative cases are the PreparedStatement, ProcessBuilder and
// correctly-configured forms a reviewer would ask for.

import java.io.PrintWriter;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.slf4j.Logger;
import org.springframework.http.ResponseEntity;

public class SecureCodingSamples {

    private Logger logger;

    public ResponseEntity<String> exceptionMessageReturned() {
        try {
            risky();
        } catch (Exception e) {
            // ruleid: devsecops-framework.secure-coding.java.exception-message-to-response
            return ResponseEntity.badRequest().body(e.getMessage());
        }
        return ResponseEntity.ok("done");
    }

    public ResponseEntity<String> exceptionLoggedNotReturned() {
        try {
            risky();
        } catch (Exception e) {
            // Correct handling: logged server-side, generic message returned.
            // ok: devsecops-framework.secure-coding.java.exception-message-to-response
            logger.error("operation failed", e);
            return ResponseEntity.status(500).body("An internal error occurred.");
        }
        return ResponseEntity.ok("done");
    }

    public void stackTraceCases(HttpServletResponse resp) throws Exception {
        try {
            risky();
        } catch (Exception e) {
            // ruleid: devsecops-framework.secure-coding.java.stack-trace-to-response
            e.printStackTrace(resp.getWriter());
        }

        try {
            risky();
        } catch (Exception e) {
            // ok: devsecops-framework.secure-coding.java.stack-trace-to-response
            logger.error("operation failed", e);
        }
    }

    public void sqlCases(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        // ruleid: devsecops-framework.secure-coding.java.sql-string-concatenation
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        // ok: devsecops-framework.secure-coding.java.sql-string-concatenation
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
    }

    public void commandCases(String host) throws Exception {
        // ruleid: devsecops-framework.secure-coding.java.command-execution
        Runtime.getRuntime().exec("ping -c 1 " + host);

        // ok: devsecops-framework.secure-coding.java.command-execution
        new ProcessBuilder("ping", "-c", "1", host).start();
    }

    public void deserializationCases(java.io.InputStream in) throws Exception {
        // ruleid: devsecops-framework.secure-coding.java.insecure-deserialization
        Object obj = new java.io.ObjectInputStream(in).readObject();

        // ok: devsecops-framework.secure-coding.java.insecure-deserialization
        String json = new String(in.readAllBytes());
    }

    public void hashCases() throws Exception {
        // ruleid: devsecops-framework.secure-coding.java.weak-password-hash
        MessageDigest weak = MessageDigest.getInstance("MD5");

        // ok: devsecops-framework.secure-coding.java.weak-password-hash
        MessageDigest strong = MessageDigest.getInstance("SHA-256");
    }

    private void risky() throws Exception { }
}

// The type is written with the short name, as real code does after importing it.
// A fully-qualified `java.security.cert.X509Certificate[]` is a different AST
// node from the pattern's `X509Certificate[]`, so the earlier fixture never
// exercised this rule at all -- the fixture was wrong, not the rule.
class TrustManagerSamples {
    // ruleid: devsecops-framework.secure-coding.java.trust-all-certificates
    public void checkServerTrusted(X509Certificate[] chain, String authType) { }

    // ruleid: devsecops-framework.secure-coding.java.trust-all-certificates
    public void checkClientTrusted(X509Certificate[] chain, String authType) { }
}

class TrustManagerSafeSamples {
    // The pattern requires an EMPTY body. A manager that actually validates has
    // a body and is correctly not flagged.
    // ok: devsecops-framework.secure-coding.java.trust-all-certificates
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty chain");
        }
    }
}

// Real Spring Security configuration. The earlier fixture called an invented
// `csrfOf(http)` helper, which no rule targets and which therefore proved
// nothing -- again a defect in the fixture rather than in the rule.
class SecurityConfigSamples {
    public void configure(HttpSecurity http) throws Exception {
        // ruleid: devsecops-framework.secure-coding.java.csrf-disabled
        http.csrf().disable();
    }
}

class SecurityConfigLambdaSamples {
    public void configure(HttpSecurity http) throws Exception {
        // ruleid: devsecops-framework.secure-coding.java.csrf-disabled
        http.csrf(c -> c.disable());
    }
}

class SecurityConfigSafeSamples {
    public void configure(HttpSecurity http) throws Exception {
        // CSRF left enabled: configured, not disabled.
        // ok: devsecops-framework.secure-coding.java.csrf-disabled
        http.csrf();
    }
}
