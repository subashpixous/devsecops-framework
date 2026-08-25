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
import javax.servlet.http.HttpServletResponse;
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

class TrustManagerSamples {
    // ruleid: devsecops-framework.secure-coding.java.trust-all-certificates
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
}

class TrustManagerSafeSamples {
    // ok: devsecops-framework.secure-coding.java.trust-all-certificates
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
            throws java.security.cert.CertificateException {
        if (chain == null || chain.length == 0) {
            throw new java.security.cert.CertificateException("empty chain");
        }
    }
}

class SecurityConfigSamples {
    public void configure(Object http) {
        // ruleid: devsecops-framework.secure-coding.java.csrf-disabled
        csrfOf(http).disable();

        // ok: devsecops-framework.secure-coding.java.csrf-disabled
        csrfOf(http).enable();
    }

    private CsrfSpec csrfOf(Object http) { return new CsrfSpec(); }

    static class CsrfSpec {
        void disable() { }
        void enable() { }
    }
}
