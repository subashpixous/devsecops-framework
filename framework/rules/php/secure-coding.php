<?php
// Rule fixtures for framework/rules/php/secure-coding.yml
//
// Semgrep test convention: `ruleid:` asserts the rule MUST fire on the next
// line; `ok:` asserts it MUST NOT. `semgrep --test` reads both and fails the
// build on either kind of miss.
//
// The negative cases carry more weight than the positive ones. After the FD-3
// rewrite the rules constrain a metavariable with `metavariable-regex` against
// the captured SOURCE TEXT, which means a mitigated call such as
// `htmlspecialchars($_GET['name'])` also contains the superglobal. Each rule
// therefore carries explicit `pattern-not` clauses for the correct forms, and
// every one of those exclusions is asserted below. If an exclusion regresses,
// the safe case starts firing and this file fails.

function sql_injection_cases($conn, $safe_id, $pdo) {
    // Interpolated -- the shape a literal pattern could not express.
    // ruleid: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, "SELECT * FROM users WHERE id = $_GET[id]");

    // Direct argument.
    // ruleid: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, $_POST['id']);

    // Concatenated. BOTH rules fire here and both are correct: it is a
    // superglobal reaching a query AND it is string concatenation. CI reported
    // this line as `incorrect` for sql-string-concatenation only because the
    // fixture declared one of the two. Corroboration is the intended behaviour,
    // so the fixture now declares both rather than one rule being narrowed.
    // ruleid: devsecops-framework.secure-coding.php.sql-injection-superglobal
    // ruleid: devsecops-framework.secure-coding.php.sql-string-concatenation
    $conn->query("SELECT * FROM users WHERE id = " . $_REQUEST['id']);

    // ok: devsecops-framework.secure-coding.php.sql-injection-superglobal
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");

    // ok: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, "SELECT * FROM users WHERE active = 1");

    // A local variable carries no superglobal in its text: correctly silent
    // here, and covered instead by the concatenation rule.
    // ok: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, $safe_id);
}

function sql_concatenation_cases($conn, $id) {
    // ruleid: devsecops-framework.secure-coding.php.sql-string-concatenation
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);

    // ok: devsecops-framework.secure-coding.php.sql-string-concatenation
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
}

function xss_cases($safe_value) {
    // ruleid: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo $_GET['name'];

    // ruleid: devsecops-framework.secure-coding.php.xss-superglobal-echo
    print $_POST['comment'];

    // Every pattern-not exclusion is asserted, because each one is the
    // difference between a usable rule and one developers switch off.
    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo htmlentities($_GET['name']);

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo strip_tags($_GET['bio']);

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo urlencode($_GET['next']);

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo intval($_GET['page']);

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo "a static string";

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo $safe_value;
}

function command_injection_cases() {
    // ruleid: devsecops-framework.secure-coding.php.command-execution-superglobal
    system("ping -c 1 $_GET[host]");

    // ruleid: devsecops-framework.secure-coding.php.command-execution-superglobal
    shell_exec($_POST['cmd']);

    // ok: devsecops-framework.secure-coding.php.command-execution-superglobal
    system(escapeshellarg($_GET['host']));

    // ok: devsecops-framework.secure-coding.php.command-execution-superglobal
    exec(escapeshellcmd($_GET['host']));

    // ok: devsecops-framework.secure-coding.php.command-execution-superglobal
    system("ping -c 1 127.0.0.1");
}

function file_inclusion_cases() {
    // ruleid: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    include $_GET['page'];

    // ruleid: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    require_once $_REQUEST['module'];

    // ok: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    include 'templates/header.php';

    // ok: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    $allowed = ['home' => 'pages/home.php'];
}

function path_traversal_cases() {
    // ruleid: devsecops-framework.secure-coding.php.path-traversal-superglobal
    readfile($_GET['file']);

    // ruleid: devsecops-framework.secure-coding.php.path-traversal-superglobal
    file_get_contents("/var/data/$_GET[name]");

    // basename() is the common correct mitigation and is excluded.
    // ok: devsecops-framework.secure-coding.php.path-traversal-superglobal
    readfile(basename($_GET['file']));

    // ok: devsecops-framework.secure-coding.php.path-traversal-superglobal
    file_get_contents(basename($_GET['file']));

    // ok: devsecops-framework.secure-coding.php.path-traversal-superglobal
    readfile('/var/www/static/logo.png');
}

function dynamic_execution_cases() {
    // ruleid: devsecops-framework.secure-coding.php.dynamic-code-execution
    eval($_GET['code']);

    // ruleid: devsecops-framework.secure-coding.php.dynamic-code-execution
    assert($_POST['expr']);

    // ok: devsecops-framework.secure-coding.php.dynamic-code-execution
    $dispatch = ['list' => 'listAction'];

    // ok: devsecops-framework.secure-coding.php.dynamic-code-execution
    eval('$x = 1;');
}

function deserialization_cases() {
    // ruleid: devsecops-framework.secure-coding.php.unserialize-superglobal
    $obj = unserialize($_COOKIE['prefs']);

    // ok: devsecops-framework.secure-coding.php.unserialize-superglobal
    $obj = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);

    // ok: devsecops-framework.secure-coding.php.unserialize-superglobal
    $obj = json_decode($_COOKIE['prefs'], true);
}

function exception_disclosure_cases() {
    try {
        risky();
    } catch (Exception $E) {
        // ruleid: devsecops-framework.secure-coding.php.exception-message-echoed
        echo $E->getMessage();
    }

    try {
        risky();
    } catch (Exception $E) {
        // ok: devsecops-framework.secure-coding.php.exception-message-echoed
        error_log($E->getMessage());
    }
}

function password_hash_cases($password, $file_contents) {
    // ruleid: devsecops-framework.secure-coding.php.weak-password-hash
    $hash = md5($password);

    // ok: devsecops-framework.secure-coding.php.weak-password-hash
    $hash = password_hash($password, PASSWORD_DEFAULT);

    // A checksum over file content is a legitimate use of md5.
    // ok: devsecops-framework.secure-coding.php.weak-password-hash
    $checksum = md5($file_contents);
}

function tls_cases($ch) {
    // ruleid: devsecops-framework.secure-coding.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    // ok: devsecops-framework.secure-coding.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
}
