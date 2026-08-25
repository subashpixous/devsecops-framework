<?php
// Rule fixtures for framework/rules/php/secure-coding.yml
//
// Semgrep's own test convention: a `ruleid:` annotation asserts the rule MUST
// fire on the next line; `ok:` asserts it MUST NOT. `semgrep --test` reads both,
// so this file is simultaneously the positive test, the negative test, and the
// documentation of what each rule considers safe.
//
// The negative cases matter more than the positive ones. A rule that fires on
// the vulnerable line is easy; a rule that stays silent on the correct line is
// what determines whether developers leave it switched on.

function sql_injection_cases($conn, $safe_id) {
    // ruleid: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, "SELECT * FROM users WHERE id = $_GET[id]");

    // ok: devsecops-framework.secure-coding.php.sql-injection-superglobal
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");

    // ok: devsecops-framework.secure-coding.php.sql-injection-superglobal
    mysqli_query($conn, "SELECT * FROM users WHERE active = 1");
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

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

    // ok: devsecops-framework.secure-coding.php.xss-superglobal-echo
    echo "a static string";
}

function command_injection_cases() {
    // ruleid: devsecops-framework.secure-coding.php.command-execution-superglobal
    system("ping -c 1 $_GET[host]");

    // ok: devsecops-framework.secure-coding.php.command-execution-superglobal
    system("ping -c 1 " . escapeshellarg('127.0.0.1'));
}

function file_inclusion_cases() {
    // ruleid: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    include $_GET['page'];

    // ok: devsecops-framework.secure-coding.php.file-inclusion-superglobal
    include 'templates/header.php';
}

function path_traversal_cases() {
    // ruleid: devsecops-framework.secure-coding.php.path-traversal-superglobal
    readfile($_GET['file']);

    // ok: devsecops-framework.secure-coding.php.path-traversal-superglobal
    readfile('/var/www/static/logo.png');
}

function dynamic_execution_cases() {
    // ruleid: devsecops-framework.secure-coding.php.dynamic-code-execution
    eval($_GET['code']);

    // ok: devsecops-framework.secure-coding.php.dynamic-code-execution
    $dispatch = ['list' => 'listAction'];
}

function deserialization_cases() {
    // ruleid: devsecops-framework.secure-coding.php.unserialize-superglobal
    $obj = unserialize($_COOKIE['prefs']);

    // ok: devsecops-framework.secure-coding.php.unserialize-superglobal
    $obj = json_decode($_COOKIE['prefs'], true);
}

function exception_disclosure_cases($e) {
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

    // A checksum over file content is a legitimate use of md5 and must not fire.
    // ok: devsecops-framework.secure-coding.php.weak-password-hash
    $checksum = md5($file_contents);
}

function tls_cases($ch) {
    // ruleid: devsecops-framework.secure-coding.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    // ok: devsecops-framework.secure-coding.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
}
