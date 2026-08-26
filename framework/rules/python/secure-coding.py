"""Rule fixtures for framework/rules/python/secure-coding.yml.

Semgrep test convention: `ruleid:` asserts the rule must fire on the next line,
`ok:` asserts it must not. The negative cases encode the precision commitments
made in each rule's rationale -- particularly that logging an exception is
correct handling and must never be flagged.
"""

import hashlib
import logging
import os
import pickle
import subprocess
import traceback

import requests
import yaml
from flask import Flask, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)


def exception_disclosure_cases():
    try:
        risky()
    except Exception as e:
        # ruleid: devsecops-framework.secure-coding.python.exception-message-to-response
        return jsonify({"error": str(e)}), 500

    try:
        risky()
    except Exception as e:
        # Correct handling: logged server-side, generic message to the caller.
        # ok: devsecops-framework.secure-coding.python.exception-message-to-response
        logger.exception("operation failed")
        return jsonify({"error": "internal error"}), 500


def traceback_cases():
    try:
        risky()
    except Exception:
        # ruleid: devsecops-framework.secure-coding.python.traceback-to-response
        return jsonify({"trace": traceback.format_exc()}), 500

    try:
        risky()
    except Exception:
        # ok: devsecops-framework.secure-coding.python.traceback-to-response
        logger.error(traceback.format_exc())
        return jsonify({"error": "internal error"}), 500


# ruleid: devsecops-framework.secure-coding.python.debug-enabled
DEBUG = True

# ok: devsecops-framework.secure-coding.python.debug-enabled
DEBUG_FROM_ENV = os.environ.get("DEBUG", "false").lower() == "true"


def sql_cases(cursor, user_id):
    # ruleid: devsecops-framework.secure-coding.python.sql-string-formatting
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # ok: devsecops-framework.secure-coding.python.sql-string-formatting
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def tls_cases():
    # ruleid: devsecops-framework.secure-coding.python.tls-verification-disabled
    requests.get("https://api.example.com", verify=False)

    # ok: devsecops-framework.secure-coding.python.tls-verification-disabled
    requests.get("https://api.example.com", timeout=10)


def deserialization_cases(untrusted, stream):
    # ruleid: devsecops-framework.secure-coding.python.unsafe-deserialization
    pickle.loads(untrusted)

    # ruleid: devsecops-framework.secure-coding.python.unsafe-deserialization
    yaml.load(stream)

    # ok: devsecops-framework.secure-coding.python.unsafe-deserialization
    yaml.safe_load(stream)


def command_cases(hostname):
    # ruleid: devsecops-framework.secure-coding.python.shell-command-execution
    subprocess.run(f"ping -c 1 {hostname}", shell=True)

    # ok: devsecops-framework.secure-coding.python.shell-command-execution
    subprocess.run(["ping", "-c", "1", hostname], shell=False)


def dynamic_execution_cases(expression):
    # ruleid: devsecops-framework.secure-coding.python.dynamic-code-execution
    eval(f"result = {expression}")

    # ok: devsecops-framework.secure-coding.python.dynamic-code-execution
    import ast

    ast.literal_eval(expression)


def logging_cases(password, user_id, request_id):
    # ruleid: devsecops-framework.secure-coding.python.sensitive-value-logged
    logger.info(f"authenticating with {password}")

    # A non-credential value in a log line is normal and must not fire.
    # ok: devsecops-framework.secure-coding.python.sensitive-value-logged
    logger.info(f"authenticating user {user_id} request {request_id}")
