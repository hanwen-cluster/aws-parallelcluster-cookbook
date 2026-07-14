# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the
# License. A copy of the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "LICENSE.txt" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and
# limitations under the License.

"""Read-only LDAP/TLS probe helpers for the directory-service checks.

These wrap the ``openssl`` and ``ldapsearch`` CLIs. Every call is read-only (a TLS handshake or an LDAP
search), runs without a shell, and closes stdin so the tools never block waiting for input. The bind
password is handed to ldapsearch through a mode-0600 temporary file (``-y``), so it never appears in the
argument list, the process table, or the logs; only the argv (which contains the temp-file path, not the
secret) and the return code are logged, never stdout (which may contain directory data).
"""

import logging
import os
import re
import subprocess  # nosec B404  # callers pass fixed argument lists, no shell
import tempfile
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

DEFAULT_LDAP_TIMEOUT_SECONDS = 30
# LDAP result code ldapsearch exits with when a simple bind is rejected for bad credentials.
LDAP_INVALID_CREDENTIALS_CODE = 49


@dataclass
class ProbeResult:
    """The outcome of an openssl/ldapsearch probe.

    Attributes:
        returncode: The process exit code, or ``None`` if the probe timed out.
        stdout: Captured standard output (may contain directory data; never logged).
        stderr: Captured standard error.
        timed_out: ``True`` if the probe exceeded its timeout and was killed.
    """

    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def succeeded(self) -> bool:
        """Return whether the probe completed with a zero exit code (and did not time out)."""
        return not self.timed_out and self.returncode == 0


def verify_tls_certificate(
    host: str, port: int, cafile: Optional[str] = None, timeout: int = DEFAULT_LDAP_TIMEOUT_SECONDS
) -> ProbeResult:
    """Open a TLS connection to ``host:port`` with openssl and let it validate the server certificate.

    ``-verify_return_error`` makes openssl exit non-zero on a validation failure; the numeric reason is
    also printed as a ``Verify return code`` line (see :func:`parse_tls_verify_code`).

    Raises:
        OSError: If the openssl binary is not installed / not on PATH.
    """
    argv = ["openssl", "s_client", "-connect", "{}:{}".format(host, port), "-servername", host, "-verify_return_error"]
    if cafile:
        argv += ["-CAfile", cafile]
    return _run(argv, timeout=timeout)


def parse_tls_verify_code(text: str) -> Optional[int]:
    """Return the numeric ``Verify return code`` openssl reports (0 == ok), or None if not present."""
    match = re.search(r"Verify return code:\s*(\d+)", text)
    return int(match.group(1)) if match else None


def ldap_bind_search(
    uri: str,
    bind_dn: str,
    password: str,
    base: str,
    scope: str = "base",
    ldap_filter: str = "(objectClass=*)",
    attributes: Optional[List[str]] = None,
    cacert: Optional[str] = None,
    reqcert: Optional[str] = None,
    timeout: int = DEFAULT_LDAP_TIMEOUT_SECONDS,
) -> ProbeResult:
    """Run a read-only simple-bind ``ldapsearch`` and return its ProbeResult.

    The password is written to a mode-0600 temp file passed via ``-y`` so it never appears in argv, the
    process table, or logs. TLS trust settings are passed through the environment (``LDAPTLS_CACERT`` /
    ``LDAPTLS_REQCERT``) rather than argv.

    Raises:
        OSError: If the ldapsearch binary is not installed / not on PATH.
    """
    env = dict(os.environ)
    if cacert:
        env["LDAPTLS_CACERT"] = cacert
    if reqcert:
        env["LDAPTLS_REQCERT"] = reqcert

    handle, password_path = tempfile.mkstemp(prefix="pcluster-diag-ldap-")
    try:
        # No trailing newline: ldapsearch -y uses the file's bytes verbatim as the password.
        os.write(handle, (password or "").encode("utf-8"))
        os.close(handle)
        argv = ["ldapsearch", "-x", "-H", uri, "-D", bind_dn, "-y", password_path, "-b", base, "-s", scope, "-LLL"]
        argv.append(ldap_filter)
        if attributes:
            argv += list(attributes)
        return _run(argv, env=env, timeout=timeout)
    finally:
        try:
            os.remove(password_path)
        except OSError:  # pragma: no cover - the file was created just above
            pass


def _run(argv: List[str], env: Optional[dict] = None, timeout: int = DEFAULT_LDAP_TIMEOUT_SECONDS) -> ProbeResult:
    """Run ``argv`` read-only with stdin closed and return a ProbeResult (logs argv + return code only)."""
    try:
        completed = subprocess.run(  # nosec B603  # no shell; fixed argv; stdin closed to avoid blocking
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        result = ProbeResult(completed.returncode, completed.stdout, completed.stderr, timed_out=False)
    except subprocess.TimeoutExpired as error:
        result = ProbeResult(None, _as_text(error.stdout), _as_text(error.stderr), timed_out=True)
    logger.info("Executed %s: timed_out=%s, returncode=%s", argv, result.timed_out, result.returncode)
    return result


def _as_text(output) -> str:
    """Normalize captured output (which may be ``None`` or ``bytes`` on timeout) to a string."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output
