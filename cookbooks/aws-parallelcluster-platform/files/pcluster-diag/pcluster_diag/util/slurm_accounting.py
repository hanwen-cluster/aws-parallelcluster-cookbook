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

"""Slurm accounting configuration resolution, secret handling, redaction, and the read-only mysql probe.

This module is the single place where the Slurm accounting checks parse configuration, resolve the
slurmdbd/database endpoints and credential references, retrieve and classify the database secret,
redact the password from any emitted text, and run the read-only ``mysql`` client probe. Every
function is import-time side-effect free and individually patchable so the checks that consume them
stay pure enough to unit-test by mocking this module's functions.

The module is organized into clearly delimited sections that are populated incrementally:

* Config resolution -- :class:`AccountingConfig`, :func:`resolve_accounting_config`,
  :func:`accounting_configured`, :func:`parse_keyvalue_conf`, :func:`parse_db_uri`.
* Secret retrieval -- :class:`SecretAccessDenied`, :class:`SecretNotFound`,
  :func:`get_secret_string`, :func:`secret_is_json_object`.
* Redaction -- :data:`REDACTION_PLACEHOLDER`, :func:`redact`, :func:`contains_reserved_comment_char`.
* Read-only mysql client probe -- :class:`MysqlProbeResult`, :data:`MYSQL_ACCESS_DENIED_CODE`,
  :data:`MYSQL_DB_ACCESS_DENIED_CODE`, :func:`mysql_probe`.
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from pcluster_diag.core.constants import (
    DEFAULT_DATABASE_PORT,
    DEFAULT_SLURM_INSTALL_DIR,
    DEFAULT_SLURMDBD_PORT,
    SLURM_CONF_RELATIVE_PATH,
    SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH,
)
from pcluster_diag.models.context import Context
from pcluster_diag.util import shell

logger = logging.getLogger(__name__)

# Local slurmdbd always listens on the head node itself in Local_Slurmdbd mode.
LOCAL_SLURMDBD_HOST = "localhost"

# slurm.conf key that carries the port slurmdbd LISTENS on.
_ACCOUNTING_STORAGE_PORT_KEY = "AccountingStoragePort"


# --- Config resolution -------------------------------------------------------------


@dataclass(frozen=True)
class AccountingConfig:
    """Resolved Slurm accounting configuration derived from ``Context`` and the on-disk conf files.

    In ExternalSlurmdbd mode the database, its credentials, and the local slurmdbd configuration files
    all live on a separate instance the head node cannot inspect, so every database-related field is
    ``None`` and only the slurmdbd endpoint (``slurmdbd_host``/``slurmdbd_port``) is populated.

    Attributes:
        is_external: ``True`` when ``Scheduling.SlurmSettings.ExternalSlurmdbd`` is declared.
        slurmdbd_host: The head node (``localhost``) in Local_Slurmdbd mode, else ``ExternalSlurmdbd.Host``.
        slurmdbd_port: The slurmdbd listening port -- ``slurm.conf`` ``AccountingStoragePort``
            (default ``6819``) in Local_Slurmdbd mode, else ``ExternalSlurmdbd.Port``.
        db_host: The Accounting_Database host parsed from ``Database.Uri`` (``None`` when external).
        db_port: The Accounting_Database port parsed from ``Database.Uri`` (default ``3306``; ``None``
            when external).
        db_user: ``Database.UserName`` (``None`` when external).
        db_name: The accounting database name (``StorageLoc``): ``Database.DatabaseName`` when set,
            otherwise the cluster name with each ``-`` replaced by ``_`` (``None`` when external).
        password_secret_arn: ``Database.PasswordSecretArn`` (``None`` when external).
        region: The AWS region the cluster runs in.
    """

    is_external: bool
    slurmdbd_host: Optional[str]
    slurmdbd_port: Optional[int]
    db_host: Optional[str]
    db_port: Optional[int]
    db_user: Optional[str]
    db_name: Optional[str]
    password_secret_arn: Optional[str]
    region: Optional[str]


def resolve_accounting_config(context: Context) -> AccountingConfig:
    """Resolve the accounting endpoints and credential references from ``context`` and conf files.

    Branches on topology, reading ``Scheduling.SlurmSettings.{Database, ExternalSlurmdbd}`` from
    ``context.cluster_config`` and setting ``is_external`` iff ``ExternalSlurmdbd`` is declared:

    * **Local_Slurmdbd** (``Database`` present): ``slurmdbd_host`` is the local head node
      (``localhost``) and ``slurmdbd_port`` is ``slurm.conf`` ``AccountingStoragePort`` (default
      ``6819``, merged in from the on-disk conf); ``db_host``/``db_port`` are parsed from
      ``Database.Uri`` (default database port ``3306``); ``db_user`` is ``Database.UserName``;
      ``password_secret_arn`` is ``Database.PasswordSecretArn``; ``db_name`` is ``StorageLoc``
      (``Database.DatabaseName`` when set, otherwise the cluster name with each ``-`` replaced by ``_``).
    * **ExternalSlurmdbd** (no ``Database``): ``slurmdbd_host``/``slurmdbd_port`` come from
      ``ExternalSlurmdbd.Host``/``ExternalSlurmdbd.Port``; every database field is ``None`` because the
      database, its credentials, and the local conf files live on the separate external instance.
    """
    slurm_settings = _slurm_settings(context)
    database = slurm_settings.get("Database") or {}
    external = slurm_settings.get("ExternalSlurmdbd")
    region = _region(context)

    if external is not None:
        return AccountingConfig(
            is_external=True,
            slurmdbd_host=external.get("Host"),
            slurmdbd_port=_coerce_port(external.get("Port")),
            db_host=None,
            db_port=None,
            db_user=None,
            db_name=None,
            password_secret_arn=None,
            region=region,
        )

    db_host, db_port = parse_db_uri(database.get("Uri"))
    if db_host is not None and db_port is None:
        db_port = DEFAULT_DATABASE_PORT

    return AccountingConfig(
        is_external=False,
        slurmdbd_host=LOCAL_SLURMDBD_HOST,
        slurmdbd_port=_local_slurmdbd_port(context),
        db_host=db_host,
        db_port=db_port,
        db_user=database.get("UserName"),
        db_name=_accounting_db_name(context, database),
        password_secret_arn=database.get("PasswordSecretArn"),
        region=region,
    )


def accounting_configured(context: Context) -> Tuple[bool, Optional[str]]:
    """Return ``(configured, missing_signal_name)`` per the topology-aware Requirement 2.4 rule.

    Slurm accounting is treated as configured when either

    * **Local_Slurmdbd**: ``Scheduling.SlurmSettings.Database`` is present **and**
      ``/opt/slurm/etc/slurm_parallelcluster_slurmdbd.conf`` exists, **or**
    * **ExternalSlurmdbd**: ``Scheduling.SlurmSettings.ExternalSlurmdbd`` is present.

    When neither branch holds, accounting is not configured and the name of the missing signal is
    returned so the caller can name the exact absent input in its ``CheckInfo``.
    """
    slurm_settings = _slurm_settings(context)
    database = slurm_settings.get("Database")
    external = slurm_settings.get("ExternalSlurmdbd")

    if external is not None:
        return True, None
    if database is not None:
        if os.path.exists(SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH):
            return True, None
        return False, SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH
    return False, "Scheduling.SlurmSettings.Database or Scheduling.SlurmSettings.ExternalSlurmdbd"


def parse_keyvalue_conf(path: str) -> Dict[str, str]:
    """Parse a ``key=value`` Slurm conf file, treating ``#`` as the start of a comment.

    Used for ``slurm.conf``, ``slurmdbd.conf``, and ``slurm_parallelcluster_slurmdbd.conf``. Everything
    from the first ``#`` on a line onward is dropped as a comment; blank lines and lines without ``=``
    are ignored. Keys and values are stripped of surrounding whitespace and the last assignment for a
    repeated key wins.

    ``slurm_external_slurmdbd.conf`` is never present on the head node and is never parsed here.

    Raises:
        OSError: If the file cannot be read. Callers distinguish "absent" via ``FileNotFoundError`` and
            "unreadable" via ``PermissionError`` (both subclasses of ``OSError``).
    """
    values: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as conf_file:
        for line in conf_file:
            # A '#' begins a comment; keep only the content before it.
            content = line.split("#", 1)[0].strip()
            if not content or "=" not in content:
                continue
            key, _, value = content.partition("=")
            values[key.strip()] = value.strip()
    return values


def parse_db_uri(uri: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Split a ``Database.Uri`` value into ``(host, port)``.

    Handles ``"host:port"`` (returning the parsed integer port) and ``"host"`` (returning ``None`` for
    the port so the caller can apply the default database port). An empty or ``None`` URI, or a
    non-integer port, yields ``(host_or_None, None)``.
    """
    if not uri:
        return None, None
    if ":" in uri:
        host, _, port_str = uri.partition(":")
        host = host or None
        try:
            return host, int(port_str)
        except ValueError:
            logger.warning("Could not parse port from Database.Uri %r; treating port as unset", uri)
            return host, None
    return uri, None


# --- Secret retrieval --------------------------------------------------------------


class SecretAccessDenied(Exception):
    """Raised when the instance role lacks permission to read the accounting password secret.

    Maps the Secrets Manager ``AccessDenied``/``AccessDeniedException`` error codes (missing
    ``secretsmanager:GetSecretValue`` or ``secretsmanager:DescribeSecret`` permission).
    """


class SecretNotFound(Exception):
    """Raised when the accounting password secret does not exist.

    Maps the Secrets Manager ``ResourceNotFoundException`` error code.
    """


# Secrets Manager error codes that translate to the exceptions above.
_SECRET_ACCESS_DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException"})
_SECRET_NOT_FOUND_CODES = frozenset({"ResourceNotFoundException"})


def get_secret_string(arn: str, region: str) -> str:
    """Return the ``SecretString`` of the Secrets Manager secret ``arn`` in ``region``.

    Retrieves the accounting database password via ``secretsmanager:GetSecretValue``. Botocore
    ``ClientError`` codes are translated to this module's exceptions so callers can classify the
    failure without inspecting AWS internals:

    * ``AccessDenied``/``AccessDeniedException`` -> :class:`SecretAccessDenied`
    * ``ResourceNotFoundException`` -> :class:`SecretNotFound`

    Any other ``ClientError`` is re-raised unchanged.

    Raises:
        SecretAccessDenied: If the instance role cannot read the secret.
        SecretNotFound: If the secret does not exist.
        ClientError: For any other Secrets Manager error.
    """
    client = boto3.client("secretsmanager", region_name=region)
    try:
        response = client.get_secret_value(SecretId=arn)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code in _SECRET_ACCESS_DENIED_CODES:
            raise SecretAccessDenied(arn) from error
        if code in _SECRET_NOT_FOUND_CODES:
            raise SecretNotFound(arn) from error
        raise
    return response["SecretString"]


def secret_is_json_object(secret: str) -> bool:
    """Return ``True`` iff ``secret`` parses as a JSON object (dict), else ``False`` (Requirement 6.3).

    ParallelCluster expects the accounting password secret to be a plaintext password string. A secret
    whose value is a JSON object of key/value pairs is a misconfiguration. A plaintext password (or any
    non-object JSON scalar such as a bare number or string) returns ``False``.
    """
    try:
        parsed = json.loads(secret)
    except (ValueError, TypeError):
        return False
    return isinstance(parsed, dict)


# --- Redaction (Requirement 4) -----------------------------------------------------


# The fixed placeholder substituted for the database password wherever its presence must be conveyed
# in a finding or log line (Requirement 4.6). No character of the real secret ever appears.
REDACTION_PLACEHOLDER = "***REDACTED***"


def redact(text: str, secret: Optional[str]) -> str:
    """Return ``text`` with every occurrence of ``secret`` replaced by :data:`REDACTION_PLACEHOLDER`.

    This is applied before ANY finding message or log line that could contain the database password is
    emitted, so no finding message, finding field, or log record ever contains a substring equal to the
    password value (Requirements 4.1, 4.2, 4.3, 4.6). When ``secret`` is ``None`` or empty there is
    nothing to redact and ``text`` is returned unchanged.
    """
    if not secret:
        return text
    return text.replace(secret, REDACTION_PLACEHOLDER)


def contains_reserved_comment_char(password: Optional[str]) -> bool:
    """Return ``True`` iff ``password`` contains the ``#`` comment character (Requirements 6.7, 6.8).

    ``slurmdbd.conf`` treats ``#`` as the start of a comment, so a password containing ``#`` is
    silently truncated by slurmdbd and authentication then fails with MySQL error ``1045`` even though
    the raw credential is otherwise valid. A ``None`` password is treated as containing no reserved
    character. The password value itself is never emitted; callers report only the placeholder.
    """
    if password is None:
        return False
    return "#" in password


# --- Read-only mysql client probe --------------------------------------------------


@dataclass
class MysqlProbeResult:
    """Outcome of a single read-only ``mysql`` CLI probe.

    The probe never mutates state: it runs one read-only statement (from the caller's allow-list, e.g.
    ``SELECT 1`` or ``SHOW GRANTS FOR CURRENT_USER()``) and reports how the client exited. Both
    ``stdout`` and ``stderr`` are already passed through :func:`redact` by :func:`mysql_probe`, so no
    field of this object can contain the database password (Requirements 4.1, 4.2).

    Attributes:
        returncode: The ``mysql`` client exit code, or ``None`` when the probe timed out.
        stdout: The captured standard output, already redacted of the password.
        stderr: The captured standard error, already redacted of the password.
        timed_out: ``True`` when the probe exceeded ``timeout`` and was killed (Requirement 3.5/6.6).
    """

    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def succeeded(self) -> bool:
        """Return whether the probe completed with a zero exit code (and did not time out)."""
        return self.returncode == 0 and not self.timed_out


# MySQL well-known error tokens used to classify failures without a database driver.
MYSQL_ACCESS_DENIED_CODE = 1045  # invalid credentials
MYSQL_DB_ACCESS_DENIED_CODE = 1044  # access denied to a named database


def mysql_probe(
    host: str,
    port: int,
    user: str,
    password: str,
    database: Optional[str],
    sql: str,
    timeout: int,
    secret_for_redaction: Optional[str] = None,
) -> MysqlProbeResult:
    """Run a single read-only ``mysql`` statement without ever placing the password on the command line.

    The database password is written only to a mode-``0600`` temporary ``--defaults-extra-file``
    containing a ``[client]`` section (host/port/user/password); the ``mysql`` client reads its
    credentials from that file, so the secret never appears in ``argv``, the process table, or any log
    line (Requirements 4.1, 4.2, following the ``util/ldap.py`` pattern). The invoked command is::

        mysql --defaults-extra-file=<tmp> [--connect-timeout=<timeout>] [database] -N -B -e "<sql>"

    where the ``database`` positional argument is included only when ``database`` is not ``None``. The
    command is run via :func:`shell.run_command` with NO shell (Requirements 3.2, 3.3). Callers are
    responsible for passing only read-only ``sql`` from the probe allow-list.

    Both ``stdout`` and ``stderr`` are passed through :func:`redact` (using ``secret_for_redaction`` when
    provided, otherwise ``password``) before being stored on the returned :class:`MysqlProbeResult`, so
    the password can never leak through the probe output even as defense-in-depth (Requirement 4). The
    temporary file is always removed in a ``finally`` block so no secret is left on disk and the probe
    remains strictly read-only (Requirement 3.6).

    A ``subprocess.TimeoutExpired`` is converted to ``timed_out=True`` (with ``returncode=None``) rather
    than propagated (Requirements 3.5, 6.6). If the ``mysql`` binary is missing, :func:`shell.run_command`
    raises ``FileNotFoundError``/``OSError``; that is intentionally left to propagate to the caller, which
    translates it into ``SKIPPED_NOT_APPLICABLE``.
    """
    redaction_secret = secret_for_redaction or password
    # mkstemp atomically creates the file with mode 0600 (owner-only), so the credentials are never
    # briefly readable by other users. It returns an open fd plus the path.
    fd, tmp_path = tempfile.mkstemp(prefix="pcluster-diag-mysql-", suffix=".cnf")
    try:
        _write_defaults_extra_file(fd, host, port, user, password)
        argv = ["mysql", "--defaults-extra-file={}".format(tmp_path)]
        if timeout:
            argv.append("--connect-timeout={}".format(timeout))
        if database is not None:
            argv.append(database)
        argv += ["-N", "-B", "-e", sql]
        try:
            result = shell.run_command(argv, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            # A timeout is diagnostic data, not an error to propagate (Requirement 3.5/6.6). The
            # partial stderr may contain the password only if the client echoed it, so redact it too.
            return MysqlProbeResult(
                returncode=None,
                stdout="",
                stderr=redact(_as_text(error.stderr), redaction_secret),
                timed_out=True,
            )
        return MysqlProbeResult(
            returncode=result.returncode,
            stdout=redact(result.stdout, redaction_secret),
            stderr=redact(result.stderr, redaction_secret),
            timed_out=False,
        )
    finally:
        # Always remove the temp file so no secret is left on disk (Requirement 3.6).
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _write_defaults_extra_file(fd: int, host: str, port: int, user: str, password: str) -> None:
    """Write the ``[client]`` credentials into the already-0600 file descriptor.

    The password is written ONLY here, to the mode-``0600`` file, and never anywhere else. Ownership of
    ``fd`` is transferred to the ``os.fdopen`` wrapper, which closes the descriptor on exit.
    """
    with os.fdopen(fd, "w", encoding="utf-8") as defaults_file:
        defaults_file.write(
            "[client]\nhost={}\nport={}\nuser={}\npassword={}\n".format(host, port, user, password)
        )


def _as_text(output) -> str:
    """Normalize captured output (which may be ``None`` or ``bytes`` on timeout) to a string."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


# --- Internal helpers --------------------------------------------------------------


def _slurm_settings(context: Context) -> dict:
    """Return the ``Scheduling.SlurmSettings`` section of the cluster config, or an empty dict."""
    scheduling = (context.cluster_config or {}).get("Scheduling") or {}
    return scheduling.get("SlurmSettings") or {}


def _region(context: Context) -> Optional[str]:
    """Return the AWS region from ``dna.json`` (``cluster.region``), falling back to the cluster config."""
    region = (((context.dna_json or {}).get("cluster")) or {}).get("region")
    if region:
        return region
    return (context.cluster_config or {}).get("Region")


def _cluster_name(context: Context) -> Optional[str]:
    """Return the cluster name from ``dna.json`` (``cluster.cluster_name``, else ``cluster.stack_name``)."""
    cluster = ((context.dna_json or {}).get("cluster")) or {}
    return cluster.get("cluster_name") or cluster.get("stack_name")


def _accounting_db_name(context: Context, database: dict) -> Optional[str]:
    """Return the accounting database name (``StorageLoc``).

    Uses ``Database.DatabaseName`` when set, otherwise the cluster name with each ``-`` replaced by
    ``_`` (ParallelCluster's default ``StorageLoc``). Returns ``None`` when neither is available.
    """
    database_name = database.get("DatabaseName")
    if database_name:
        return database_name
    cluster_name = _cluster_name(context)
    if cluster_name:
        return cluster_name.replace("-", "_")
    return None


def _slurm_conf_path(context: Context) -> str:
    """Return the ``slurm.conf`` path derived from the Slurm install dir in ``dna.json`` (or the default)."""
    install_dir = (((context.dna_json or {}).get("cluster") or {}).get("slurm") or {}).get(
        "install_dir"
    ) or DEFAULT_SLURM_INSTALL_DIR
    return "{}/{}".format(install_dir.rstrip("/"), SLURM_CONF_RELATIVE_PATH)


def _local_slurmdbd_port(context: Context) -> int:
    """Return the local slurmdbd listening port from ``slurm.conf`` ``AccountingStoragePort``.

    Falls back to :data:`DEFAULT_SLURMDBD_PORT` (6819) when ``slurm.conf`` is absent, unreadable, or
    does not set the port (or sets it to a non-integer value).
    """
    try:
        conf = parse_keyvalue_conf(_slurm_conf_path(context))
    except OSError as error:
        logger.info("Could not read slurm.conf to resolve the slurmdbd port; using default: %s", error)
        return DEFAULT_SLURMDBD_PORT
    port = _coerce_port(conf.get(_ACCOUNTING_STORAGE_PORT_KEY))
    return port if port is not None else DEFAULT_SLURMDBD_PORT


def _coerce_port(value) -> Optional[int]:
    """Coerce a port value (which may be a string from a conf file) to an int, or ``None`` if invalid."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("Ignoring non-integer port value %r", value)
        return None
