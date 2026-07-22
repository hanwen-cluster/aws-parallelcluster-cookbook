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

"""A single read-only Check diagnosing Slurm accounting health on a ParallelCluster head node.

``pcluster-diag`` always runs on the head node. The :class:`SlurmAccounting` check validates the health of
Slurm accounting -- the chain of slurmdbd, its MySQL/MariaDB Accounting_Database, the credentials, the
configuration files, and the database privileges -- by running several read-only probes and folding their
findings into one Result. Every probe is strictly read-only and non-destructive: it opens sockets, reads
files, runs the ``mysql`` client with read-only SQL, and scans logs, but never creates, alters, or deletes
any configuration, database, or cluster state. The database password is never emitted in a finding or a
log line.

The probes are topology-aware. Accounting is served either by a **Local_Slurmdbd** (the cluster config
declares ``Scheduling.SlurmSettings.Database`` and slurmdbd runs on the head node) or by an
**ExternalSlurmdbd** (``Scheduling.SlurmSettings.ExternalSlurmdbd`` declares a slurmdbd on a separate
instance). In ExternalSlurmdbd mode the database, its credentials, and the local slurmdbd config files are
all absent from the head node, so the database- and local-slurmdbd-facing probes contribute nothing.

The check applies only on the head node and only when accounting is configured (otherwise the whole
capability is not applicable). A probe whose precondition is simply not present (external slurmdbd owns
the resource, no secret configured, an endpoint that cannot be derived) contributes nothing. A probe that
is relevant but cannot reach a verdict because a required tool is unavailable (the ``mysql`` client or
``sacctmgr`` not installed) contributes a WARNING so the coverage gap is visible. The aggregate Result
status follows from the findings (see :meth:`Result.from_findings`).
"""

from pathlib import Path
from typing import List, Optional, Tuple

from pcluster_diag.core.constants import (
    ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS,
    ACCOUNTING_QUERY_LATENCY_FAIL_THRESHOLD_SECONDS,
    ACCOUNTING_QUERY_LATENCY_WARN_THRESHOLD_SECONDS,
    ACCOUNTING_QUERY_TIMEOUT_SECONDS,
    SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH,
    SLURM_STATE_CLUSTERNAME_PATH,
    SLURMCTLD_LOG_PATH,
    SLURMDBD_CONF_GROUP,
    SLURMDBD_CONF_MODE,
    SLURMDBD_CONF_OWNER,
    SLURMDBD_CONF_PATH,
)
from pcluster_diag.models.check import Check, run_probe
from pcluster_diag.models.context import Context, NodeType
from pcluster_diag.models.expected_path_permissions import ExpectedPathPermissions
from pcluster_diag.models.finding import CheckError, CheckWarning
from pcluster_diag.models.result import Result
from pcluster_diag.util import filesystem, shell
from pcluster_diag.util.network import (
    DEFAULT_DNS_TIMEOUT_SECONDS,
    DEFAULT_TCP_TIMEOUT_SECONDS,
    resolve_host,
    tcp_connect,
)
from pcluster_diag.util.slurm_accounting import (
    AccountingConfig,
    SecretAccessDenied,
    SecretNotFound,
    accounting_configured,
    contains_reserved_comment_char,
    get_secret_string,
    mysql_probe,
    parse_keyvalue_conf,
    resolve_accounting_config,
    secret_is_json_object,
)

# The slurmdbd daemon log, scanned read-only for blocking-error signatures when it is present on the
# head node (Local_Slurmdbd mode). Not a cookbook-managed path, so it is defined here.
SLURMDBD_LOG_PATH = "/var/log/slurmdbd.log"

# Read-only SQL issued by the credential/privilege probes.
_SQL_SELECT_ONE = "SELECT 1"
_SQL_SHOW_GRANTS = "SHOW GRANTS FOR CURRENT_USER()"

# Short, bounded timeout for the local ``systemctl is-active slurmdbd`` query.
_SYSTEMCTL_TIMEOUT_SECONDS = 10

# The literal placeholder the slurm_parallelcluster_slurmdbd.conf template renders for StoragePass
# before the real password is injected at runtime; it is never a usable password.
_STORAGE_PASS_TEMPLATE_DEFAULT = "dummy"

# The accounting configuration files present on the head node in Local_Slurmdbd mode, with their
# expected slurm:slurm 0600 ownership/mode. slurm_external_slurmdbd.conf is never present on the head
# node and is never inspected.
_ACCOUNTING_CONF_FILES: Tuple[ExpectedPathPermissions, ...] = (
    ExpectedPathPermissions(
        path=SLURMDBD_CONF_PATH,
        owner=SLURMDBD_CONF_OWNER,
        group=SLURMDBD_CONF_GROUP,
        mode=SLURMDBD_CONF_MODE,
        node_types=(NodeType.HEAD,),
    ),
    ExpectedPathPermissions(
        path=SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH,
        owner=SLURMDBD_CONF_OWNER,
        group=SLURMDBD_CONF_GROUP,
        mode=SLURMDBD_CONF_MODE,
        node_types=(NodeType.HEAD,),
    ),
)


class SlurmAccounting(Check):
    """Diagnose Slurm accounting (slurmdbd, database, credentials, configuration) as a single capability.

    Runs the accounting probes in order -- connectivity, credentials, configuration, read/write &
    end-to-end -- and folds their findings into one Result. Applies only on the head node and only when
    accounting is configured; otherwise the whole capability is not applicable. Local_Slurmdbd-only probes
    contribute nothing in ExternalSlurmdbd mode.
    """

    # --- Errors (a real problem that breaks accounting) ----------------------------------------
    SLURMDBD_UNREACHABLE = CheckError(
        1,
        "slurmdbd is not reachable at {0}:{1} within {2}s (network error: {3}). Verify that slurmdbd is "
        "running on the accounting endpoint and that the security group and host firewall permit inbound "
        "TCP to {0}:{1} from the head node.",
    )
    DB_DNS_RESOLUTION_FAILED = CheckError(
        2,
        "The Accounting_Database host {0} could not be resolved via DNS within {1}s (error: {2}). Verify "
        "that the database host derived from Database.Uri is correct and resolvable from the head node.",
    )
    DB_PORT_UNREACHABLE = CheckError(
        3,
        "The Accounting_Database is not reachable at {0}:{1} within {2}s (network error: {3}). This is "
        "commonly a security-group misconfiguration; verify that the database security group allows "
        "inbound TCP on {0}:{1} from the head node.",
    )
    PASSWORD_HAS_RESERVED_CHAR = CheckError(
        4,
        "The accounting database password (from {}) contains the '#' character. slurmdbd.conf treats '#' "
        "as the start of a comment, so slurmdbd silently truncates the password at the '#' and "
        "authentication then fails with a MySQL 1045 Access-denied error even though the raw credential "
        "is otherwise valid. Rotate the password to one that excludes the '#' character.",
    )
    SECRET_MISSING_IAM_PERMISSION = CheckError(
        5,
        "The accounting password secret {} could not be retrieved because the instance role lacks "
        "secretsmanager:GetSecretValue / secretsmanager:DescribeSecret permission. Grant the instance "
        "role access to the secret.",
    )
    SECRET_IS_JSON_OBJECT = CheckError(
        6,
        "The accounting password secret {} stores a JSON object of key/value pairs, but ParallelCluster "
        "expects a plaintext password string. Store the password as a plaintext secret value.",
    )
    CREDENTIALS_INVALID = CheckError(
        7,
        "Authentication to the Accounting_Database at {0}:{1} as user '{2}' was rejected (credentials "
        "from {3}). Verify the database user and the password stored in the secret. Detail: {4}",
    )
    DATABASE_ACCESS_DENIED = CheckError(
        8,
        "The database user '{0}' was denied access to the accounting database '{1}' at {2}:{3}. Grant the "
        "user access to that database. Detail: {4}",
    )
    AUTH_TIMED_OUT = CheckError(
        9,
        "Authentication to the Accounting_Database at {0}:{1} did not complete within {2}s. The database "
        "may be unreachable or overloaded.",
    )
    CONF_FILE_MISSING = CheckError(10, "The accounting configuration file '{}' is missing.")
    CONF_WRONG_OWNERSHIP = CheckError(
        11, "The accounting configuration file '{}' is owned by {}:{} but should be {}:{}."
    )
    CONF_WRONG_MODE = CheckError(12, "The accounting configuration file '{}' has mode {} but should be {}.")
    CONF_FILE_UNREADABLE = CheckError(
        13, "The accounting configuration file '{}' is present but cannot be read (permission denied)."
    )
    CONFIG_ENDPOINT_INCONSISTENT = CheckError(
        14,
        "The accounting database endpoint in slurm_parallelcluster_slurmdbd.conf is inconsistent with "
        "Database.Uri: {}.",
    )
    SLURMDBD_UP_BUT_NOT_ACCEPTING = CheckError(
        15,
        "slurmdbd reports active to systemd but is not accepting connections on {}:{} (error: {}). This "
        "commonly indicates an in-progress schema migration; wait for the migration to complete and "
        "re-check before restarting slurmdbd.",
    )
    DB_MISSING_PRIVILEGES = CheckError(
        16,
        "The accounting database user '{}' is missing the following privileges required for the "
        "accounting schema: {}. Grant these privileges on the accounting database.",
    )
    QUERY_FAILED = CheckError(
        17,
        "The end-to-end accounting query '{}' failed ({}). Accounting is not functional end to end; "
        "inspect slurmdbd and the accounting database.",
    )
    QUERY_EXCESSIVE_LATENCY = CheckError(
        18,
        "The accounting query '{}' took {:.3f}s, exceeding the {:.0f}s fail threshold. Excessive "
        "accounting-query latency stalls slurmctld scheduling and can block cluster operations.",
    )
    LOG_VERSION_INCOMPATIBILITY = CheckError(
        19,
        "The slurm logs indicate a Slurm version incompatibility between slurmctld and slurmdbd ({}). "
        "Bring slurmdbd to the same Slurm version as slurmctld.",
    )
    LOG_CLUSTER_ID_MISMATCH = CheckError(
        20,
        "The slurm logs indicate a cluster-ID mismatch: slurmctld state records the cluster name '{}' "
        "(see {}), which disagrees with what slurmdbd expects. Reconcile the cluster identifier via that "
        "clustername file.",
    )

    # --- Warnings (elevated latency, and coverage gaps when a required tool is unavailable) ----
    QUERY_ELEVATED_LATENCY = CheckWarning(
        1,
        "The accounting query '{}' took {:.3f}s, above the {:.0f}s warn threshold. Elevated "
        "accounting-query latency can delay slurmctld scheduling and slow cluster operations.",
    )
    MYSQL_UNAVAILABLE = CheckWarning(
        2,
        "The 'mysql' client is not available on the head node, so the accounting database credentials and "
        "privileges could not be verified.",
    )
    SACCTMGR_UNAVAILABLE = CheckWarning(
        3,
        "The 'sacctmgr' client is not available, so end-to-end accounting responsiveness could not be measured.",
    )

    # slurmctld/slurmdbd log signatures of a version incompatibility.
    _VERSION_SIGNATURES = (
        "Failed to unpack SLURM_PERSIST_INIT message",
        "Incompatible versions of client and server code",
    )
    # Log signature of a cluster-ID mismatch.
    _CLUSTER_ID_SIGNATURE = "CLUSTER ID MISMATCH"

    @property
    def description(self) -> str:
        """Return the human-readable description of this Check."""
        return "Verify that Slurm accounting (slurmdbd, database, credentials, and configuration) is healthy."

    def should_run(self, context: Context) -> bool:
        """Run only on the head node and only when Slurm accounting is configured."""
        if context.node_type is not NodeType.HEAD:
            return False
        configured, _missing_signal = accounting_configured(context)
        return configured

    def run(self, context: Context) -> Result:
        """Run every accounting probe in isolation, accumulate findings, and derive the aggregate Result.

        Each probe is run through :func:`~pcluster_diag.models.check.run_probe`, so an unexpected exception
        in one probe becomes an error finding for that probe alone and never sinks its siblings' findings.
        """
        errors: List[CheckError] = []
        warnings: List[CheckWarning] = []
        config = resolve_accounting_config(context)

        probes = (
            ("slurmdbd endpoint reachability", lambda: self._probe_slurmdbd_endpoint(config, errors)),
            ("database reachability", lambda: self._probe_database_reachable(config, errors)),
            ("password reserved character", lambda: self._probe_password_reserved_char(config, errors)),
            ("password secret", lambda: self._probe_secret_well_formed(config, errors)),
            ("database credentials", lambda: self._probe_credentials_valid(config, errors, warnings)),
            ("configuration files", lambda: self._probe_config_files(config, errors)),
            ("configuration consistency", lambda: self._probe_config_consistent(config, errors)),
            ("slurmdbd accepting connections", lambda: self._probe_slurmdbd_accepting(config, errors)),
            ("database privileges", lambda: self._probe_db_privileges(config, errors, warnings)),
            ("end-to-end query", lambda: self._probe_queries_healthy(errors, warnings)),
            ("slurm logs", lambda: self._probe_logs(errors)),
        )
        for label, probe in probes:
            run_probe(label, probe, errors)

        return Result.from_findings(self, errors=errors, warnings=warnings)

    # --- Connectivity probes ------------------------------------------------------------------

    def _probe_slurmdbd_endpoint(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail when the slurmdbd accounting endpoint cannot be reached over TCP (both topology modes)."""
        host, port = config.slurmdbd_host, config.slurmdbd_port
        if not host or not port:
            return
        result = tcp_connect(host, port, timeout=DEFAULT_TCP_TIMEOUT_SECONDS)
        if not result.connected:
            errors.append(self.SLURMDBD_UNREACHABLE.format(host, port, DEFAULT_TCP_TIMEOUT_SECONDS, result.error))

    def _probe_database_reachable(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail when the Accounting_Database host does not resolve or its port is unreachable (local only)."""
        if config.is_external:
            return
        host, port = config.db_host, config.db_port
        if not host or not port:
            return
        dns = resolve_host(host, timeout=DEFAULT_DNS_TIMEOUT_SECONDS)
        if not dns.resolved:
            errors.append(self.DB_DNS_RESOLUTION_FAILED.format(host, DEFAULT_DNS_TIMEOUT_SECONDS, dns.error))
            return
        tcp = tcp_connect(host, port, timeout=DEFAULT_TCP_TIMEOUT_SECONDS)
        if not tcp.connected:
            errors.append(self.DB_PORT_UNREACHABLE.format(host, port, DEFAULT_TCP_TIMEOUT_SECONDS, tcp.error))

    # --- Credentials probes -------------------------------------------------------------------

    def _probe_password_reserved_char(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail when the resolved accounting password contains the reserved '#' comment char (local only)."""
        if config.is_external:
            return
        password = _resolve_password(config)
        if password is None:
            return
        if contains_reserved_comment_char(password):
            source = config.password_secret_arn or SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH
            errors.append(self.PASSWORD_HAS_RESERVED_CHAR.format(source))

    def _probe_secret_well_formed(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail on missing IAM permission or a JSON-object secret; contribute nothing when absent (local only)."""
        if config.is_external:
            return
        if not config.password_secret_arn or not config.region:
            return
        try:
            secret = get_secret_string(config.password_secret_arn, config.region)
        except SecretAccessDenied:
            errors.append(self.SECRET_MISSING_IAM_PERMISSION.format(config.password_secret_arn))
            return
        except SecretNotFound:
            return
        if secret_is_json_object(secret):
            errors.append(self.SECRET_IS_JSON_OBJECT.format(config.password_secret_arn))

    def _probe_credentials_valid(
        self, config: AccountingConfig, errors: List[CheckError], warnings: List[CheckWarning]
    ) -> None:
        """Fail on rejected credentials/timeout; warn when the mysql client is unavailable (local only)."""
        if config.is_external:
            return
        password = _resolve_password(config)
        if _missing_credentials(config, password):
            return
        try:
            auth = mysql_probe(
                config.db_host,
                config.db_port,
                config.db_user,
                password,
                database=None,
                sql=_SQL_SELECT_ONE,
                timeout=ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS,
                secret_for_redaction=password,
            )
        except OSError:
            warnings.append(self.MYSQL_UNAVAILABLE)
            return

        if auth.timed_out:
            errors.append(
                self.AUTH_TIMED_OUT.format(config.db_host, config.db_port, ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS)
            )
            return
        if not auth.succeeded:
            errors.append(
                self.CREDENTIALS_INVALID.format(
                    config.db_host,
                    config.db_port,
                    config.db_user,
                    config.password_secret_arn or SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH,
                    auth.stderr.strip() or "returncode {}".format(auth.returncode),
                )
            )
            return
        if config.db_name:
            self._probe_database_access(config, password, errors, warnings)

    def _probe_database_access(
        self, config: AccountingConfig, password: Optional[str], errors: List[CheckError], warnings: List[CheckWarning]
    ) -> None:
        """Fail when the authenticated user is denied access to the named accounting database (local only)."""
        try:
            db_access = mysql_probe(
                config.db_host,
                config.db_port,
                config.db_user,
                password,
                database=config.db_name,
                sql=_SQL_SELECT_ONE,
                timeout=ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS,
                secret_for_redaction=password,
            )
        except OSError:
            warnings.append(self.MYSQL_UNAVAILABLE)
            return

        if db_access.timed_out:
            errors.append(
                self.AUTH_TIMED_OUT.format(config.db_host, config.db_port, ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS)
            )
            return
        if not db_access.succeeded:
            errors.append(
                self.DATABASE_ACCESS_DENIED.format(
                    config.db_user,
                    config.db_name,
                    config.db_host,
                    config.db_port,
                    db_access.stderr.strip() or "returncode {}".format(db_access.returncode),
                )
            )

    # --- Configuration probes -----------------------------------------------------------------

    def _probe_config_files(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail on any missing/mis-permissioned/unreadable local slurmdbd conf file (local only)."""
        if config.is_external:
            return
        for expected in _ACCOUNTING_CONF_FILES:
            errors.extend(self._inspect_conf_file(expected))

    def _inspect_conf_file(self, expected: ExpectedPathPermissions) -> List[CheckError]:
        """Return the CheckErrors for ``expected``: empty when present, readable, and correctly permissioned."""
        try:
            observed = filesystem.stat_path(expected.path)
        except FileNotFoundError:
            return [self.CONF_FILE_MISSING.format(expected.path)]

        errors: List[CheckError] = []
        if observed.owner != expected.owner or observed.group != expected.group:
            errors.append(
                self.CONF_WRONG_OWNERSHIP.format(
                    expected.path, observed.owner, observed.group, expected.owner, expected.group
                )
            )
        if observed.mode != expected.mode:
            errors.append(self.CONF_WRONG_MODE.format(expected.path, observed.mode, expected.mode))
        if not _is_readable(expected.path):
            errors.append(self.CONF_FILE_UNREADABLE.format(expected.path))
        return errors

    def _probe_config_consistent(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail when slurm_parallelcluster_slurmdbd.conf's StorageHost/StoragePort disagree with Database.Uri.

        Local only. When the conf file cannot be read, this contributes nothing (a missing file is
        reported by the config-files probe).
        """
        if config.is_external:
            return
        try:
            conf = parse_keyvalue_conf(SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH)
        except OSError:
            return

        mismatches: List[str] = []
        storage_host = conf.get("StorageHost")
        if config.db_host and storage_host and storage_host != config.db_host:
            mismatches.append(
                "StorageHost is '{}' (slurm_parallelcluster_slurmdbd.conf) but Database.Uri implies '{}'".format(
                    storage_host, config.db_host
                )
            )

        storage_port = conf.get("StoragePort")
        if config.db_port is not None and storage_port:
            try:
                observed_port = int(storage_port)
            except ValueError:
                mismatches.append(
                    "StoragePort is '{}' (slurm_parallelcluster_slurmdbd.conf), which is not a valid port; "
                    "Database.Uri implies {}".format(storage_port, config.db_port)
                )
            else:
                if observed_port != config.db_port:
                    mismatches.append(
                        "StoragePort is {} (slurm_parallelcluster_slurmdbd.conf) but Database.Uri implies "
                        "{}".format(observed_port, config.db_port)
                    )

        if mismatches:
            errors.append(self.CONFIG_ENDPOINT_INCONSISTENT.format("; ".join(mismatches)))

    # --- Read/write & end-to-end probes -------------------------------------------------------

    def _probe_slurmdbd_accepting(self, config: AccountingConfig, errors: List[CheckError]) -> None:
        """Fail when systemd reports slurmdbd active but its port is closed (local only).

        A stopped slurmdbd surfaces through the endpoint-reachability and query probes instead, so this
        only inspects the "active but not accepting" case (commonly an in-progress schema migration).
        """
        if config.is_external:
            return
        active = shell.run_command(["systemctl", "is-active", "slurmdbd"], timeout=_SYSTEMCTL_TIMEOUT_SECONDS)
        if active.stdout.strip() != "active":
            return
        host, port = config.slurmdbd_host, config.slurmdbd_port
        if host and port:
            tcp = tcp_connect(host, port, timeout=DEFAULT_TCP_TIMEOUT_SECONDS)
            if not tcp.connected:
                errors.append(self.SLURMDBD_UP_BUT_NOT_ACCEPTING.format(host, port, tcp.error))

    def _probe_db_privileges(
        self, config: AccountingConfig, errors: List[CheckError], warnings: List[CheckWarning]
    ) -> None:
        """Fail when the database user lacks create/read/write privileges; warn if mysql is unavailable (local only).

        A failed/empty grants probe is authoritatively reported by the credentials probe, so it
        contributes nothing here.
        """
        if config.is_external:
            return
        password = _resolve_password(config)
        if _missing_credentials(config, password):
            return
        try:
            probe = mysql_probe(
                config.db_host,
                config.db_port,
                config.db_user,
                password,
                database=None,
                sql=_SQL_SHOW_GRANTS,
                timeout=ACCOUNTING_DB_AUTH_TIMEOUT_SECONDS,
                secret_for_redaction=password,
            )
        except OSError:
            warnings.append(self.MYSQL_UNAVAILABLE)
            return

        if not probe.succeeded or not probe.stdout.strip():
            return
        missing_privileges = _missing_privileges(probe.stdout)
        if missing_privileges:
            errors.append(self.DB_MISSING_PRIVILEGES.format(config.db_user, ", ".join(missing_privileges)))

    def _probe_queries_healthy(self, errors: List[CheckError], warnings: List[CheckWarning]) -> None:
        """Time an end-to-end sacctmgr query; fail on failure/excessive latency, warn on elevated latency.

        Applies in both topology modes. Warns when sacctmgr is unavailable (responsiveness cannot be
        measured).
        """
        command = ["sacctmgr", "-n", "show", "cluster"]
        label = " ".join(command)
        try:
            timed = shell.time_command(command, timeout=ACCOUNTING_QUERY_TIMEOUT_SECONDS)
        except OSError:
            warnings.append(self.SACCTMGR_UNAVAILABLE)
            return

        if timed.timed_out:
            errors.append(self.QUERY_FAILED.format(label, "timed out after {:.0f}s".format(timed.elapsed_seconds)))
            return
        if timed.returncode != 0:
            detail = "exit code {}: {}".format(timed.returncode, timed.stderr.strip())
            errors.append(self.QUERY_FAILED.format(label, detail))
            return

        elapsed = timed.elapsed_seconds
        if elapsed > ACCOUNTING_QUERY_LATENCY_FAIL_THRESHOLD_SECONDS:
            errors.append(
                self.QUERY_EXCESSIVE_LATENCY.format(label, elapsed, ACCOUNTING_QUERY_LATENCY_FAIL_THRESHOLD_SECONDS)
            )
            return
        if elapsed > ACCOUNTING_QUERY_LATENCY_WARN_THRESHOLD_SECONDS:
            warnings.append(
                self.QUERY_ELEVATED_LATENCY.format(label, elapsed, ACCOUNTING_QUERY_LATENCY_WARN_THRESHOLD_SECONDS)
            )

    def _probe_logs(self, errors: List[CheckError]) -> None:
        """Fail on a version-incompatibility or cluster-ID-mismatch signature in the slurm logs (both modes)."""
        logs = _read_logs(SLURMCTLD_LOG_PATH, SLURMDBD_LOG_PATH)
        if any(signature in logs for signature in self._VERSION_SIGNATURES):
            errors.append(self.LOG_VERSION_INCOMPATIBILITY.format("version-mismatch signature in the slurm logs"))
            return
        if self._CLUSTER_ID_SIGNATURE in logs.upper():
            state_cluster_name = _read_state_cluster_name()
            errors.append(
                self.LOG_CLUSTER_ID_MISMATCH.format(state_cluster_name or "unknown", SLURM_STATE_CLUSTERNAME_PATH)
            )


# --- Internal helpers (credentials, config, logs) ----------------------------------


def _resolve_password(config: AccountingConfig) -> Optional[str]:
    """Return the resolved database password, or ``None`` when it cannot be obtained.

    The authoritative source is ``Database.PasswordSecretArn`` (the value ParallelCluster injects into
    ``slurm_parallelcluster_slurmdbd.conf`` at runtime). Expected secret errors (access denied / not
    found) are swallowed so this helper never raises for them; the secret probe reports those. When the
    ARN is unavailable, the helper falls back to a usable ``StoragePass`` from
    ``slurm_parallelcluster_slurmdbd.conf`` (the template default ``dummy`` is not usable). This helper
    never emits the password; callers redact it.
    """
    if config.password_secret_arn and config.region:
        try:
            return get_secret_string(config.password_secret_arn, config.region)
        except (SecretAccessDenied, SecretNotFound):
            pass  # Fall back to StoragePass below; the secret probe reports these conditions.

    try:
        conf = parse_keyvalue_conf(SLURM_PARALLELCLUSTER_SLURMDBD_CONF_PATH)
    except OSError:
        return None
    storage_pass = conf.get("StoragePass")
    if storage_pass and storage_pass != _STORAGE_PASS_TEMPLATE_DEFAULT:
        return storage_pass
    return None


def _missing_credentials(config: AccountingConfig, password: Optional[str]) -> Optional[str]:
    """Return a human-readable name of the first missing probe input, or ``None`` when all are present."""
    if not config.db_host:
        return "database host (Database.Uri)"
    if not config.db_port:
        return "database port (Database.Uri)"
    if not config.db_user:
        return "database user (Database.UserName)"
    if not password:
        return "database password (PasswordSecretArn / StoragePass)"
    return None


def _missing_privileges(grants_text: str) -> List[str]:
    """Return which of create/read/write privileges are absent from ``grants_text`` (empty when all present).

    ``ALL PRIVILEGES`` (or ``ALL``) satisfies every requirement. Otherwise CREATE covers create, SELECT
    covers read, and INSERT or UPDATE covers write. Parsing is case-insensitive.
    """
    upper = grants_text.upper()
    all_privileges = "ALL PRIVILEGES" in upper or "GRANT ALL " in upper
    missing: List[str] = []
    if not (all_privileges or "CREATE" in upper):
        missing.append("CREATE")
    if not (all_privileges or "SELECT" in upper):
        missing.append("SELECT (read)")
    if not (all_privileges or "INSERT" in upper or "UPDATE" in upper):
        missing.append("INSERT/UPDATE (write)")
    return missing


def _is_readable(path: str) -> bool:
    """Return whether ``path`` can be opened for reading (``False`` only on ``PermissionError``)."""
    try:
        with open(path, "rb"):
            return True
    except PermissionError:
        return False
    except OSError:
        # A non-permission error (e.g. a race that removed the file) is not a readability finding here;
        # presence is handled separately.
        return True


def _read_logs(*paths: str) -> str:
    """Return the concatenated contents of the readable log files among ``paths`` (missing ones skipped)."""
    chunks: List[str] = []
    for path in paths:
        try:
            chunks.append(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def _read_state_cluster_name() -> Optional[str]:
    """Return the cluster name recorded in Slurm's StateSaveLocation clustername file, or ``None``."""
    try:
        return Path(SLURM_STATE_CLUSTERNAME_PATH).read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        return None
