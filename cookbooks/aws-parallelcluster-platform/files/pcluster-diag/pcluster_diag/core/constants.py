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

"""Shared constants."""

# General
PACKAGE_NAME = "pcluster-diag"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H-%M-%S"

# Relevant paths
DEFAULT_DNA_JSON_PATH = "/etc/chef/dna.json"
DEFAULT_CLUSTER_CONFIG_PATH = "/opt/parallelcluster/shared/cluster-config.yaml"
DEFAULT_BOOTSTRAPPED_PATH = "/opt/parallelcluster/.bootstrapped"

# cfn-hup runs as a supervisord program (not a systemd service) managed via the cookbook virtualenv's
# supervisorctl, reading the supervisord config installed by the cookbook.
CFN_HUP_PROGRAM = "cfn-hup"
SUPERVISORCTL_GLOB = "/opt/parallelcluster/pyenv/versions/*/envs/cookbook_virtualenv/bin/supervisorctl"

SLURM_CONF_RELATIVE_PATH = "etc/slurm.conf"

# The supervisord state token that indicates a program is up.
SUPERVISORD_RUNNING_STATE = "RUNNING"

# ParallelCluster management daemons that supervisord must keep RUNNING, keyed by node type value
# (see the cookbook's parallelcluster_supervisord.conf.erb). cfn-hup is intentionally excluded: it has
# its own dedicated check (CfnHupRunsOnlyOnHeadNode).
NODE_TYPE_EXPECTED_DAEMONS = {
    "HeadNode": ("clustermgtd", "clusterstatusmgtd"),
    "ComputeFleet": ("computemgtd",),
    "LoginNode": ("loginmgtd",),
}

# clustermgtd writes a heartbeat file that compute nodes read to decide whether the head node is still
# managing the fleet.
DEFAULT_SLURM_INSTALL_DIR = "/opt/slurm"
CLUSTERMGTD_HEARTBEAT_RELATIVE_PATH = "etc/pcluster/.slurm_plugin/clustermgtd_heartbeat"
CLUSTERMGTD_HEARTBEAT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f%z"
# Age beyond which the heartbeat is considered stale. Mirrors computemgtd's default clustermgtd_timeout
# (600s): once the heartbeat is older than this, compute nodes treat the head node as offline and can
# self-terminate.
CLUSTERMGTD_HEARTBEAT_STALE_THRESHOLD_SECONDS = 600
# Hard cap on reading the heartbeat file. The file may live on a shared/networked filesystem, so a read
# is done via a timed command: hitting this cap means the filesystem is wedged, which is itself a signal.
CLUSTERMGTD_HEARTBEAT_READ_TIMEOUT_SECONDS = 30

# Directory service
SSSD_CONF_PATH = "/etc/sssd/sssd.conf"
NSS_SLURM_LAUNCH_PARAMETER = "enable_nss_slurm"

DIRECTORY_LOOKUP_WARN_THRESHOLD_SECONDS = 2.0
DIRECTORY_LOOKUP_FAIL_THRESHOLD_SECONDS = 10.0
# Hard cap so a probe never hangs indefinitely on a stuck directory backend.
DIRECTORY_LOOKUP_COMMAND_TIMEOUT_SECONDS = 30
