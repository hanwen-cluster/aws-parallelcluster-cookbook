# frozen_string_literal: true
#
# Copyright:: 2013-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "LICENSE.txt" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
# See the License for the specific language governing permissions and limitations under the License.

def gdrcopy_service
  'gdrcopy'
end

def gdrcopy_dependencies
  %w(dkms)
end

# NVIDIA redist distro directory segment used in the download path
# (e.g. rhel9). Distinct from gdrcopy_platform below, which is the tag embedded
# in the package *filenames* (el9). Default for redhat/rocky; Amazon Linux 2023
# overrides it to reuse the rhel9 redist directory.
def gdrcopy_redist_distro
  "rhel#{node['platform_version'].to_i}"
end

# Tag embedded in the package filenames (e.g. gdrcopy-2.6-1.el9.x86_64.rpm).
# Default for redhat/rocky; Amazon Linux 2023 overrides it to el9.
def gdrcopy_platform
  "el#{node['platform_version'].to_i}"
end

def gdrcopy_arch
  arm_instance? ? 'aarch64' : 'x86_64'
end

# Prebuilt RPMs to download, matching NVIDIA's redist naming, e.g.:
#   gdrcopy-kmod-2.6-1dkms.el9.noarch.rpm
#   gdrcopy-2.6-1.el9.x86_64.rpm
#   gdrcopy-devel-2.6-1.el9.noarch.rpm
def gdrcopy_packages
  [
    "gdrcopy-kmod-#{gdrcopy_version_extended}dkms.#{gdrcopy_platform}.noarch.rpm",
    "gdrcopy-#{gdrcopy_version_extended}.#{gdrcopy_platform}.#{gdrcopy_arch}.rpm",
    "gdrcopy-devel-#{gdrcopy_version_extended}.#{gdrcopy_platform}.noarch.rpm",
  ]
end

def gdrcopy_install_command
  # The install is idempotent at the resource level (action :setup returns early
  # when gdrcopy is already installed), so a single rpm transaction over all the
  # downloaded files is enough; passing them together lets rpm resolve the
  # inter-package dependencies.
  "rpm -Uvh #{gdrcopy_packages.join(' ')}"
end
