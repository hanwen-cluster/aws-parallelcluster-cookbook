# frozen_string_literal: true

# Copyright:: 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

provides :gdrcopy, platform: 'ubuntu' do |node|
  node['platform_version'].to_i >= 22
end

use 'partial/_gdrcopy_common.rb'

def gdrcopy_dependencies
  %w(dkms)
end

def gdrcopy_arch
  arm_instance? ? 'arm64' : 'amd64'
end

# The gdrcopy-tests package is tagged with the CUDA major.minor it was built
# against (e.g. gdrcopy-tests_2.6-1_amd64.Ubuntu22_04+cuda13.0.deb).
def gdrcopy_cuda_suffix
  "+cuda#{gdrcopy_cuda_version}"
end

# Prebuilt debs to download, matching NVIDIA's redist naming, e.g.:
#   gdrdrv-dkms_2.6-1_amd64.Ubuntu22_04.deb
#   libgdrapi_2.6-1_amd64.Ubuntu22_04.deb
#   gdrcopy-tests_2.6-1_amd64.Ubuntu22_04+cuda13.0.deb
#   gdrcopy_2.6-1_amd64.Ubuntu22_04.deb
def gdrcopy_packages
  [
    "gdrdrv-dkms_#{gdrcopy_version_extended}_#{gdrcopy_arch}.#{gdrcopy_platform}.deb",
    "libgdrapi_#{gdrcopy_version_extended}_#{gdrcopy_arch}.#{gdrcopy_platform}.deb",
    "gdrcopy-tests_#{gdrcopy_version_extended}_#{gdrcopy_arch}.#{gdrcopy_platform}#{gdrcopy_cuda_suffix}.deb",
    "gdrcopy_#{gdrcopy_version_extended}_#{gdrcopy_arch}.#{gdrcopy_platform}.deb",
  ]
end

def gdrcopy_install_command
  # Install all debs in one dpkg invocation so it can satisfy the
  # inter-package dependencies within the set (gdrcopy -> libgdrapi, etc.).
  "dpkg -i #{gdrcopy_packages.join(' ')}"
end

def gdrcopy_service
  'gdrdrv'
end

# NVIDIA redist distro directory segment used in the download path. Note it uses
# an underscore (ubuntu22_04), unlike the CUDA-repo form (ubuntu2204). Distinct
# from gdrcopy_platform, the package filename tag (Ubuntu22_04).
def gdrcopy_redist_distro
  "ubuntu#{node['platform_version'].gsub('.', '_')}"
end

# Tag embedded in the package filenames (e.g. libgdrapi_2.6-1_amd64.Ubuntu22_04.deb).
def gdrcopy_platform
  "Ubuntu#{node['platform_version'].gsub(/\./, '_')}"
end
