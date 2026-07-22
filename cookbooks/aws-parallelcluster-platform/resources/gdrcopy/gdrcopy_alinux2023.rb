# frozen_string_literal: true

# Copyright:: 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

provides :gdrcopy, platform: 'amazon' do |node|
  node['platform_version'].to_i == 2023
end

use 'partial/_gdrcopy_common.rb'
use 'partial/_gdrcopy_common_rhel.rb'

# NVIDIA does not publish Amazon Linux 2023 gdrcopy packages, so AL2023 reuses
# the RHEL9 (el9) build. It is ABI-compatible (both AL2023 and RHEL9 are glibc
# 2.34) and the kernel module is a DKMS source package rebuilt locally against
# the AL2023 kernel, so the el9 tag does not affect the module. Everything else
# (enabled?, arch, packages, install) comes from the shared RHEL partial.
#
# Both the redist directory (gdrcopy_redist_distro) and the filename tag
# (gdrcopy_platform) point at rhel9/el9 so AL2023 downloads the same packages
# from the same redist path as RHEL9 (no duplicated mirror files).
def gdrcopy_redist_distro
  'rhel9'
end

def gdrcopy_platform
  'el9'
end
