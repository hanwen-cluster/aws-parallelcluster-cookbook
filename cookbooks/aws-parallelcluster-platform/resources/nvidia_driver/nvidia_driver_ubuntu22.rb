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

provides :nvidia_driver, platform: 'ubuntu' do |node|
  node['platform_version'].to_i == 22
end

use 'partial/_nvidia_driver_common.rb'

def rebuild_initramfs?
  true
end

def set_compiler?
  true
end

def compiler_version
  'gcc'
end

def extra_packages
  %w()
end

def compiler_path
  gcc_major_version = gcc_major_version_used_by_kernel

  # If the gcc version used to compile the kernel cannot be detected,
  # empty string is returned, meaning that the NVIDIA driver will be compiled
  # using the system default compiler.
  return "" if gcc_major_version.nil?

  "CC=/usr/bin/gcc-#{gcc_major_version}"
end
