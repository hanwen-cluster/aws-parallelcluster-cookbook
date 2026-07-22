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

def gdrcopy_version
  node['cluster']['nvidia']['gdrcopy']['version']
end

def gdrcopy_enabled?
  nvidia_enabled?
end

# True if gdrcopy is installed (regardless of version). Like nvidia-smi for the
# driver, the gdrcopy_sanity binary is the one of the test commands that are
# installed by GDRCopy and we use it as signal of a healthy install
# and is installed to /usr/bin on all platforms.
def gdrcopy_installed?
  ::File.exist?('/usr/bin/gdrcopy_sanity')
end

unified_mode true
default_action :setup

action :setup do
  return unless gdrcopy_enabled?
  return if on_docker?

  # Skip install if already installed (e.g. DLAMI).
  return if gdrcopy_installed?

  # Save gdrcopy version for InSpec tests
  node.default['cluster']['nvidia']['gdrcopy']['version'] = gdrcopy_version
  node.default['cluster']['nvidia']['gdrcopy']['service'] = gdrcopy_service
  node_attributes 'dump node attributes'

  directory node['cluster']['sources_dir'] do
    recursive true
  end

  package_repos 'update package repos' do
    action :update
  end

  # The gdrcopy kernel module (gdrdrv) ships as a DKMS package that is rebuilt
  # against the running kernel at install time, so dkms and the kernel build
  # toolchain must be present. This is the only build step; it runs under
  # /var/lib/dkms, never /tmp, so it is unaffected by a noexec /tmp mount.
  robust_package 'install gdrcopy dependencies' do
    packages gdrcopy_dependencies
  end

  # Download the prebuilt packages and install them directly. No source build.
  gdrcopy_packages.each do |package_file|
    remote_file "#{node['cluster']['sources_dir']}/#{package_file}" do
      source "#{gdrcopy_url_prefix}/#{package_file}"
      mode '0644'
      retries 3
      retry_delay 5
      action :create_if_missing
    end
  end

  bash 'Install NVIDIA GDRCopy' do
    user 'root'
    group 'root'
    cwd node['cluster']['sources_dir']
    code <<-GDRCOPY_INSTALL
    set -e
    #{gdrcopy_install_command}
    GDRCOPY_INSTALL
  end

  service gdrcopy_service do
    action %i(disable stop)
  end
end

action :verify do
  %w(copybw).each do |command|
    bash "Verify NVIDIA GDRCopy: #{command}" do
      user 'root'
      group 'root'
      cwd Chef::Config[:file_cache_path]
      code <<-GDRCOPY_VERIFY
      set -e
      #{command}
      GDRCOPY_VERIFY
    end
  end
end

action :configure do
  return if on_docker?
  # Save gdrcopy version for InSpec tests
  node.default['cluster']['nvidia']['gdrcopy']['version'] = gdrcopy_version
  node_attributes 'dump node attributes'

  if graphic_instance? && is_service_installed?(gdrcopy_service)
    # NVIDIA GDRCopy
    execute "enable #{gdrcopy_service} service" do
      # Using command in place of service resource because of: https://github.com/chef/chef/issues/12053
      command "systemctl enable #{gdrcopy_service}"
    end
    service gdrcopy_service do
      action :start
      supports status: true
    end
  end
end

def gdrcopy_version_extended
  "#{gdrcopy_version}-1"
end

# CUDA major.minor the packages were built against (e.g. 13.0). Used both for
# the redist path segment and, on Ubuntu, the gdrcopy-tests filename suffix.
def gdrcopy_cuda_version
  node['cluster']['nvidia']['cuda']['version'].split('.')[0..1].join('.')
end

# NVIDIA redist arch directory: x64 / aarch64 (note: x64, not x86_64). Same for
# both the RHEL and Ubuntu redist trees.
def gdrcopy_redist_arch
  arm_instance? ? 'aarch64' : 'x64'
end

# Download prefix mirroring NVIDIA's redist tree, so the same builder works for
# both the S3 mirror (default base_url) and NVIDIA's redist directly (when a
# user overrides base_url to point at it):
#   {base_url}/CUDA <major.minor>/<distro>/<arch>/<filename>
# The space in "CUDA 13.0" is percent-encoded so the URL is valid for both S3
# and the NVIDIA CDN.
def gdrcopy_url_prefix
  "#{node['cluster']['nvidia']['gdrcopy']['base_url']}/CUDA%20#{gdrcopy_cuda_version}/#{gdrcopy_redist_distro}/#{gdrcopy_redist_arch}"
end
