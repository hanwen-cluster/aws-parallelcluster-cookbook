# frozen_string_literal: true

#
# Cookbook:: aws-parallelcluster
# Recipe:: remount_tmp_noexec
#
# Copyright:: 2013-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the
# License. A copy of the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "LICENSE.txt" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and
# limitations under the License.

# TEST ONLY (PCLUSTER-3858) - not set in production builds.
# Remounts /tmp as noexec so that any bootstrap step that executes from /tmp fails fast.
# This is a test knob to validate noexec compliance during both build-image and create-cluster;
# ParallelCluster does not enforce noexec on /tmp by default.
if node['cluster']['tmp_noexec'] == 'true'
  execute 'TEST ONLY - remount /tmp as noexec' do
    command 'mount --bind /tmp /tmp && mount -o remount,bind,noexec,nosuid,nodev /tmp'
    not_if 'findmnt -no OPTIONS /tmp | grep -qw noexec'
  end
end
