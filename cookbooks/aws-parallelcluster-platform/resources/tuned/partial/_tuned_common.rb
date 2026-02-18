# frozen_string_literal: true

# Copyright:: 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

unified_mode true
default_action :setup

action :setup do
  return if on_docker?

  desired_profile = node['cluster']['tuned']['profile']

  execute "Set tuned profile to #{desired_profile}" do
    command "tuned-adm profile #{desired_profile}"
    only_if "which tuned-adm && tuned-adm list | grep -q '- #{desired_profile} '"
    not_if "tuned-adm active | grep -q 'Current active profile: #{desired_profile}'"
  end
end
