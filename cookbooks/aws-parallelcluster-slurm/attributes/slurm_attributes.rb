# URLs to software packages used during install recipes
default['cluster']['slurm']['fleet_config_path'] = "#{node['cluster']['slurm_plugin_dir']}/fleet-config.json"

default['cluster']['dns_domain'] = nil
default['cluster']['use_private_hostname'] = 'false'

default['cluster']['realmemory_to_ec2memory_ratio'] = 0.95
default['cluster']['slurm_node_reg_mem_percent'] = 75
default['cluster']['slurmdbd_response_retries'] = 30
default['cluster']['slurm_plugin_console_logging']['sample_size'] = 1
default["cluster"]["scheduler_compute_resource_name"] = nil

default['cluster']['enable_nss_slurm'] = node['cluster']['directory_service']['enabled']

# PMIX Version and Checksum
default['cluster']['pmix']['version'] = '5.0.6'
default['cluster']['pmix']['sha256'] = '5a5e0cd36067144e2171d59164d59ea478a2e540ccf4eee4530f55fc6e8cf78b'

# Slurmdbd
default['cluster']['slurmdbd_service_enabled'] = "true"

# Spank
default['cluster']['slurm']['spank_config_dir'] = "#{node['cluster']['slurm']['install_dir']}/etc/plugstack.conf.d"

# Pyxis
default['cluster']['pyxis']['version'] = '0.20.0'
default['cluster']['pyxis']['runtime_path'] = '/run/pyxis'
