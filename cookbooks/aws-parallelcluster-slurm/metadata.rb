# frozen_string_literal: true

name 'aws-parallelcluster-slurm'
maintainer 'Amazon Web Services'
license 'Apache-2.0'
description 'Manages Slurm in AWS ParallelCluster'
issues_url 'https://github.com/aws/aws-parallelcluster-cookbook/issues'
source_url 'https://github.com/aws/aws-parallelcluster-cookbook'
chef_version '>= 18'
version '3.13.0'

depends 'iptables', '~> 8.0.0'
depends 'line', '~> 4.5.21'
depends 'nfs', '~> 5.1.5'
depends 'openssh', '~> 2.11.14'
depends 'yum', '~> 7.4.20'
depends 'yum-epel', '~> 5.0.8'
depends 'aws-parallelcluster-computefleet', '~> 3.13.0'
depends 'aws-parallelcluster-environment', '~> 3.13.0'
depends 'aws-parallelcluster-shared', '~> 3.13.0'
