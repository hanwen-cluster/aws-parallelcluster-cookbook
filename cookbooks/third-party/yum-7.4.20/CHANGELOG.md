# yum Cookbook CHANGELOG

This file is used to list changes made in each version of the yum cookbook.

## 7.4.20 - *2024-12-07*

## 7.4.19 - *2024-11-18*

Standardise files with files in sous-chefs/repo-management

Standardise files with files in sous-chefs/repo-management

## 7.4.18 - *2024-07-15*

Standardise files with files in sous-chefs/repo-management

Standardise files with files in sous-chefs/repo-management

Standardise files with files in sous-chefs/repo-management

## 7.4.17 - *2024-05-02*

## 7.4.16 - *2024-05-02*

## 7.4.15 - *2023-09-28*

## 7.4.14 - *2023-09-28*

## 7.4.13 - *2023-04-17*

## 7.4.12 - *2023-04-07*

Standardise files with files in sous-chefs/repo-management

## 7.4.11 - *2023-04-01*

## 7.4.10 - *2023-04-01*

Standardise files with files in sous-chefs/repo-management

## 7.4.9 - *2023-03-20*

Standardise files with files in sous-chefs/repo-management

## 7.4.8 - *2023-03-18*

- Update gaurav-nelson/github-action-markdown-link-check action to v1.0.15
- Fix yaml

## 7.4.7 - *2023-03-15*

- Standardise files with files in sous-chefs/repo-management

## 7.4.6 - *2023-02-27*

- remove circleci

## 7.4.5 - *2023-02-23*

- Standardise files with files in sous-chefs/repo-management

## 7.4.4 - *2023-02-16*

- Standardise files with files in sous-chefs/repo-management

## 7.4.3 - *2023-02-15*

- Update Actions

## 7.4.2 - *2023-02-15*

- Standardise files with files in sous-chefs/repo-management

## 7.4.1 - *2022-12-08*

- Standardise files with files in sous-chefs/repo-management

## 7.4.0 - *2022-05-09*

- Add support for DNF property `best`
- Add support for DNF property `skip_if_unavailable`
- Add support for DNF property `excludepkgs`

## 7.3.2 - *2022-02-02*

## 7.3.1 - *2022-01-27*

- Add testing for Alma Linux and Rocky Linux
- Remove testing for CentOS 8 (prefer Stream instead)

## 7.3.0 - *2022-01-07*

- Add `flush_cache` option to `dnf_module`

## 7.2.1 - *2021-12-21*

- Fix version comparison in `dnf_module` supported check

## 7.2.0 - *2021-09-29*

- Add `dnf_module` resource for managing DNF modules on RHEL 8+ / Fedora

## 7.1.0 - *2021-08-29*

- Add support for DNF (Yum v4) property `install_weak_deps` (#193)

## 7.0.1 - *2021-08-26*

- Standardise files with files in sous-chefs/repo-management (#191)

## 7.0.0 - *2021-08-13*

- Enable `unified_mode` for Chef 17 compatibility
- Remove deprecated `dnf_yum_compat` recipe

## 6.1.1 - *2021-06-01*

## 6.1.0 - *2021-03-24*

- complete ip_resolve additions started in 6.0.0

## 6.0.0 - *2021-01-20*

- Sous Chefs Adoption
- Cookstyle fixes
- Various testing fixes
- Standardise files with files in sous-chefs/repo-management
- Adding proper distroverpkg assignment for Oracle Linux
- Require 13+
- Remove RHEL5 references
- Mark `dnf_yum_compat` recipe deprecated
- Add EL8 support

## 5.1.0 (2017-08-04)

- Avoid spec deprecation warnings
- Use an empty string `releasever` to lock an Amazon Linux AMI to its current verison

## 5.0.1 (2017-04-06)

- Switch from Rake testing to Local Delivery
- Rename kitchen-docker to kitchen-dokken
- Update apache2 license string
- use true/false vs. TrueClass and FalseClass in the resource

## 5.0.0 (2017-02-12)

### Breaking changes

- Removed the yum_repository resource and instead require chef-client 12.14 or later, which has the yum repository functionality built in. This resolves Chef 13 compatibility warnings for any cookbook with the yum cookbook.

### Other changes

- Convert yum_globalconfig from an LWRP to a custom resource

## 4.2.0 (2017-02-12)

- Make cache in the DNF compat recipe
- Fix `fastestmirror_enabled`.
- Require Chef 12.1 not 12.0
- Convert to Inspec

## 4.1.0 (2016-10-21)

- Purge yum cache before removing a repo not after

## 4.0.0 (2016-09-06)

- Remove support for Chef 11

## 3.13.0 (2016-09-06)

- Add deprecation warning for add/remove actions, which were replaced with create/delete in Yum 3.0
- Remove support for Chef 10

## v3.12.0 (2016-08-25)

- Fixing baseurl to support multiple urls
- Modify releasever attribute for Amazon to match Amazon's default policy for releasever

## v3.11.0 (2016-06-01)

- Install yum at compile time in the dnf compatibility recipe
- Add IBM zlinux as a supported platform in the metadata
- Use cookstyle instead of rubocop to provide a consistent linting experience

## v3.10.0 (2016-02-04)

- Add a new sensitive attribute to the repository resource so prevent writing the diff of the config to Chef output / logs
- Update testing dependencies and remove the Guardfile / Guard dependencies

## v3.9.0 (2016-01-14)

- Added dnf_yum_compat recipe to ensure yum is installed on Fedora systems for Chef package resource compatibility. This will no longer be necessary when native dnf package support ships in chef-client.

## v3.8.2 (2015-10-28)

- #141 - Replace clean_headers with clean_metadata

## v3.8.1 (2015-10-28)

- Fixing up Chef13 deprecation warnings

## v3.8.0 (2015-10-13)

- adding clean_headers boolean property to yum_resource
- restoring Chef 10 backwards compat for the sake of ChefSpec
- (unique resource names needed to avoid cloning)
- Fixing localpkg_gpgcheck values

## v3.7.1 (2015-09-08)

- #135 - reverting "yum clean headers" as it breaks dnf compat

## v3.7.0 (2015-09-05)

- Adding deltarpm toggle
- Cleaning 'headers' rather than 'all'

## v3.6.3 (2015-07-13)

- Normalizing sslverify option rendering behavior
- Setting default value on the resource to nil
- Explictly setting string to render in template if value is supplied
- Behavior should default to "True", per man page

## v3.6.2 (2015-07-13)

- Adding -y to makecache, to import key when repo_gpgcheck = true.
- Accepting Integer value for max_retries

## v3.6.1 (2015-06-04)

- Executing yum clean before makecache
- Adding repo_gpgcheck

## v3.6.0 (2015-04-23)

- Adding "yum clean" before "yum makecache" in yum_repository :create
- Adding why_run support to yum_globalconfig

## v3.5.4 (2015-04-07)

- Changing tolerant config line to stringified integer

## v3.5.3 (2015-01-16)

- Adding reposdir to globalconfig template

## v3.5.2 (2014-12-24)

- Fixing redhat-release detection for Redhat 7

## v3.5.1 (2014-11-24)

- Reverting management of ca-certificates because EL5 was broken

## v3.5.0 (2014-11-24)

- Adding management of ca-certificates package to yum_repository provider

## v3.4.1 (2014-10-29)

- Run yum-makecache only_if new_resource.enabled
- Allow setting of reposdir in global yum config and man page
- Change default 'obsoletes' behavior to match yum defaults

## v3.4.0 (2014-10-15)

- Dynamically generate the new_resource attributes

## v3.3.2 (2014-09-11)

- Fix globalconfig resource param for http_caching

## v3.3.1 (2014-09-04)

- Fix issue with sslverify if set to false
- Add fancy badges

## v3.3.0 (2014-09-03)

- Adding tuning attributes for all supported resource parameters
- Adding options hash parameter
- Adding (real) rhel-6.5 and centos-7.0 to test-kitchen coverage
- Updating regex for mirror_expire and mirrorlist_expire to include /^\d+[mhd]$/
- Updating README so keepcache reflects reality (defaults to false)
- Changing 'obsoletes' behavior in globalconfig resource to match
- default behavior. (now defaults to nil, yum defaults to false)
- Adding makecache action to repository resource
- Adding mode parameter to repository resource. Defaults to '0644'.

## v3.2.4 (2014-08-20)

- #82 - Adding a makecache parameter

## v3.2.2 (2014-06-11)

- #77 - Parameter default to be Trueclass instead of "1"

- #78 - add releasever parameter

## v3.2.0 (2014-04-09)

- [COOK-4510] - Adding username and password parameters to node attributes
- [COOK-4518] - Fix Scientific Linux distroverpkg

## v3.1.6 (2014-03-27)

- [COOK-4463] - support multiple GPG keys
- [COOK-4364] - yum_repository delete action fails

## v3.1.4 (2014-03-12)

- [COOK-4417] Expand test harness to encompass 32-bit boxes

## v3.1.2 (2014-02-23)

Fixing bugs around :delete action and cache clean Fixing specs to cover :remove and :delete aliasing properly Adding Travis-ci build matrix bits

## v3.1.0 (2014-02-13)

- Updating testing harness for integration testing on Travis-ci
- Adding TESTING.md and Guardfile
- PR #67 - Add skip_if_unvailable repository option
- PR #64 - Fix validation of 'metadata_expire' option to match documentation
- [COOK-3591] - removing node.name from repo template rendering
- [COOK-4275] - Enhancements to yum cookbook
- Adding full spec coverage
- Adding support for custom source template to yum_repository

## v3.0.8 (2014-01-27)

Fixing typo in default.rb. yum_globalconfig now passes proxy attribute correctly.

## v3.0.6 (2014-01-27)

Updating default.rb to consume node['yum']['main']['proxy']

## v3.0.4 (2013-12-29)

### Bug

- **[COOK-4156](https://tickets.chef.io/browse/COOK-4156)** - yum cookbook creates a yum.conf with "cachefir" directive

## v3.0.2

Updating globalconfig provider for Chef 10 compatability

## v3.0.0

3.0.0 Major rewrite with breaking changes. Recipes broken out into individual cookbooks yum_key resource has been removed yum_repository resource now takes gpgkey as a URL directly yum_repository actions have been reduced to :create and :delete 'name' has been changed to repositoryid to avoid ambiguity chefspec test coverage gpgcheck is set to 'true' by default and must be explicitly disabled

## v2.4.4

Reverting to Ruby 1.8 hash syntax.

## v2.4.2

[COOK-3275] LWRP repository.rb :add method fails to create yum repo in some cases which causes :update to fail Amazon rhel

## v2.4.0

### Improvement

- [COOK-3025] - Allow per-repo proxy definitions

## v2.3.4

### Improvement

- **[COOK-3689](https://tickets.chef.io/browse/COOK-3689)** - Fix warnings about resource cloning
- **[COOK-3574](https://tickets.chef.io/browse/COOK-3574)** - Add missing "description" field in metadata

## v2.3.2

### Bug

- **[COOK-3145](https://tickets.chef.io/browse/COOK-3145)** - Use correct download URL for epel `key_url`

## v2.3.0

### New Feature

- [COOK-2924]: Yum should allow type setting in repo file

## v2.2.4

### Bug

- [COOK-2360]: last commit to `yum_repository` changes previous behaviour
- [COOK-3015]: Yum cookbook test minitest to fail

## v2.2.2

### Improvement

- [COOK-2946]: update tests, test kitchen support in yum cookbook

### Bug

- [COOK-2639]: Yum cookbook - epel - always assumes url is a mirror list
- [COOK-2663]: Yum should allow metadata_expire setting in repo file
- [COOK-2751]: Update yum.ius_release version to 1.0-11

## v2.2.0

- [COOK-2189] - yum::ius failed on install (caused from rpm dependency)
- [COOK-2196] - Make includepkgs and exclude configurable for each repos
- [COOK-2244] - Allow configuring caching using attributes
- [COOK-2399] - yum cookbook LWRPs fail FoodCritic
- [COOK-2519] - Add priority option to Yum repo files
- [COOK-2593] - allow integer or string for yum priority
- [COOK-2643] - don't use conditional attribute for `yum_key` `remote_file`

## v2.1.0

- [COOK-2045] - add remi repository recipe
- [COOK-2121] - add `:create` action to `yum_repository`

## v2.0.6

- [COOK-2037] - minor style fixes
- [COOK-2038] - updated README

## v2.0.4

- [COOK-1908] - unable to install repoforge on CentOS 6 32 bit

## v2.0.2

- [COOK-1758] - Add default action for repository resource

## v2.0.0

This version changes the behavior of the EPEL recipe (most commonly used in other Chef cookbooks) on Amazon, and removes an attribute, `node['yum']['epel_release']`. See the README for details.

- [COOK-1772] - Simplify management of EPEL with LWRP

## v1.0.0

`mirrorlist` in the `yum_repository` LWRP must be set to the mirror list URI to use rather than setting it to true. See README.md.

- [COOK-1088] - use dl.fedoraproject.org for EPEL to prevent redirects
- [COOK-1653] - fix mirrorlist
- [COOK-1710] - support http proxy
- [COOK-1722] - update IUS version

## v0.8.2

- [COOK-1521] - add :update action to `yum_repository`

## v0.8.0

- [COOK-1204] - Make 'add' default action for yum_repository
- [COOK-1351] - option to not make the yum cache (via attribute)
- [COOK-1353] - x86_64 centos path fixes
- [COOK-1414] - recipe for repoforge

## v0.6.2

- Updated README to remove git diff artifacts.

## v0.6.0

- Default action for the yum_repository LWRP is now add.
- [COOK-1227] - clear Chefs internal cache after adding new yum repo
- [COOK-1262] - yum::epel should enable existing repo on Amazon Linux
- [COOK-1272], [COOK-1302] - update RPM file for CentOS / RHEL 6
- [COOK-1330] - update cookbook documentation on excludes for yum
- [COOK-1346] - retry remote_file for EPEL in case we get an FTP mirror

## v0.5.2

- [COOK-825] - epel and ius `remote_file` should notify the `rpm_package` to install

## v0.5.0

- [COOK-675] - add recipe for handling EPEL repository
- [COOK-722] - add recipe for handling IUS repository

## v.0.1.2

- Remove yum update in default recipe, that doesn't update caches, it updates packages installed.
