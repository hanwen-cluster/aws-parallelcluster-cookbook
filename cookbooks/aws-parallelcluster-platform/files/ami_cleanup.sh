#!/bin/bash

# clean up cloud init artifacts https://cloudinit.readthedocs.io/en/latest/topics/cli.html#clean
cloud-init clean -s

rm -rf /var/tmp/* /tmp/*
rm -rf /etc/ssh/ssh_host_*
rm -f /etc/udev/rules.d/70-persistent-net.rules
grep -l "Created by cloud-init on instance boot automatically" /etc/sysconfig/network-scripts/ifcfg-* | xargs rm -f
rm -rf /var/crash/*

if [ -f /opt/parallelcluster/pin_releasesever ]; then
  rm -f /opt/parallelcluster/pin_releasesever
  rm -f /etc/yum/vars/releasever
fi

# https://bugs.centos.org/view.php?id=13836#c33128
source /etc/os-release

systemctl stop rsyslog
systemctl stop systemd-journald

# Clean journals
journalctl --rotate
journalctl --vacuum-time=1s
rm -rf /var/log/journal/*

# Clean logs
find /var/log -type f -exec /bin/rm -v {} \;
touch /var/log/lastlog

# Clean instance-specific data
rm -rf /var/lib/cloud/*
rm -rf /var/lib/dhcp/*

# Reset systemd
systemctl daemon-reexec

# Restart logging
systemctl start systemd-journald
systemctl start rsyslog
