#!/bin/bash

# clean up cloud init artifacts https://cloudinit.readthedocs.io/en/latest/topics/cli.html#clean
cloud-init clean -s

rm -rf /var/tmp/* /tmp/* /var/cache/*
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

# Clean instance-specific data
rm -rf /var/lib/cloud/*
rm -rf /var/lib/dhcp/*
rm -rf /var/crash/*

# Clean AWS-specific files
rm -rf /var/lib/amazon/*
rm -f /etc/boto.cfg
rm -f /etc/aws/*

# Clear DNS cache
if command -v systemd-resolve >/dev/null 2>&1; then
    systemd-resolve --flush-caches
elif [ -f /etc/init.d/nscd ]; then
    service nscd restart
fi

# Clean resolv.conf if it's not managed by system
if [ ! -L "/etc/resolv.conf" ]; then
    echo -n > /etc/resolv.conf
fi

# Clean network configuration state
rm -f /etc/sysconfig/network
rm -f /etc/hostname
rm -rf /var/lib/NetworkManager/*

systemctl stop rsyslog
systemctl stop systemd-journald

# Clean journals
journalctl --rotate
journalctl --vacuum-time=1s
rm -rf /var/log/journal/*

# Clean logs
find /var/log -type f -exec /bin/rm -v {} \;
touch /var/log/lastlog

# Reset systemd
systemctl daemon-reexec

# Restart logging
systemctl start systemd-journald
systemctl start rsyslog
