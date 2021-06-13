# PlayIO SELinux

This page describes briefly about the policy module we created for working on system with SELinux enabled.

## Overview

Custom SELinux policy module should be installed prior to VPN client installation.

We tend to create a custom SELinux type enforcement policy module, all the resources to build it contains:
- The file contexts expressions `playio_vpnc.fc` file, data in this file is the reference in labelling step (the `restorecon` command, for example)
- The module interface definition `playio_vpnc.if` file, it defines set of *public functions* that other modules can use to properly interact with the `vpnc_playio` module we're about to create
- The rules definition `playio_vpnc.te` file, this file is considered the most important in the module: it defines type enforcement rules.
- The policy binary file `playio_vpnc.pp` which is compiled from 3 above source files. This file is installed into system's SELinux policy

### File contexts expressions

This file is identified by its extension `.fc`

We define label for files are belong to `playio_vpnc`: label for executable and label for the whole resources

### Module interface definition

Basically, we define `playio_vpnc_domtrans` interface allows other processes (called domain in context of SELinux) to do a domain transition to `playio_vpnc_t` by executing our program which is labeled `playio_vpnc_exec_t`

The other interface `playio_vpnc_exec` we defined allows other domains to execute our program labeled `playio_vpnc_exec_t`

### Rules definition

Set of rules to allow VPNC client to be run and interacted with multiple elements of the system: file system, network socket, unix socket, other processes/applications...

For example, this rule:
```
allow playio_vpnc_t dhcp_etc_t:dir { getattr search };
```
Can be described as: allow domain labeled `playio_vpnc_t` to search and get attributes on directories of the directory type labeled `dhcp_etc_t`. In this case, our VPN client generates a hook script and put into `/etc/dhcp/dhclient-exit-hooks.d` directory. The SElinux context of this directory is `unconfined_u:object_r:dhcp_etc_t:s0` as below:
```
$ sudo ls -lZ /etc/dhcp/
total 0
drwxr-xr-x. 2 root root system_u:object_r:bin_t:s0          23 May 12 05:59 dhclient.d
drwxr-xr-x. 2 root root unconfined_u:object_r:dhcp_etc_t:s0 24 Jun  5 17:31 dhclient-exit-hooks.d
```
Where the 3rd field (":" separated) is the domain type: `dhcp_etc_t`

Some references:
- https://wiki.gentoo.org/wiki/SELinux
- https://debian-handbook.info/browse/stable/sect.selinux.html

## How this policy got composed

- Set system's SELinux operation to `permissive` mode, in this mode nothing's got prohibitted by SELinux but all policy violations are logged to system log or audit log.
- Install and configure VPN client as usual.
- Analyze the log and generate rules, some useful tools to help achieve this task: `ausearch`, `journalctl`, `sealert`

**Contribution:** There're always room for improvemnt, we're really appreciate your contribution and suggestion in documenting and improving this custom policy module.