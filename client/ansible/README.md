# DRAFT Deploy VPN client

The inventory and variables for every hosts follows standard as sample file in this repository.

## Usage

This playbook uses enclosed `vpnc-install` role which has `clean_up` variable. This variable is used in case there's existing messy installation of VPN client on target host. Set it to `true` to perform the cleanup before installing.

*default value is false*

```
ansible-playbook main.yml
```