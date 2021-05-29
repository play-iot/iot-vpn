# SELinux policy

*Tested on Fedora*

1. Prerequisites packages:
    - setroubleshoot 
    - policycoreutils 
    - policycoreutils-devel

2. Other prerequisites:
-   The `playio-vpnc` executatble folder path is existed, it's defaulted to `/app`

3. Build and install the policy

Change to this folder `selinux` and run below command:

```bash
make -f /usr/share/selinux/devel/Makefile playio_vpnc.pp
semodule -i playio_vpnc.pp
restorecon -FRv /app
```
