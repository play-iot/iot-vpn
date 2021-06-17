# SELinux policy

*Tested on Fedora*

1. Prerequisites packages:
    - setroubleshoot 
    - policycoreutils 
    - policycoreutils-devel

2. Other prerequisites:
    - The `playio-vpnc` executatble folder path is existed, it's defaulted to `/app`
    - Enable SELinux [boolean](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans):
    ```bash
    setsebool -P domain_can_mmap_files 1
    setsebool -P domain_kernel_load_modules 1
    setsebool -P daemons_enable_cluster_mode 1
    ```

3. Build and install the policy module:

    Change to this folder `selinux` and run below command:

    ```bash
    make -f /usr/share/selinux/devel/Makefile playio_vpnc.pp
    semodule -i playio_vpnc.pp
    restorecon -FRv /app
    ```

[**More information**](./playio_selinux.md)