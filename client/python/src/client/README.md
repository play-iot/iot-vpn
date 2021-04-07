# QWE VPN client CLI

This is collection of script to set up softether-vpn client.

It supports multiple VPN accounts backed by different `unix` services.

After run this script, it is able to manage by `unix` services. For example, `VPN account` is `qweiovpn`

```bash
systemctl start qweiovpn
systemctl status qweiovpn
systemctl stop qweiovpn
```

## CLI

A Linux command line interface, is run on vary linux OS and architecture, that supports:

- Installation [SoftetherVPN](https://www.softether.org/)
- Setup VPN account
- Tweak network configuration includes VPN IP resolver and VPN DNS resolver
- `qweio-vpnc.armv7.zip` for IoT device: RaspberryPi, BeagleBone, etc...
- `qweio-vpnc.amd64.zip` for user computer.

Unzip a release artifact to `/app`

```bash
$ sudo mkdir -p /app
$ sudo unzip /tmp/qweio-vpnc*.zip -d /app
$ sudo chmod +x /app/qweio-vpnc
# Make Linux symlink for invoke command directly (it is optional and can skip if done it before
$ sudo ln -s /app/qweio-vpnc /usr/local/bin/qweio-vpnc
# Verify
$ sudo qweio-vpnc version
INFO : VPN version: 4.29 Build 9680   (English)
INFO : CLI version: 1.0.2
```

### Usage

- `qweio-vpnc -h` for more information

  ```bash
  $ qweio-vpnc -h
  Usage: qweio-vpnc [OPTIONS] COMMAND [ARGS]...

  VPN Client tool to install Softether VPN Client and setup VPN connection

  Options:
    -h, --help  Show this message and exit.
  
  Commands:
    add         Add new VPN Account
    command     Execute Ad-hoc VPN command
    connect     Connect to VPN connection with VPN account
    detail      Get detail VPN Account configuration
    disconnect  Disconnect VPN connection with VPN account
    install     Install VPN client and setup *nix service
    list        Get all VPN Accounts
    log         Get VPN log
    status      Get current VPN status
    trust       Trust VPN Server cert
    uninstall   Stop and disable VPN client and *nix service
    version     VPN Version
  ```

- To connect VPN server, you must provide
  - `VPN Host` HTTPS VPN server.
  - `VPN Port` Default is `443`.
  - `VPN Hub`  It is multi-tenant option, might be `customer` code.
  - `Authentication` A login credential to appropriate VPN host and VPN Hub. One of `password` or `certification`

#### VPN on IoT device

- Must use `Client Certificate Authentication`
- Need `VPN device user`, `VPN device certificated` file, `VPN device private key` file
- 2 steps for quick install and setup:
  - Install VPN client and setup Linux service (For detail explanation, please read `qweio-vpnc install -h`)

    ```bash
    $ sudo qweio-vpnc install
    ```

  - Add new VPN account: (For detail explanation, please read `qweio-vpnc add -h`)

    ```bash
    $ sudo qweio-vpnc add -sh <vpn_server> -su <hub_name> -cd -ct cert -cu <vpn_device_user> -cck <vpn_device_certificated> -cpk <vpn_device_private_key> --hostname
    ```

- After that, please verify by commands:

```bash
$ sudo qweio-vpnc status

INFO : VPN Service        : qweiovpn.service - inactive(dead)
INFO : Current VPN IP     : [{'addr': '10.0.0.2', 'netmask': '255.0.0.0', 'broadcast': '10.255.255.255'}]
INFO : Current VPN Account: devops - Connection Completed (Session Established)
```

#### VPN on User device

- Use `Client Password Authentication`
- Need `VPN user`, `VPN password`, `VPN Customer hub` (a.k.a customer code, per hub per customer)
- If you manage cross VPN customer, then it's ideally to provide `VPN account` (VPN connection name) that equals to `VPN customer code`

```bash
$ sudo qweio-vpnc install -da linux-x64
# You can check log
$ sudo qweio-vpnc log -f
# Put your password in `single quotes` 'your-password'
$ sudo qweio-vpnc add -sh <vpn_server> -su <customer_code_1> -ca <customer_code_1> -ct password -cu <vpn_user> -cp <vpn_password>
# You can add other VPN accounts, 
# with '-cd' option is make VPN client account is default for startup system/computer
$ sudo qweio-vpnc add -sh <vpn_server> -su <customer_code_n> -ca <customer_code_n> -ct password -cu <vpn_user> -cp <vpn_password> -cd
# Then you can switch among account by: disconnect acc1 then connect acc2
$ sudo qweio-vpnc disconnect customer_code_1
$ sudo qweio-vpnc connect customer_code_n
# To uninstall vpn service
$ sudo qweio-vpnc uninstall
```

## Passwordless

It is optional but good to have if you want to connect IoT device via SSH without a password but using `SSH key`

**Prerequisite:**

1. Public and private ssh key pairs are generated and available on your deployment computer.
2. Both deployment computer and `qweio` device are joined VPN.

Use `ssh-copy-id` command to securely import ssh public key into targeted `qweio` device.

```
ssh-copy-id -i <path-to-private-ssh-key> <user>@<hostname>.<hub_name>.device
```

Afterward, the `qweio` device can be accessed via password-less ssh

```
ssh -i <path-to-private-ssh-key> <user>@<hostname>.<hub_name>.device
```

## Limitation

- Not yet test in `MacOS` with `--arch macos-x64` or `--arch macos-x86`
- Not yet supported in `Windows` but you can use [GUI](https://www.softether.org/4-docs/1-manual/4._SoftEther_VPN_Client_Manual/4.2_Using_the_VPN_Client) [here](https://www.softether-download.com/files/softether/v4.34-9745-rtm-2020.04.05-tree/Windows/SoftEther_VPN_Client/softether-vpnclient-v4.34-9745-rtm-2020.04.05-windows-x86_x64-intel.exe)
