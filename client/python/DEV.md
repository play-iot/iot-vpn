# Development

## Install pipenv

```bash
# By pip/or pip3
pip3 install pipenv

# Debian Buster+:
sudo apt install pipenv

# Fedora/Redhat/centos
sudo dnf install pipenv
```

## Install dependencies

```bash
pipenv install
# Join pipenv in virtualenv
pipenv shell
```

## Develop VPN client tool

### Run in dev

```bash
# After pipenv shell
python -m src.client.cmd_client -h
# OR
python index.py client -h
Usage: cmd_client.py [OPTIONS] COMMAND [ARGS]...

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

- Using `download -h` (it is invisible for end-user) to download binary in `src/client/resources/debug` folder, then every `command`, it is mandatory to add `--dev` for using VPN binary in `src/client/resources/debug` folder.
- `start`/`stop` command also invisible because it is system command, that avoids confusing to end-user 

### Build client tool to binary

```bash
# After pipenv shell
# Download and compile VPN client binary. Default is `linux-x64`
python -m src.client.cmd_client download
# Build to CLI binary
pyinstaller src/client/cmd_client.py -n qweio-vpnc --clean --onefile --add-data src/client/resources/*:resources/
```

## Develop VPN tool

VPN Tool covers all aspect of VPN from `server`/`hub`/`client`/`secret`

### Run in dev

```bash
# After pipenv shell
python index.py -h
Usage: index.py [OPTIONS] COMMAND [ARGS]...

  VPN Helper

Options:
  -h, --help  Show this message and exit.

Commands:
  client  VPN Client tool to install Softether VPN Client and setup VPN connection
  hub     VPN Hub Tool to add/modify SoftEther VPN users and groups.
  secret  Secret utils
  server  VPN Server tool
  vpn     Tool to add/modify SoftEther VPN users and groups.
```

### Build VPN client tool to binary

```bash
# After pipenv shell
pyinstaller src/client/cmd_client.py -n qweio-vpnc --clean --onefile \
    --add-data src/client/resources/*:resources/
```

## Develop MAC tool

```bash
python -m src.command.cmd_mac -h

Usage: cmd_mac.py [OPTIONS] COMMAND [ARGS]...

  MAC generator

Options:
  -h, --help  Show this message and exit.

Commands:
  generate  Generate MAC
  last      Get last MAC sequence in given file
  validate  Validate MAC duplication in given file
```

### Build client tool to binary

```bash
# After pipenv shell
pyinstaller src/command/cmd_mac.py -n qweio-mac --clean --onefile
```

### MAC Usage

```bash
qweio-mac generate -h
Usage: qweio-mac generate [OPTIONS] [OUTPUT]

  Generate MAC

Options:
  -n, --quantity INTEGER  The quantity that you need  [default: 1]
  -o, --overwrite         Append to file  [default: False]
  --asix1                 First ASIX: "F8:E4:3B"
  --asix2                 Second ASIX: "00:0E:C6"
  --oui TEXT              Enforces a specific an organization unique identifier (like F8:E4:3B for ASIX)
  --seq TEXT              From last sequence. Use with --asix1/--asix2/--oui
  --rand                  Random MAC instead of sequence  [default: False]
  --uaa                   Generates a universally administered address (instead of LAA otherwise)  [default: False]
  --multicast             Generates a multicast MAC (instead of unicast otherwise)  [default: False]
  --byte-fmt TEXT         The byte format. Set to %02X for uppercase hex formatting.  [default: %02x]
  --sep TEXT              The byte separator character  [default: :]
  -h, --help              Show this message and exit.
```

### MAC Usage

- Generate in random mode

```bash
# Print to console
> qweio-mac generate --rand -n 10

# Write to file
> qweio-mac generate --rand -n 10 qweio.mac

# Overwrite file
> qweio-mac generate --rand -n 5 -o qweio.mac

# Generate random MAC with organization unique identifier
> qweio-mac generate --rand -n 10000 --oui 00:0E:C6 qweio.mac

# Validate MAC collision
> qweio-mac validate qweio.mac 
Duplicated key: 02:0e:c6:91:14:42 in lines [1229, 2793]
Duplicated key: 02:0e:c6:82:19:5c in lines [2073, 5991]
Duplicated key: 02:0e:c6:d2:fa:20 in lines [3285, 4060]
Duplicated key: 02:0e:c6:ec:8f:49 in lines [4162, 5469]
Duplicated 4 keys
```

- Generate in with `organization unique identifier` and `sequence`

```bash
# Write based on ASIX
> qweio-mac generate --asix1 -n 5
f8:e4:3b:00:00:00
f8:e4:3b:00:00:01
f8:e4:3b:00:00:02
f8:e4:3b:00:00:03
f8:e4:3b:00:00:04

# Write to file then keep it for generate MAC sequently
> qweio-mac generate --asix1 -n 5 qweio.mac
## Check last MAC
> qweio-mac last qweio.mac
f8:e4:3b:00:00:04
## Generate next 5 from last sequence
> qweio-mac generate --asix1 -n 5 --seq $(qweio-mac last qweio.mac) qweio.mac
> cat qweio.mac
f8:e4:3b:00:00:00
f8:e4:3b:00:00:01
f8:e4:3b:00:00:02
f8:e4:3b:00:00:03
f8:e4:3b:00:00:04
f8:e4:3b:00:00:05
f8:e4:3b:00:00:06
f8:e4:3b:00:00:07
f8:e4:3b:00:00:08
f8:e4:3b:00:00:09
```

- Copy `MAC` from current NIC with override option from `OUI` 

```bash
> qweio-mac copy -h
Usage: qweio-mac mac copy [OPTIONS] [NIC]
  Copy MAC with override OUI

Options:
  --asix1          First ASIX: "F8:E4:3B"
  --asix2          Second ASIX: "00:0E:C6"
  --oui TEXT       Enforces a specific an organization unique identifier (like F8:E4:3B for ASIX)
  --byte-fmt TEXT  The byte format. Set to %02X for uppercase hex formatting.  [default: %02x]
  --sep TEXT       The byte separator character  [default: :]
  -h, --help       Show this message and exit.

## Default NIC is `eth0`
> qweio-mac copy --asix1
f8:e4:3b:86:71:1c

> qweio-mac copy --asix2 wlp4s0
00:0e:c6:86:71:1c
```

**Reference**: http://standards-oui.ieee.org/oui/oui.txt

**Note**:

- Have 2 `asix` so we have 2 options `--asix1` and `--asix2`
- Because generate with `organization unique identifier` and `random` mode still having collision so should
  use `MAC sequence` and keep `qweio.mac` in repository to reference later