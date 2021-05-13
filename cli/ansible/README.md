# Deploy VPN client

## Usage

```bash
ansible-inventory --graph
```

```bash
ansible-playbook wf-vpnc-rollout.yml -e 'debug=1' -e '{"args_vpn_state_test_domains": ["google.com"]}'
```

### Docker

- See `docker-compose` dev version [here](../../docker/vpnc-deployer-dkc.yml)

### Script

#### Precondition

- Copy `vpnc-deployer.sh` to anywhere in **YOUR LINUX COMPUTER**
- Install [`docker`](https://docs.docker.com/engine/install) and [`docker-compose`](https://docs.docker.com/compose/install/)

## Init step

```bash
$ ./vpnc-deployer.sh init

## Script will show information like this. Don't ask, just do it
Please copy 'credentials.json' into '<your_data_dir>/files'
Please create new 'hosts.yml' into '<your_data_dir>/inventory'
Then invoke './vpnc-deployer.sh setup'
```

## Prepare hosts

- Create `hosts.yml` as format below
  ```bash
  all:
    children:
      cba:
        hosts:
          <vpn_user_1>:
            ansible_host: <ip_1>
          <vpn_user_2>:
            ansible_host: <ip_2>
        vars:
          ansible_port: 2022
          ansible_user: pi
          ansible_password: N00BRCRC
  ```

  **Importance**
  - Replace `vpn_user_*` to vpn user format. For example: `n000001`, `n000002`
  - Replace `ip_1` to host ip that corresponding to `vpn_user`. For example: `192.168.10.15` for `n000001` in your office.

- `credentials.json` is file contains VPN user per customer and is provided by VPN administrators

## Setup VPN for bulk deploy to remote devices

After do `init step` and `Prepare hosts`, run:

```bash
./vpnc-deployer.sh setup
```

It will show output to console, then don't close it by `Ctrl+C`
After the progress is finished, it will show something like that

```bash
vpnc-deployer_1  | PLAY RECAP *********************************************************************
vpnc-deployer_1  | n000002                    : ok=14   changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0   
vpnc-deployer_1  | n000003                    : ok=14   changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

- If output show `unreachable=1`, please check your connection to target device (ip/port/username/password)
- If output show `failed=1`, please copy a log file in `/tmp/out/ansible.log` then send to `@zero88`
