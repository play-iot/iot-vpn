# Deploy VPN client

## Usage

```bash
ansible-inventory --graph
```

```bash
ansible-playbook wf-vpnc-rollout.yml -e 'debug=1' -e '{"args_vpn_state_test_domains": ["google.com"]}'
```
