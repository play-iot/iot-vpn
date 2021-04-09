# QWE VPN

QWE VPN solution for IoT

## SoftEther VPN server in Docker

### Build

2 edition repositories:
- `RTM` repository(`rtm`): https://github.com/SoftEtherVPN/SoftEtherVPN_Stable
- `Developer` repository(`src`): https://github.com/SoftEtherVPN/SoftEtherVPN

2 based Docker images: `debian-slim`, `alpine`

```bash
# Build on slim and latest RTM version 
./ss.d.vpnserver.sh build

# Build on slim and specific RTM version
./ss.d.vpnserver.sh build slim rtm v4.34-9745-beta

# Build on slim and src latest version
./ss.d.vpnserver.sh build slim src 

# Build on slim and specific src version
./ss.d.vpnserver.sh build slim src 5.01.9674
```

### Run

```bash
# Up on slim and latest RTM version
./ss.d.vpnserver.sh up

# Up on slim and specific RTM version
./ss.d.vpnserver.sh up slim rtm v4.34-9745-beta

# Up on slim and src latest version
./ss.d.vpnserver.sh up slim src 

# Up on slim and specific src version
./ss.d.vpnserver.sh up slim src 5.01.9674
```

### Use JSON-RPC

```bash
curl -k -X POST -H 'Content-Type: application/json' \
        -H 'X-VPNADMIN-PASSWORD: 123' \
        -d '{"jsonrpc":"2.0","id":"rpc_call_id","method":"Test","params":{"IntValue_u32":0}}' \
        https://localhost:8443/api/
```

## SoftEther VPN client to Vagrant

```bash
# Build VPN Client CLI then copy to vagrant/shared
./ss.b.vpnc_2_vagrant.sh
# go to any box in vagrant folder then up. Binary file will be synced to /vagrant/qweio-vpnc
# with ubuntu20
cd vagrant/ubuntu20 && vagrant up && vagrant ssh
# now, it is inside vagrant guest machine, and binary already symlink to /usr/local/bin/qweio-vpnc  
qweio-vpnc version
```
