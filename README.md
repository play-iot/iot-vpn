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
./docker.sh build

# Build on slim and specific RTM version
./docker.sh build slim rtm v4.34-9745-beta

# Build on slim and src latest version
./docker.sh build slim src 

# Build on slim and specific src version
./docker.sh build slim src 5.01.9674
```

### Run

```bash
# Up on slim and latest RTM version
./docker.sh up

# Up on slim and specific RTM version
./docker.sh up slim rtm v4.34-9745-beta

# Up on slim and src latest version
./docker.sh up slim src 

# Up on slim and specific src version
./docker.sh up slim src 5.01.9674
```

### Use JSON-RPC

```bash
curl -k -X POST -H 'Content-Type: application/json' \
        -H 'X-VPNADMIN-PASSWORD: 123' \
        -d '{"jsonrpc":"2.0","id":"rpc_call_id","method":"Test","params":{"IntValue_u32":0}}' \
        https://localhost:8443/api/
```
