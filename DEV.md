# Development

- [scripts](./scripts) folder contains some linux script to build/run `vpnserver`/`vpnc`/`vpnddns` and shared artifact to `vagrant`
- [docker](./docker) folder contains a list of `vpnserver`/`vpnc`/`vpnddns` `dockerfile` and `docker-compose`

## SoftEther VPN server

### Docker

#### Build

2 edition repositories:

- `RTM` repository(`rtm`): https://github.com/SoftEtherVPN/SoftEtherVPN_Stable
- `Developer` repository(`src`): https://github.com/SoftEtherVPN/SoftEtherVPN

2 based Docker images: `debian-slim`, `alpine`

```bash
# Build on slim and latest RTM version 
./scripts/docker.vpnserver.sh build

# Build on slim and specific RTM version
./scripts/docker.vpnserver.sh build slim rtm v4.34-9745-beta

# Build on slim and src latest version
./scripts/docker.vpnserver.sh build slim src 

# Build on slim and specific src version
./scripts/docker.vpnserver.sh build slim src 5.01.9674
```

#### Run

```bash
# Up on slim and latest RTM version
./scripts/docker.vpnserver.sh up

# Up on slim and specific RTM version
./scripts/docker.vpnserver.sh up slim rtm v4.34-9745-beta

# Up on slim and src latest version
./scripts/docker.vpnserver.sh up slim src 

# Up on slim and specific src version
./scripts/docker.vpnserver.sh up slim src 5.01.9674
```

### Use JSON-RPC

```bash
curl -k -X POST -H 'Content-Type: application/json' \
        -H 'X-VPNADMIN-PASSWORD: 123' \
        -d '{"jsonrpc":"2.0","id":"rpc_call_id","method":"Test","params":{"IntValue_u32":0}}' \
        https://localhost:8443/api/
```

## VPN client CLI

### Vagrant

```bash
# Build VPN Client CLI then copy to vagrant/shared
./scripts/build.vpnc_2_vagrant.sh
# go to any box in vagrant folder then up. Binary file will be synced to /vagrant/qweio-vpnc
# with ubuntu20
cd vagrant/ubuntu20 && vagrant up && vagrant ssh
# now, it is inside vagrant guest machine, and binary already symlink to /usr/local/bin/qweio-vpnc  
qweio-vpnc version
```

### Docker

#### Setup multiple arch

- Use `docker` [buildx](https://github.com/docker/buildx/#installing)
- Use `docker` [registry](https://github.com/zero88/gh-registry) to distribute image in local registry

```bash
# Create buildx instance
docker buildx create --append --name multiarch --buildkitd-flags --use '--allow-insecure-entitlement security.insecure --allow-insecure-entitlement network.host'
docker buildx ls

# Create docker registry as service
docker run -v docker-registry-data:/var/lib/registry -p 5000:5000 --privileged --network host -d --restart always
```

#### Build

[vpnclient.Dockerfile](cli/python/docker/vpnc.Dockerfile)

```bash
# build amd64 arch
./scripts/docker.vpntool.sh client

# build multiple arch (amd64/armv7)
./scripts/docker.vpntool.sh client true
```

## VPN DDNS

[vpnddns.Dockerfile](cli/python/docker/vpnddns.Dockerfile)

```bash
./scripts/docker.vpntool.sh ddns
```
