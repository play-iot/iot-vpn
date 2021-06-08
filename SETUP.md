# Setup Development Environment

- [scripts](./scripts) folder contains some linux script to build/run `vpnserver`/`vpnc`/`vpnddns` and shared artifact
  to `vagrant`
- [docker](./docker) folder contains a list of `vpnserver`/`vpnc`/`vpnddns` `dockerfile` and `docker-compose`

## Vagrant

It is used for test VPN client CLI in the specific environment/`OS`.

Use [./scripts/vagrant.sh](./scripts/vagrant.sh) to `up`/`halt`/`destroy`/`status`/`port`/`ssh` one or
multiple `vagrant` boxes. The `vagrant` box parameter is one of folder name in [./vagrant](vagrant)

For example:

```bash
# Up multiple boxes
./scripts/vagrant.sh up ubuntu20 fedora32 debian10
# ssh to one box
./scripts/vagrant.sh ssh ubuntu20
```

## Docker multi arches

- Use `docker` [buildx](https://github.com/docker/buildx/#installing)
- Use `docker` [registry](https://github.com/zero88/gh-registry) to distribute image in local registry

```bash
# Create buildx instance
docker buildx create --append --name multiarch --buildkitd-flags --use '--allow-insecure-entitlement security.insecure --allow-insecure-entitlement network.host'
docker buildx ls

# Create docker registry as service
docker run -v docker-registry-data:/var/lib/registry -p 5000:5000 --privileged --network host -d --restart always
```

## VPN server

### Docker

[Dockerfile](./docker/dockerfile)

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

## VPN CLI

### Setup python environment

```bash
## Install pipenv
# By pip/or pip3
pip3 install pipenv
# Debian Buster+:
sudo apt install pipenv
# Fedora/Redhat/centos
sudo dnf install pipenv

# In root project dir
pipenv install
# Join pipenv in virtualenv
pipenv shell
```

### VPN client

#### Build and test

[vpnclient.Dockerfile](cli/python/docker/vpnc.Dockerfile)

```bash
#==========================================================
#### USE VAGRANT ------------------------------------------
# Build VPN Client CLI then copy to vagrant/shared
./scripts/build.vpnc_2_vagrant.sh
# go to any box in vagrant folder then up. Binary file will be synced to /vagrant/playio-vpnc
# with ubuntu20
./scripts/vagrant.sh up ubuntu20 && ./scripts/vagrant.sh ssh ubuntu20
# now, it is inside vagrant guest machine, and binary already symlink to /usr/local/bin/playio-vpnc  
playio-vpnc version

#==========================================================
#### USE DOCKER -------------------------------------------
# build amd64 arch
./scripts/docker.vpntool.sh c

# build multiple arch (amd64/armv7)
./scripts/docker.vpntool.sh c true
```


### VPNC Deployer

[vpnc-deployer.Dockerfile](cli/ansible/docker/vpnc-deployer.Dockerfile)

```bash
./scripts/docker.vpntool.sh ddns
```

Please read [VPNC Deployer](./cli/ansible/README.md) to see how it works based on `ansible` and `docker`

### VPN DDNS

[vpnddns.Dockerfile](cli/python/docker/vpnddns.Dockerfile)

```bash
./scripts/docker.vpntool.sh ddns
```

Please read [VPN DDNS k8s](./cli/k8s/ddns/README.md) to see sample `k8s` deployment

### Implementation

Please consume [vpnc-dev](./cli/python/DEV.md)

## VPN manager

TBD
