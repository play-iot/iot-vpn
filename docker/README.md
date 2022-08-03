# Containerize SoftEther VPN

# VPN Server

Build container image using `sevpn` file.

# VPN Client

Build container image using `clvpn` file, optional build `net_tools` image for network troubleshooting.

## Running VPN client container

Run SoftEther VPN client container

```bash
podman run -d --name vpnclient \
-e SE_SERVER=$SE_SERVER:$SE_PORT \
-e SE_HUB=$SE_HUB \
-e SE_USERNAME=$SE_USERNAME \
-e SE_PASSWORD=$SE_PASSWORD \
--privileged \
--cap-add NET_ADMIN $CONTAINER_IMAGE
```

After this step, our client should be connected to VPN tunnel but no IPv4 obtained.

We need to run a separated process to get IP from VPN Server DHCP, most well known method is using `dhclient`

```bash
podman run --rm --network=container:vpnclient --privileged --cap-add NET_ADMIN net_tools dhclient -v $SE_NICNAME
```
