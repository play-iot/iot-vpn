# Containerize SoftEther VPN

# VPN Server

Build container image using `sevpn` file.

# VPN Client

Build container image using `clvpn` file, optional build `net-tools` image using `net_tools.Dockerfile` for network troubleshooting.

## Running VPN client container

Run SoftEther VPN client container

* Password authentication:

```bash
podman run -d --name vpnclient \
--hostname $(hostname) \
-e SE_SERVER=$SE_SERVER:$SE_PORT \
-e SE_HUB=$SE_HUB \
-e SE_USERNAME=$SE_USERNAME \
-e SE_PASSWORD=$SE_PASSWORD \
-e SE_TYPE=standard \
--dns=$SE_VNAT_GATEWAY \
--dns=8.8.8.8 \
--privileged \
--cap-add NET_ADMIN $CONTAINER_IMAGE 
```

* Client certificate authentication:

***Assuming cert file and private key file are put in `cacerts` folder and file name are vpn username***

```bash
podman run -d --name vpnclient \
--hostname $(hostname) \
-v $(pwd)/cacerts:/app/cacerts
-e SE_SERVER=$SE_SERVER:$SE_PORT \
-e SE_HUB=$SE_HUB \
-e SE_USERNAME=$SE_USERNAME \
--dns=$SE_VNAT_GATEWAY \
--dns=8.8.8.8 \
--privileged \
--cap-add NET_ADMIN $CONTAINER_IMAGE 
```

Run another container using `net-tools` image to check for network (ping, nslookup...)

```bash
podman run --rm -it --network=container:vpnclient --privileged net-tools 
```
