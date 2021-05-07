# VPN Cloud DNS sync

## Usage

### CLI

```bash
$ python index.py dns sync -h
Usage: index.py dns sync [OPTIONS]

  Sync DNS

Options:
  -ct, --cloud-type [gcloud|amazon|azure]
                                  DNS server type  [default: gcloud]
  -cp, --cloud-project TEXT       Cloud project id  [required]
  -sa, --cloud-svc FILE           Cloud service account  [required]
  -zn, --zone-name TEXT           Zone name  [required]
  -zd, --dns-name TEXT            DNS name. Default is <VPN_HUB>.device
  -zt, --time-to-live INTEGER     Number of seconds that this DNS can be cached by resolvers  [default: 3600]
  -sh, --host TEXT                VPN server host  [required]
  -sp, --port INTEGER RANGE       VPN server port  [default: 443]
  -su, --hub TEXT                 VPN server Hub  [required]
  -pw, --hub-password TEXT        VPN Hub admin password
  -dd, --vpn-dir TEXT             VPN installation directory  [default: /app/vpnbridge]
  -v, --verbose                   Enables verbose mode
  -h, --help                      Show this message and exit.
```

### Docker

All options in CLI can be from environment variables, with a prefix: `VPN_SYNC`. E.g: `VPN_SYNC_CLOUD_PROJECT`
, `VPN_SYNC_ZONE_NAME`

Default `cloud service account` will be loaded from `/certs/svc.json`, then it is ideally to mount volume from your host
to docker volume by `--mount type=bind,source=<your_svc_file>,target=/certs/svc.json`

## Cloud provider

### Google Cloud DNS

- Google cloud service account should have right to read, write and modify `GCloud DNS`.

```bash
docker run -dit \
--mount type=bind,source=<path-to-network-bot.json>,target=/certs/svc.json \
-e VPN_SYNC_CLOUD_PROJECT=<Cloud project id> \
-e VPN_SYNC_ZONE_NAME=<zone-name> \
-e VPN_SYNC_HOST=<vpn-server-ip-or-dns> \
-e VPN_SYNC_HUB=<hub-admin-password> \
-e VPN_SYNC_HUB_PASSWORD=<hub-admin-password> \
-e CUSTOMER_ZONE=<cloud-dns-zone-name> \
--name vpn \
playio-vpndns:dev
```

### Amazon Router 53

TBD

### Azure Cloud DNS
