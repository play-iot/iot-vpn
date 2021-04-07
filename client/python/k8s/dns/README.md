# VPN DNS sync job

Query VPN client session based on `hostname`, `vpn ip address` then creating DNS record in [Cloud DNS](https://console.cloud.google.com/net-services/dns/zones). The job is run on K8S cronjob

- Use this [utility](https://github.com/zero-88/devops-utils/tree/master/k8s)
- Cronjob manifest:
  - [10_create-config-secret.sh](./10_create-config-secret.sh) Create config/secret
  - [11_vpn-dns-sync-cronjob.yaml](./11_vpn-dns-sync-cronjob.yaml)


## Deployment steps

- Prepare `google-service-account.json` with right permission to update Cloud DNS records.
- Copy and fill information based on a customer code. For example: `qweio` is customer code
  - [customer.env.tmpl](customer.env.tmpl) = qweio.env
  - [customer.secret.env.tml](customer.secret.env.tmpl) = qweio.secret.env
  - [.runner.env.tmpl](.runner.env.tmpl) = .prod.env
- Checkout [utility](https://github.com/zero-88/devops-utils/tree/master/k8s)

```bash
PROJECT_DIR=<your-path>
python deploy.py -e prod -m gcp -d $PROJECT_DIR/infrastructure/softether-vpn/k8s/dns
```
