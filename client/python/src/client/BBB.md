# BeagleBone black

https://beagleboard.org/black

## Wireless version

### Connect to WiFi network

```bash
sudo connmanctl
connmanctl> enable wifi
connmanctl> scan wifi
connmanctl> services
connmanctl> agent on
connmanctl> connect wifi_506583d4fc5e_544e434150413937414239_managed_psk
Passphrase? xxxxxxxxxxx
connected wifi_506583d4fc5e_544e434150413937414239_managed_psk
connmanctl> quit
```
