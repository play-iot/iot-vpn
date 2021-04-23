# Changelog

## [v0.9.0](https://github.com/qweio/iot-vpn/tree/vpnc/v0.9.0) (2021-04-24)

### Improvement

- Resolve [#46](https://github.com/qweio/iot-vpn/issues/46)

## [v0.8.1](https://github.com/qweio/iot-vpn/tree/vpnc/v0.8.1) (2021-04-20)

### Bugfix

- Regression fix [#38](https://github.com/qweio/iot-vpn/issues/38): Connman on BeagleBone

## [v0.8.0](https://github.com/qweio/iot-vpn/tree/vpnc/v0.8.0) (2021-04-20)

### Added
- Install and manage VPN client in *Unix service

  | Distro      | Release        | Architecture |
  |-------------|----------------|--------------|
  | Raspbian    | Stretch/Buster | ARM          |
  | BeagleBoard | Stretch/Buster | ARM          |
  | Ubuntu      | 16.x/18.x/20.x | ARM/x86_64   |
  | Debian      | 9/10           | ARM/x86_64   |
  
- DNS resolver by combining `dnsmasq` with default DNS local resolver.
  - [x] `NetworkManager`
  - [x] `systemd-resolver`
  - [x] `resolvconf`
  - [x] `openresolv`
  - [x] `connman`
