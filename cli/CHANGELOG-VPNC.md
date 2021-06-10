# Changelog

## [v0.9.4](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.9.4) (2021-06-10)

### Changes

- Resolve [#34](https://github.com/play-iot/iot-vpn/issues/34) Support `ARM64`
- `playio-vpnc disconnect` support one or many or all VPN accounts

### Bugfix

- Fix [#85](https://github.com/play-iot/iot-vpn/issues/85): conflict DNS resolver between `dnsmasq` and `systemd-resolved`
- Fix [#86](https://github.com/play-iot/iot-vpn/issues/86): make VPN stable when manage many VPN connections on same computer 

## [v0.9.3](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.9.3) (2021-05-13)

### Changes

- Update `Brand` from `qweio` -> `playio`

## [v0.9.2](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.9.2) (2021-05-05)

### Improvement

- Resolved [#53](https://github.com/play-iot/iot-vpn/issues/53)
- Resolved [#54](https://github.com/play-iot/iot-vpn/issues/54)
- Fixed [#56](https://github.com/play-iot/iot-vpn/issues/56)

## [v0.9.1](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.9.1) (2021-04-25)

### Improvement

- Resolved [#50](https://github.com/play-iot/iot-vpn/issues/50)

## [v0.9.0](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.9.0) (2021-04-24)

### Improvement

- Resolved [#46](https://github.com/play-iot/iot-vpn/issues/46)

## [v0.8.1](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.8.1) (2021-04-20)

### Bugfix

- Regression fix [#38](https://github.com/play-iot/iot-vpn/issues/38): Connman on BeagleBone

## [v0.8.0](https://github.com/play-iot/iot-vpn/tree/vpnc/v0.8.0) (2021-04-20)

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
