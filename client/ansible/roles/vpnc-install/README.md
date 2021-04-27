#DRAFT# vpnc-install
=========

This role install and configure vpn client

Requirements
------------

- Rename `qweio-vpnc` binary to match CPU architecture and put in `binary` folder like sample below.
- Put credentials in `credentials` folder, naming the credential files to match what're stated in [`inventory.yml`](../inventory.yml) file.

```
.
└── vpnc-install
    ├── README.md
    ├── defaults
    │   └── main.yml
    ├── files
    │   ├── binary
    │   │   ├── qweio-vpnc-amd64
    │   │   └── qweio-vpnc-armv7
    │   └── credentials
    ├── tasks
        ├── Debian.yml
        ├── Redhat.yml
        ├── common.yml
        └── main.yml
```

