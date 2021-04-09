#!/usr/bin/env bash

if [[ -x "/vagrant/qweio-vpnc" ]]; then
    rm -rf /usr/local/bin/qweio-vpnc
    ln -s /vagrant/qweio-vpnc /usr/local/bin/qweio-vpnc
fi
