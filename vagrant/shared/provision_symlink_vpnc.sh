#!/usr/bin/env bash

if [[ -x "/vagrant/playio-vpnc" ]]; then
    rm -rf /usr/local/bin/playio-vpnc
    ln -s /vagrant/playio-vpnc /usr/local/bin/playio-vpnc
fi
