#!/usr/bin/env bash

DOWNLOAD=${1:-false}
cur="$PWD"

pipenv install
cd cli/python
if [[ "$DOWNLOAD" == "true" ]]; then
    V=$(python -c "from src.utils.constants import Versions; print (Versions.VPN_VERSION)") \
        && pipenv run python -m src.client.cmd_client download -cv "$V"
fi
pipenv run pyinstaller src/client/cmd_client.py -n playio-vpnc --clean --onefile --add-data src/client/resources/*:resources/
cp -rf dist/playio-vpnc "$cur/vagrant/shared"
cd -
