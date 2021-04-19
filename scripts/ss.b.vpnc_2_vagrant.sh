#!/usr/bin/env bash

cur="$PWD"
pipenv install
cd client/python
pipenv run pyinstaller src/client/cmd_client.py -n qweio-vpnc --clean --onefile --add-data src/client/resources/*:resources/
cp -rf dist/qweio-vpnc "$cur/vagrant/shared"
cd -
