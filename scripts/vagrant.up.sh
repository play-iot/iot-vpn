#!/usr/bin/env bash

cur="$PWD"

BLUE='\033[0;34m'
NC='\033[0m'

for machine in "$@"
do
    if [[ -f "$cur/vagrant/$machine/Vagrantfile" ]]; then
        cd "$cur/vagrant/$machine"
        echo -e "${BLUE}Vagrant up $machine....${NC}"
        vagrant up
        cd -
        echo "=================================================================================="
    fi
done
