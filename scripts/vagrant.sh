#!/usr/bin/env bash

cur="$PWD"

COMMAND=(up halt destroy status port ssh)

RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

cmd=$1

if [[ ! " ${COMMAND[*]} " =~ " $cmd " ]]; then
    c=$(
        IFS=/
        echo "${COMMAND[*]}"
    )
    echo -e "${RED}Unsupported [$cmd]. One of command [${c}] ${NC}"
    exit 10
fi

shift

vagrant_opt=("$cmd")
if [[ $cmd == "destroy" && $FORCE == "1" ]]; then
    vagrant_opt+=("-f")
fi

for machine in "$@"; do
    if [[ -f "$cur/vagrant/$machine/Vagrantfile" ]]; then
        cd "$cur/vagrant/$machine"
        echo -e "${BLUE}Vagrant $cmd $machine....${NC}"
        vagrant "${vagrant_opt[@]}"
        cd - >/dev/null
        echo "=================================================================================="
    else
        echo -e "${YELLOW}Not found machine [$machine] ${NC}"
        echo "=================================================================================="
    fi
done
