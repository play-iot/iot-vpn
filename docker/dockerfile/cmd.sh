#!/bin/bash 

/app/vpnclient/vpnclient execsvc &
sleep 20
while true; do
    if [[ $(./vpncmd /client localhost /cmd accountlist | grep Status | cut -d'|' -f 2) == 'Connected' ]]; then
        dhclient -4 -v vpn_${SE_NICNAME}
        break
    fi
    sleep 5
done

wait
