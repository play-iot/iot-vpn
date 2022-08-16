#!/bin/sh

set -e

rm -f /app/vpnclient/vpn_client.config

/app/vpnclient/vpnclient start
# skip adapter creation if exists
if grep -q vpn_${SE_NICNAME} /proc/net/dev; then 
printf "NIC ${SE_NICNAME} already exists, skipping creation" 1>&2
else
/app/vpnclient/vpncmd localhost \
    /CLIENT \
    /CMD NicCreate ${SE_NICNAME} > /dev/null 2>&1
fi

if [ -z ${SE_USERNAME+blank} ]; then
    printf 'Please provide VPN Username' 1>&2
fi

# create account
/app/vpnclient/vpncmd localhost \
/CLIENT \
/CMD AccountCreate ${SE_ACCOUNT_NAME} \
/SERVER:${SE_SERVER} \
/HUB:${SE_HUB} \
/USERNAME:${SE_USERNAME} \
/NICNAME:${SE_NICNAME} > /dev/null 2>&1

# set account cert
/app/vpnclient/vpncmd localhost \
/CLIENT \
/CMD AccountCertSet ${SE_ACCOUNT_NAME} \
/LOADCERT:/app/cacerts/${SE_USERNAME}.crt \
/LOADKEY:/app/cacerts/${SE_USERNAME}.key

# set account to auto-connect
/app/vpnclient/vpncmd localhost \
/CLIENT \
/CMD AccountStartupSet ${SE_ACCOUNT_NAME} > /dev/null 2>&1

/app/vpnclient/vpnclient stop

exec "$@"
