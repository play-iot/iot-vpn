#!/bin/bash

# m4_ignore(
echo "This is just a script template, not the script (yet) - pass it to 'argbash' to fix this." >&2
exit 11 #)Created by argbash-init v2.10.0
# ARG_OPTIONAL_SINGLE([directory], d, [Deployment directory. Default CURRENT_DIR. If provide, it will override env:VPNC_DEPLOYER])
# ARG_OPTIONAL_SINGLE([vpn-corp], c, [A VPN corporation], [playio])
# ARG_OPTIONAL_SINGLE([vpn-ver], r, [A VPN Client version])
# ARG_OPTIONAL_SINGLE([priv-dns], p, [A private DNS for test VPN state])
# ARG_OPTIONAL_SINGLE([customer], e, [An end customer code])
# ARG_POSITIONAL_SINGLE([command], , [Command to execute])
# ARG_TYPE_GROUP_SET([commands], [COMMAND], [command], [init,setup,state,rollout,extend,undeploy], [index])
# ARGBASH_SET_DELIM([ =])
# ARG_OPTION_STACKING([getopt])
# ARG_RESTRICT_VALUES([no-local-options])
# ARG_DEFAULTS_POS
# ARG_HELP([Play-iO VPNC deployer script])
# ARGBASH_GO

# [ <-- needed because of Argbash

# vvv  PLACE YOUR CODE HERE  vvv

set -e

NC='\033[0m'      #]
RED='\033[0;31m'  #]
GREEN='\033[32m'  #]
YELLOW='\033[33m' #]
BLUE='\033[34m'   #]

function error() {
    echo -e "$RED$1$NC"
}

function progress() {
    echo -e "$BLUE$1$NC"
}

function success() {
    echo -e "$GREEN$1$NC"
}

function debug() {
    echo -e "$YELLOW$1$NC"
}

GHRD_VER=1.1.2
GHRD_URL=https://github.com/zero88/gh-release-downloader/releases/download/v$GHRD_VER/ghrd

VPNC_REPO=play-iot/iot-vpn
VPNC_BINARY=playio-vpnc
VPNC_ARCH=("amd64" "armv7" "arm64")

DOCKER_COMPOSE_FILE="docker-compose.yml"
DOCKER_COMPOSE_V2_TMPL=$(
    cat <<-END
version: "2.4"

services:
  vpnc-deployer:
    image: playio/vpnc-deployer:{{VPNC_VERSION}}
    volumes:
      - {{DEPLOYMENT_DIR}}/files:/app/files:Z
      - {{DEPLOYMENT_DIR}}/inventory:/app/inventory:Z
      - /tmp/vpnc-deployer:/app/out
    environment:
      - ANSIBLE_STRATEGY_PLUGINS=/usr/lib/python3.8/site-packages/ansible_mitogen/plugins/strategy
      - ANSIBLE_STRATEGY=mitogen_linear
    command: >
      ansible-playbook "wf-vpnc-\$WORKFLOW.yml" -l all
          -e vpn_corp={{VPN_CORP}}
          -e vpnc_artifact={{VPN_CORP}}-vpnc
          -e args_prepare_credential_certs_file={{CUSTOMER_CODE}}-credentials.json
          -e '{"args_vpn_state_test_domains": ["google.com", "{{PRIVATE_DNS}}"]}'
END
)

HOST_FILE_TMPL=$(
cat <<-END
all:
  children:
    device:
      hosts:
        <device_name_1>:
          ansible_host: <device_ip_1>
        <device_name_2>:
          ansible_host: <device_ip_2>
          ansible_port: <device_port_2>
          ansible_user: <device_user_2>
          ansible_password: <device_password_2>
      vars:
        ansible_port: <device_ssh_port_for_all_hosts>
        ansible_user: <device_username_for_all_hosts>
        ansible_password: <device_user_password_for_all_hosts>
END
)

CER_FILE_TMPL=$(
cat <<-END
{
  "<device_name>": {
    "vpn_server": "<vpn_server>",
    "vpn_port": "<vpn_port>",
    "vpn_hub": "<customer_code>",
    "vpn_account": "<customer_code>",
    "vpn_auth_type": "<cert|password>",
    "vpn_user": "<vpn_user>",
    "vpn_password": "<vpn_password>",
    "vpn_cert_key": "<vpn_cert_key>",
    "vpn_private_key": "<vpn_private_key>"
  }
}
END
)

DEPLOYMENT_DIR=$([[ -z "$_arg_directory" ]] && ([[ -z "$VPNC_DEPLOYER" ]] && echo "$(pwd)" || echo "$VPNC_DEPLOYER") || echo "$_arg_directory")

function validate_dep() {
    progress "Validating dependencies..."
    local rc
    rc="$(which docker &> /dev/null; echo $?)" && [[ "$rc" != "0" ]] && { error "Docker is not installed"; exit 10; }
    rc="$(which docker-compose &> /dev/null; echo $?)" && [[ "$rc" != "0" ]] && { error "Docker Compose is not installed"; exit 10; }
    rc="$(which curl &> /dev/null; echo $?)" && [[ "$rc" != "0" ]] && { error "curl is not installed"; exit 10; }
    rc="$(which jq &> /dev/null; echo $?)" && [[ "$rc" != "0" ]] && { error "jq is not installed"; exit 10; }
    success "Dependencies OK!!!"
}

function validate_arg() {
    progress "Validating arguments..."
    if [[ $1 == "1" ]]; then
        [[ -n "$_arg_vpn_corp" ]] || { error "Missing VPN Corp arg"; exit 11; }
        [[ -n "$_arg_vpn_ver" ]]  || { error "Missing VPN Version arg"; exit 11; }
        [[ -n "$_arg_priv_dns" ]] || { error "Missing VPN private DNS arg"; exit 11; }
    fi
    [[ -n "$_arg_customer" ]] || { error "Missing customer code"; exit 11; }
    success "Arguments OK!!!"
}

function prepare() {
    progress "Preparing deployment location [$1]..."
    mkdir -p "$1/files" "$1/inventory"

    local rc
    rc="$(which ghrd &> /dev/null; echo $?)"
    if [[ "$rc" != "0" ]]; then
        sudo curl -L $GHRD_URL -o /usr/local/bin/ghrd && \
            sudo chmod +x /usr/local/bin/ghrd && \
            sudo ln -sf /usr/local/bin/ghrd /usr/bin/ghrd
    fi

    local tmp=/tmp/playio
    mkdir -p "$tmp"
    for arch in "${VPNC_ARCH[@]}"; do
        progress "Downloading VPNC binary for arch[$arch] to [$1/files/$2-vpnc-$arch]..."
        ghrd -a "$VPNC_BINARY.$arch.zip" -r "vpnc/v$3" -o $tmp $VPNC_REPO &> /dev/null
        unzip -d "$1/files" "$tmp/$VPNC_BINARY.$arch.zip" &> /dev/null
        mv "$1/files/$VPNC_BINARY" "$1/files/$2-vpnc-$arch"
    done
    rm -rf "$tmp"
    success "Prepared OK!!!"
}

function generate() {
    progress "Generating Docker compose stack..."
    echo "$DOCKER_COMPOSE_V2_TMPL" | sed \
        -e "s|{{DEPLOYMENT_DIR}}|$1|g" \
        -e "s|{{VPN_CORP}}|$_arg_vpn_corp|g" \
        -e "s|{{VPNC_VERSION}}|$_arg_vpn_ver|g" \
        -e "s|{{PRIVATE_DNS}}|$_arg_priv_dns|g" \
        -e "s|{{CUSTOMER_CODE}}|$_arg_customer|g" \
        > "$1/$2"
    echo "$HOST_FILE_TMPL" > "$1/$3"
    echo "$CER_FILE_TMPL" > "$1/$4"
    success "Generated OK: $1/$2"
    success "Generated OK: $1/$3"
    success "Generated OK: $1/$4"
}

function init() {
    validate_dep
    validate_arg "1"
    local hosts="inventory/$_arg_customer-hosts.yml"
    local creds="files/$_arg_customer-credentials.json"
    prepare "$DEPLOYMENT_DIR" "$_arg_vpn_corp" "$_arg_vpn_ver"
    generate "$DEPLOYMENT_DIR" "$_arg_customer-$DOCKER_COMPOSE_FILE" "$hosts" "$creds"
    debug "Please update remote device connection in '$DEPLOYMENT_DIR/$hosts'"
    debug "Please update VPN credentials in '$DEPLOYMENT_DIR/$creds'"
    debug "Then invoke '$0 <command>' in which command can be one of [setup,state,rollout,extend,undeploy]"
    success "DONE!!!"
}

function run() {
    validate_arg "2"
    local hosts="$DEPLOYMENT_DIR/inventory/$_arg_customer-hosts.yml"
    local creds="$DEPLOYMENT_DIR/files/$_arg_customer-credentials.json"
    [[ ! -f "$hosts" ]] && { error "Must provide $hosts"; exit 100; }
    [[ ! -f "$creds" ]] && { error "Must provide $creds"; exit 100; }
    progress "Start workflow vpnc $_arg_command..."
    echo "WORKFLOW=$_arg_command" > "$DEPLOYMENT_DIR/dkc.env"
    docker-compose -f "$DEPLOYMENT_DIR/$_arg_customer-$DOCKER_COMPOSE_FILE" --env-file "$DEPLOYMENT_DIR/dkc.env" up
    success "FINISH!!!"
}

if [[ "$_arg_command" == "init" ]]; then
    init
else
    run
fi

# ^^^  TERMINATE YOUR CODE BEFORE THE BOTTOM ARGBASH MARKER  ^^^

# ] <-- needed because of Argbash
