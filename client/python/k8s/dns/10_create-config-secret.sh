#!/bin/bash

function createSecret {
    local ns="$1"
    local component="$2"
    local name="$3"
    shift 3
    local cmd="kubectl --namespace $ns create secret generic $name $* --dry-run=client --output=yaml | kubectl apply -f -"
    echo "$cmd"
    eval "$cmd"
    kubectl --namespace "$ns" label --overwrite secret "$name" app="$ns" role=secret component="$component"
}

function createConfig {
    local ns="$1"
    local component="$2"
    local name="$3"
    shift 3
    local cmd="kubectl --namespace $ns create configmap $name $* --dry-run=client --output=yaml | kubectl apply -f -"
    echo "$cmd"
    eval "$cmd"
    kubectl --namespace "$ns" label --overwrite configmap "$name" app="$ns" role=config component="$component"
}

source "$WORK_DIR/$CUSTOMER_SECRET_FILE"

createConfig "$NAMESPACE" "$K8S_COMPONENT" "$K8S_CONFIG_NAME" --from-env-file="$WORK_DIR/$CUSTOMER_ENV_FILE"
createSecret "$NAMESPACE" "$K8S_COMPONENT" "$K8S_SECRET_NAME" \
    --from-file=svc="$WORK_DIR/svc.json" \
    --from-literal=hubpwd="$VPN_SYNC_HUB_PASSWORD"
