#!/usr/bin/env bash

source ./docker/.env

COMMAND="${1:-build}"
WORKFLOW=${2:-state}

sha=$(git rev-parse --short HEAD)
tag="dev"
name="vpnc-ansible"
image="$BRAND-$name"
docker_workdir="$(pwd)/cli/ansible"
dockerfile="$docker_workdir/docker/$name.Dockerfile"

function build() {
    DOCKER_BUILDKIT=1 docker build \
        --build-arg "BASE_IMAGE_VERSION=$ANSIBLE_2_9" \
        --build-arg "MAINTAINER=$APP_MAINTAINER" \
        --build-arg "APP_VERSION=$APP_VERSION" \
        --build-arg "COMMIT_SHA=$sha" \
        -t "$image:$tag" \
        --progress=plain \
        -f "$dockerfile" \
        "$docker_workdir" || {
        echo "Build $tag failure"
        exit 2
    }
}

if [[ $COMMAND == "build" ]]; then
    build
elif [[ $COMMAND == "up" ]]; then
    echo "WORKFLOW=$WORKFLOW" > docker/dev-vpnc-ansible.env
    docker-compose -f docker/vpnc-deployer-dkc.yml --env-file docker/dev-vpnc-ansible.env up
fi
