#!/usr/bin/env bash

source ./docker/.env

sha=$(git rev-parse --short HEAD)
tag="dev"
name="vpnc-ansible"
image="$BRAND-$name"
docker_workdir="$(pwd)/cli/ansible"
dockerfile="$docker_workdir/docker/$name.Dockerfile"

DOCKER_BUILDKIT=1 docker build \
    --build-arg "BASE_IMAGE_VERSION=$ANSIBLE_2_9" \
    --build-arg "MAINTAINER=$APP_MAINTAINER" \
    --build-arg "APP_VERSION=$APP_VERSION" \
    --build-arg "COMMIT_SHA=$sha" \
    -t "$image:$tag" \
    --progress=plain \
    -f "$dockerfile" \
    "$docker_workdir" || { echo "Build $tag failure"; exit 2; }
