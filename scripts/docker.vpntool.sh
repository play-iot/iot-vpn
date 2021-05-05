#!/usr/bin/env bash

source ./docker/.env

mode="${1:-client}"
arch="${2:-false}"
sha=$(git rev-parse --short HEAD)
tag="dev"
name="vpn$mode"
image="$BRAND-$name"
docker_workdir="$(pwd)/client/python"
dockerfile="$docker_workdir/docker/$name.Dockerfile"
platform="linux/arm/v7,linux/amd64"


function multiarch() {
    DOCKER_BUILDKIT=1 docker buildx build \
    --build-arg "MAINTAINER=$APP_MAINTAINER" \
    --build-arg "APP_VERSION=$APP_VERSION" \
    --build-arg "BASE_IMAGE_VERSION=$1" \
    --build-arg "COMMIT_SHA=$sha" \
    --platform "$platform" \
    --network host \
    --allow network.host \
    --cache-from "type=registry,ref=localhost:5000/$image:buildcache" \
    --cache-to "type=registry,ref=localhost:5000/$image:buildcache,mode=max" \
    -f "$dockerfile" \
    --pull --push --tag "localhost:5000/$image:$tag" \
    "$docker_workdir" || { echo "Build $tag failure"; exit 2; }
}

function normal() {
    DOCKER_BUILDKIT=1 docker build \
    --build-arg "MAINTAINER=$APP_MAINTAINER" \
    --build-arg "APP_VERSION=$APP_VERSION" \
    --build-arg "BASE_IMAGE_VERSION=$1" \
    --build-arg "COMMIT_SHA=$sha" \
    -t "$image:$tag"\
    --progress=plain \
    -f "$dockerfile" \
    "$docker_workdir" || { echo "Build $tag failure"; exit 2; }
}

PYTHON_VERSION=$([[ "$mode" == "client" ]] && echo "$PYTHON_3_7" || echo "$PYTHON_3_8")

if [[ "$arch" == "true" ]]; then
    multiarch "$PYTHON_VERSION"
else
    normal "$PYTHON_VERSION"
fi


docker rmi $(docker images | grep "none" | awk '/ / { print $3 }') || exit 0
