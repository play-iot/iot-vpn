#!/usr/bin/env bash

COMMAND="${1:-build}"
IMAGE="${2:-debian}"
BRANCH="${3:-rtm}"
VERSION="$4"

if [[ $IMAGE != "alpine" && $IMAGE != "debian" ]]; then
    echo "Unsupported image $IMAGE"
    exit 5
fi

if [[ $BRANCH != "src" && $BRANCH != "rtm" ]]; then
    echo "Unsupported image $BRANCH"
    exit 5
fi

if [[ -z "$VERSION" ]]; then
  VERSION=$([[ "$BRANCH" == "rtm" ]] && echo "v4.34-9745-beta" || echo "5.01.9674")
fi

dockerfile="docker/dockerfile/sevpn.$BRANCH.$IMAGE.Dockerfile"
tag="softethervpn:dev-$IMAGE-$BRANCH-$VERSION"

if [[ $COMMAND == "build" ]]; then
    docker build -f "$dockerfile" --build-arg VPN_VERSION="$VERSION" -t "$tag" ./docker
elif [[ $COMMAND == "up" ]]; then
    cat <<EOT > docker/dev.env
IMAGE=$IMAGE
BRANCH=$BRANCH
VERSION=$VERSION
EOT

    docker-compose -f docker/vpn-dkc.yml --env-file dev.env up
fi
