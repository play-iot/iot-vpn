#!/usr/bin/env bash

COMMAND="${1:-build}"
IMAGE="${2:-slim}"
EDITION="${3:-rtm}"
VERSION="${4:-latest}"

if [[ $IMAGE != "alpine" && $IMAGE != "slim" ]]; then
    echo "Unsupported image $IMAGE"
    exit 5
fi

if [[ $EDITION != "src" && $EDITION != "rtm" ]]; then
    echo "Unsupported image $EDITION"
    exit 5
fi

if [[ -z "$VERSION" ]]; then
    VERSION=$([[ "$EDITION" == "rtm" ]] && echo "v4.34-9745-beta" || echo "5.01.9674")
fi

dockerfile="docker/dockerfile/sevpn.$EDITION.$IMAGE.Dockerfile"
tag="softethervpn:$IMAGE-$EDITION-$VERSION"

if [[ $COMMAND == "build" ]]; then
    docker build -f "$dockerfile" --build-arg VPN_VERSION="$VERSION" -t "$tag" ./docker
elif [[ $COMMAND == "up" ]]; then
    cat <<EOT >docker/dev.env
IMAGE=$IMAGE
EDITION=$EDITION
VERSION=$VERSION
EOT

    docker-compose -f docker/vpn-dkc.yml --env-file dev.env up
fi
