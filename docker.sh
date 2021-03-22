#!/usr/bin/env bash

IMAGE="${1:-alpine}"
VERSION="${2:-v4.34-9745-beta}"

if [[ $IMAGE == "alpine" ]]; then
    docker build -f docker/softethervpn.alpine.Dockerfile --build-arg VPN_VERSION="$VERSION" -t softethervpn:dev-alpine ./
elif [[ $IMAGE == "debian" ]]; then
    docker build -f docker/softethervpn.debian.Dockerfile --build-arg VPN_VERSION="$VERSION" -t softethervpn:dev-debian ./
else
    echo "Unsupported image $IMAGE"
    exit 5
fi

