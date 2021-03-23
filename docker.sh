#!/usr/bin/env bash

IMAGE="${1:-alpine}"
BRANCH="${2:-rtm}"
VERSION="$3"

if [[ $IMAGE != "alpine" && $IMAGE != "debian" ]]; then
    echo "Unsupported image $IMAGE"
    exit 5
fi

if [[ $BRANCH != "src" && $BRANCH != "rtm" ]]; then
    echo "Unsupported image $BRANCH"
    exit 5
fi

if [[ -z "$VERSION" ]]; then
  VERSION=$([[ "$BRANCH" == "stable" ]] && echo "v4.34-9745-beta" || echo "5.01.9674")
fi

dockerfile="docker/dockerfile/sevpn.$BRANCH.$IMAGE.Dockerfile"
tag="softethervpn:dev-$IMAGE-$BRANCH-$VERSION"

docker build -f "$dockerfile" --build-arg VPN_VERSION="$VERSION" -t "$tag" ./
