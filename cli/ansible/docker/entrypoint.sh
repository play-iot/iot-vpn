#!/bin/bash

/docker-entrypoint.sh
if [[ -f /app/docker/banner.txt && $SHOW_ABOUT == "1" ]]; then
    cat /app/docker/banner.txt
    echo ""
fi
if [[ $SHOW_VERSION == "1" ]]; then
    python /app/version.py
fi
exec "${@}"
