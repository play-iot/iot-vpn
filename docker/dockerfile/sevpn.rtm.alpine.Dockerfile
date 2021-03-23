FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.34-9745-beta"
ARG VPN_BRANCH="stable"

USER root

ENV VPN_REPO_STABLE="SoftEtherVPN/SoftEtherVPN_Stable"
ENV VPN_REPO_DEV="SoftEtherVPN/SoftEtherVPN"

WORKDIR /app

RUN apk add build-base openssl openssl-dev ncurses readline cmake linux-headers
SHELL ["/bin/bash", "-c"]
RUN VPN_REPO=$([[ $VPN_BRANCH == "stable" ]] && echo $VPN_REPO_STABLE || echo $VPN_REPO_DEV) \
    && [[ $VPN_BRANCH == "stable" ]] && opts=(-a .*vpnserver-.*-linux-x64.*.tar.gz -x) || opts=(-s tar) \
    && ghrd ${opts[@]} -r $VPN_VERSION -o /tmp $VPN_REPO
    && tar -xvzf /tmp/*.tar.gz -C /app \
    && cd /app/vpnserver \
    && yes 1 | make -C ./

# -----------------------------------------------
FROM alpine:latest

WORKDIR /app
COPY --from=stage1 /app/vpnserver ./

RUN apk add --no-cache tini \
    && ln -sf /etc/vpnserver/vpn_server.config /app/vpnserver/vpn_server.config

VOLUME /etc/vpnserver
EXPOSE 443/tcp

ENTRYPOINT ["/usr/bin/tini", "-vvv", "--"]
CMD ["/app/vpnserver/vpnserver", "execsvc", "--foreground"]
