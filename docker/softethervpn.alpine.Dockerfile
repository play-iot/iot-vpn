FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.34-9745-beta"

USER root
ENV LANG en_US.UTF-8
WORKDIR /app
RUN apk add build-base openssl openssl-dev ncurses readline cmake linux-headers
RUN ghrd -a .*vpnserver-.*-linux-x64.*.tar.gz -x -r $VPN_VERSION -o /tmp SoftEtherVPN/SoftEtherVPN_Stable \
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

ENTRYPOINT ["/sbin/tini",  "--"]
CMD ["/bin/sh", "-c", "touch /etc/vpnserver/vpn_server.conf && exec /app/vpnserver/vpnserver execsvc"]
