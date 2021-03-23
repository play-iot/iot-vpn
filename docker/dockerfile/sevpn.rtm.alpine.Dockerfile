FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.34-9745-beta"

USER root
RUN apk add cmake git gcc g++ make openssl-dev ncurses-dev libsodium-dev readline-dev zlib-dev linux-headers

WORKDIR /app
RUN ghrd -a .*vpnserver-.*-linux-x64.*.tar.gz -x -r $VPN_VERSION -o /tmp SoftEtherVPN/SoftEtherVPN_Stable
ENV USE_MUSL=YES
RUN tar -xvzf /tmp/*.tar.gz -C /app \
    && cd /app/vpnserver \
    && yes 1 | make -C ./

# -----------------------------------------------
FROM alpine:3.13.2

WORKDIR /app/vpnserver
COPY --from=stage1 /app/vpnserver ./

RUN apk add --no-cache tini \
    && mkdir -p /etc/vpnserver \
    && touch /etc/vpnserver/vpn_server.conf \
    && ln -sf /etc/vpnserver/vpn_server.config /app/vpnserver/vpn_server.config

VOLUME /etc/vpnserver
EXPOSE 443/tcp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./vpnserver", "execsvc"]
