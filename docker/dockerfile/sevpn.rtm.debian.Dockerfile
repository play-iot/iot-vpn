FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.34-9745-beta"

USER root

WORKDIR /app
RUN ghrd -a .*vpnserver-.*-linux-x64.*.tar.gz -x -r $VPN_VERSION -o /tmp SoftEtherVPN/SoftEtherVPN_Stable

# ------------------------------------------------------------------
FROM debian:10-slim as stage2

WORKDIR /app/vpnserver
RUN apt-get update -y \
    && apt-get install build-essential -y
COPY --from=stage1 /tmp/* /tmp
RUN tar -xvzf /tmp/*.tar.gz -C ./ \
    && yes 1 | make -C ./

# ------------------------------------------------------------------
FROM debian:10-slim

WORKDIR /app/vpnserver
COPY --from=stage2 /app/vpnserver ./

ENV TINI_VERSION v0.19.0
LABEL VPN_VERSION=$VPN_VERSION

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini

RUN mkdir -p /etc/vpnserver \
    && touch /etc/vpnserver/vpn_server.conf \
    && ln -sf /etc/vpnserver/vpn_server.config /app/vpnserver/vpn_server.config \
    && chmod +x /usr/bin/tini

VOLUME /etc/vpnserver
EXPOSE 443/tcp 5555/tcp

ENTRYPOINT ["/usr/bin/tini", "-vvv", "--"]
CMD ["/app/vpnserver/vpnserver", "execsvc", "--foreground"]
