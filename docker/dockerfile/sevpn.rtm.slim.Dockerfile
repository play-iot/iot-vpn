FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.34-9745-beta"

USER root

WORKDIR /app
RUN ghrd -a .*vpnserver-.*-linux-x64.*.tar.gz -x -r $VPN_VERSION -o /app SoftEtherVPN/SoftEtherVPN_Stable

# ------------------------------------------------------------------
FROM debian:10-slim as stage2

WORKDIR /app
RUN apt-get update -y && apt-get install build-essential -y
COPY --from=stage1 /app/* /tmp
RUN tar -xvzf /tmp/*.tar.gz -C ./ \
    && cd vpnserver/ \
    && yes 1 | make -C ./

# ------------------------------------------------------------------
FROM debian:10-slim

WORKDIR /app/vpnserver

ARG VPN_VERSION="5.01.9674"
ENV TINI_VERSION v0.19.0
LABEL VPN_VERSION=$VPN_VERSION
LABEL maintainer="sontt246@gmail.com"

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini

RUN mkdir -p /etc/vpnserver \
    && touch /etc/vpnserver/vpn_server.conf \
    && ln -sf /etc/vpnserver/vpn_server.config /app/vpnserver/vpn_server.config \
    && chmod +x /usr/bin/tini

COPY --from=stage2 /app/vpnserver ./

VOLUME /etc/vpnserver
EXPOSE 443/tcp 5555/tcp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./vpnserver", "execsvc"]
