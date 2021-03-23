FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="5.01.9674"

USER root

WORKDIR /app
RUN ghrd -s tar -r $VPN_VERSION -o /tmp SoftEtherVPN/SoftEtherVPN

# ------------------------------------------------------------------
FROM debian:10-slim as stage2

WORKDIR /app/vpnserver
RUN apt-get update -y \
    && apt-get install cmake git gcc g++ make libncurses5-dev libssl-dev libsodium-dev libreadline-dev zlib1g-dev -y
COPY --from=stage1 /tmp/* /tmp
RUN tar -xvzf /tmp/*.tar.gz -C /app/vpnserver --strip-component 1 \
    && CMAKE_FLAGS="-DSKIP_CPU_FEATURES=1" ./configure \
    && make -C tmp
RUN apt-get install tree \
    && tree -ah /app/vpnserver

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
