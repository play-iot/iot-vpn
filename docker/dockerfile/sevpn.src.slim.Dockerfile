FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="5.01.9674"

USER root

WORKDIR /app
RUN VER=$(ghrd -s tar -r $VPN_VERSION -o /tmp SoftEtherVPN/SoftEtherVPN \
    | tee /dev/stdout | awk '{print $2}' | awk -F '-' '{print $3}' | sed "s/.tar.gz//g")

ENV VER=$VER

# ------------------------------------------------------------------
FROM debian:10-slim as stage2

WORKDIR /app/vpnserver
RUN apt-get update -y \
    && apt-get install cmake git gcc g++ make libncurses5-dev libssl-dev libsodium-dev libreadline-dev zlib1g-dev -y
COPY --from=stage1 /tmp/* /tmp
RUN tar -xzf /tmp/*.tar.gz -C /app/vpnserver --strip-component 1 \
    && CMAKE_FLAGS="-DSKIP_CPU_FEATURES=1" ./configure \
    && make -C tmp

# ------------------------------------------------------------------
FROM debian:10-slim

WORKDIR /app/vpnserver

ARG VER
LABEL VPN_VERSION=$VER
LABEL maintainer="sontt246@gmail.com"

RUN apt-get update -y \
    && apt-get install tini libreadline7 libncurses6 libssl1.1 -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/vpnserver \
    && touch /etc/vpnserver/vpn_server.conf \
    && ln -sf /etc/vpnserver/vpn_server.config /app/vpnserver/vpn_server.config \
    && chmod +x /usr/bin/tini

COPY --from=stage2 /app/vpnserver/build/* ./

VOLUME /etc/vpnserver
EXPOSE 443/tcp 5555/tcp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./vpnserver", "execsvc", "--foreground"]
