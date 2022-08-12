FROM zero88/ghrd:1.1.2 as stage1

ARG VPN_VERSION="v4.38-9760-rtm"

USER root

WORKDIR /app
RUN ghrd -a .*vpnclient-.*-linux-x64.*.tar.gz -x -r $VPN_VERSION -o /app SoftEtherVPN/SoftEtherVPN_Stable

# ------------------------------------------------------------------
FROM debian:10-slim as stage2

WORKDIR /app
RUN apt-get update -y && apt-get install build-essential -y
COPY --from=stage1 /app/* /tmp/
RUN tar -xvzf /tmp/*.tar.gz -C ./ \
    && cd vpnclient/ \
    && yes 1 | make -C ./

# ------------------------------------------------------------------
FROM debian:10-slim

WORKDIR /app/vpnclient

ENV TINI_VERSION v0.19.0
ENV SE_SERVER playiot
ENV SE_NICNAME playiot
ENV SE_ACCOUNT_NAME playiot
ENV SE_TYPE standard

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini

RUN apt-get update -y && apt-get install -y isc-dhcp-client \
    && mkdir -p /etc/vpnclient \
    && touch /etc/vpnclient/vpn_client.conf \
    && ln -sf /etc/vpnclient/vpn_client.config /app/vpnclient/vpn_client.config \
    && chmod +x /usr/bin/tini

COPY --from=stage2 /app/vpnclient ./

COPY ./entrypoint_cl.sh /app/entrypoint.sh
COPY ./cmd.sh /app/cmd.sh

RUN chmod +x /app/entrypoint.sh
RUN chmod +x /app/cmd.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/usr/bin/tini", "--", "/app/cmd.sh"]
