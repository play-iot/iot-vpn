ARG BASE_IMAGE_VERSION=2.10.0
FROM matejak/argbash:$BASE_IMAGE_VERSION

WORKDIR /app
COPY vpnc-deployer-cli.m4 ./
RUN argbash vpnc-deployer-cli.m4 -o vpnc-deployer-cli && chmod +x vpnc-deployer-cli
