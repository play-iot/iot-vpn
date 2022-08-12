FROM debian:10-slim

RUN apt-get update && \
    apt-get install -y isc-dhcp-client iputils-ping dnsutils

CMD [ "/bin/bash" ]