ARG BASE_IMAGE_VERSION=2.9
FROM cytopia/ansible:$BASE_IMAGE_VERSION

RUN pip3 install --no-cache-dir jmespath

ARG BRAND=""
ARG MAINTAINER="zero88 <sontt246@gmail.com>"
ARG APP_VERSION="1.0.0"
ARG COMMIT_SHA=$COMMIT_SHA

LABEL "maintainer"="$MAINTAINER" version=$APP_VERSION commit=$COMMIT_SHA
LABEL "org.opencontainers.image.authors"="$MAINTAINER"
LABEL "org.opencontainers.image.vendor"="$BRAND"
LABEL "org.opencontainers.image.licenses"="Apache 2.0"
LABEL "org.opencontainers.image.url"=""
LABEL "org.opencontainers.image.documentation"=""
LABEL "org.opencontainers.image.source"=""
LABEL "org.opencontainers.image.ref.name"="Ansible for VPNC"
LABEL "org.opencontainers.image.title"="Ansible for VPNC"
LABEL "org.opencontainers.image.description"="Ansible for VPNC"

WORKDIR /app
ADD . ./

ENV SHOW_ABOUT=1
ENV SHOW_VERSION=1

ENTRYPOINT [ "/app/docker/entrypoint.sh" ]
