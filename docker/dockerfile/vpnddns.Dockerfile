ARG BASE_IMAGE_VERSION
FROM python:$BASE_IMAGE_VERSION as build

RUN apt update -qq \
    && apt install git curl gcc g++ make file musl-dev libffi6 libffi-dev zlib1g zlib1g-dev jq -y

WORKDIR /app
ADD src/ddns/Pipfile src/ddns/Pipfile.lock ./
RUN pip install pipenv && pipenv install -d

ADD src/utils src/utils
ADD src/executor src/executor
ADD src/ddns src/ddns
RUN V=$(python -c "from src.utils.constants import Versions; print (Versions.VPN_VERSION)") \
    && pipenv run python -m src.ddns.cmd_ddns download -cv $V -o /app/vpnbridge --no-zip \
    && pipenv run pip freeze > requirements.txt

FROM python:$BASE_IMAGE_VERSION

ARG MAINTAINER="zero88 <sontt246@gmail.com>"
ARG APP_VERSION="1.0.0"
ARG COMMIT_SHA=$COMMIT_SHA

LABEL maintainer=$MAINTAINER version=$APP_VERSION commit=$COMMIT_SHA

WORKDIR /app

ADD src/utils src/utils
ADD src/executor src/executor
ADD src/ddns src/ddns
COPY --from=build /app/vpnbridge ./vpnbridge
COPY --from=build /app/requirements.txt ./requirements.txt

RUN mkdir -p /certs && pip install -r requirements.txt

VOLUME /certs

ENTRYPOINT [ "python", "-m", "src.ddns.cmd_ddns", "sync" ]
