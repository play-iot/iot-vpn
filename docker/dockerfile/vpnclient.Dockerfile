ARG BASE_IMAGE_VERSION
FROM python:$BASE_IMAGE_VERSION as build

ARG TARGETPLATFORM
ARG EABI="true"

RUN apt update -qq \
    && apt install git curl gcc g++ make file musl-dev libffi6 libffi-dev zlib1g zlib1g-dev jq -y

WORKDIR /usr/src/app/
RUN pip install pipenv
ADD src/client/Pipfile src/client/Pipfile.lock ./
RUN pipenv install -d

ADD src/client src/client
ADD src/utils src/utils
ADD src/executor src/executor
SHELL ["/bin/bash", "-c"]
RUN P=$([[ "$TARGETPLATFORM" =~ linux/arm/v(6|7) && "$EABI" == "true" ]] && echo "linux/arm/32-eabi" || echo "$TARGETPLATFORM") \
    && V=$(python -c "from src.utils.constants import Versions; print (Versions.VPN_VERSION)") \
    && pipenv run python -m src.client.cmd_client download -p $P -cv $V \
    && pipenv run pyinstaller src/client/cmd_client.py -n qweio-vpnc --clean --onefile \
        --add-data src/client/resources/*:resources/

FROM python:$BASE_IMAGE_VERSION

ARG MAINTAINER="zero88 <sontt246@gmail.com>"
ARG APP_VERSION="1.0.0"
ARG COMMIT_SHA=$COMMIT_SHA

LABEL maintainer=$MAINTAINER version=$APP_VERSION commit=$COMMIT_SHA

WORKDIR /usr/src/app/
COPY --from=build /usr/src/app/dist/qweio-vpnc ./

ENTRYPOINT [ "./qweio-vpnc" ]
