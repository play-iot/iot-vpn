FROM alpine

RUN apk add --no-cache curl dhclient

CMD [ "/bin/sh" ]