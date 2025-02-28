FROM alpine:3.21

RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories

RUN apk update \
    && apk upgrade musl \
    && apk add ca-certificates dpkg@edge rpm@edge expat@edge libbz2@edge libarchive@edge db@edge

COPY starboard-scanner-khulnasoft /usr/local/bin/starboard-scanner-khulnasoft

ENTRYPOINT ["starboard-scanner-khulnasoft"]
