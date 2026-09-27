FROM ubuntu:22.04 as builder

WORKDIR /app

COPY . /app

ARG APT_HTTPPROXY=
ARG APT_MIRROR=archive.ubuntu.com

RUN sed -i "s/archive.ubuntu.com/$APT_MIRROR/g" /etc/apt/sources.list


RUN apt update \
    && apt install -y git curl build-essential libssl-dev zlib1g-dev vim \
    && make \
    && ! ldd objs/bin/mtproto-proxy  && echo "Library check successful" || echo "Library check failed"


RUN env https_proxy=$APT_HTTPPROXY curl -s https://core.telegram.org/getProxySecret -o objs/bin/proxy-secret \
    && env https_proxy=$APT_HTTPPROXY curl -s https://core.telegram.org/getProxyConfig -o objs/bin/proxy-multi.conf

FROM busybox:latest

WORKDIR /app

COPY --from=builder --chown=0 /app/objs/bin/ /app


ENTRYPOINT ["/app/mtproto-proxy"]

