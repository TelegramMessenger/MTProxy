FROM alpine:3.8 as build

WORKDIR /srv/mtproto-proxy-build
COPY . /srv/mtproto-proxy-build

RUN apk add --no-cache --virtual .build-deps \
	git make gcc musl-dev linux-headers openssl-dev \
	&& patch -p0 -i patches/randr_compat.patch \
	&& make

FROM alpine:3.8
LABEL maintainer="Pavel Shishkanov <pshishkanov@fastmail.com>" \
      description="Telegram Messenger MTProto zero-configuration proxy server."

RUN apk add --no-cache curl \
  && ln -s /usr/lib/libcrypto.so.43 /usr/lib/libcrypto.so.1.0.0

WORKDIR /srv/mtproto-proxy

COPY --from=build /srv/mtproto-proxy-build/objs/bin/mtproto-proxy .
COPY docker/entrypoint.sh .

VOLUME /srv/mtproto-proxy/config
EXPOSE 7227 443

ENTRYPOINT ["sh", "/srv/mtproto-proxy/entrypoint.sh"]
CMD [ "--port", "7227", "--http-ports", "443", "--slaves", "2", "--max-special-connections", "60000",  "--allow-skip-dh"]