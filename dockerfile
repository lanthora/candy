FROM alpine as base

RUN apk update
RUN apk add spdlog openssl libconfig++ uriparser zlib

FROM base as builder
WORKDIR root
COPY . .
RUN apk add git cmake make pkgconf g++ spdlog-dev openssl-dev libconfig-dev uriparser-dev zlib-dev argp-standalone linux-headers
RUN cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release .. && make -j install

FROM base as production
COPY --from=builder /usr/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
