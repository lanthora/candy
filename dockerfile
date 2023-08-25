FROM alpine as base
RUN apk update
RUN apk add openssl libconfig++ uriparser zlib

FROM base as builder
RUN apk add git cmake ninja pkgconf g++ openssl-dev libconfig-dev uriparser-dev zlib-dev argp-standalone linux-headers
COPY . candy
RUN cd candy/build && cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release .. && cmake --build . && cmake --install .

FROM base as production
COPY --from=builder /usr/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-m", "client", "-w", "wss://zone.icandy.one/demo"]
