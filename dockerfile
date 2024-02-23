FROM alpine as base
RUN apk update
RUN apk add spdlog openssl libconfig++ uriparser zlib

FROM base AS build
RUN apk add git cmake ninja pkgconf g++ spdlog-dev openssl-dev libconfig-dev uriparser-dev zlib-dev argp-standalone linux-headers
COPY . candy
RUN cd candy/build && cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && cmake --build . && cmake --install .

FROM base AS product
VOLUME /var/lib/candy
COPY --from=build /usr/local/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-m", "client", "-w", "wss://zone.icandy.one/demo", "-s", "stun://stun.qq.com"]
