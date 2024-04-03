FROM alpine as base
RUN apk update
RUN apk add spdlog openssl libconfig++ uriparser poco

FROM base AS build
RUN apk add git cmake ninja pkgconf g++ spdlog-dev openssl-dev libconfig-dev uriparser-dev poco-dev argp-standalone linux-headers
COPY . candy
RUN cd candy && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build && cmake --install build

FROM base AS product
RUN install -D /dev/null /var/lib/candy/lost
COPY --from=build /usr/local/bin/candy /usr/bin/candy
COPY candy.conf /etc/candy.conf
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
