FROM ubuntu:rolling AS base
RUN apt-get update && apt-get -y install ca-certificates libspdlog-dev libssl-dev libconfig++-dev liburiparser-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*

FROM base AS build
RUN apt-get update && apt-get -y install git cmake ninja-build pkgconf g++ linux-headers-generic
COPY . candy
RUN cd candy/build && cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && cmake --build . && cmake --install .

FROM base AS product
COPY --from=build /usr/local/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-m", "client", "-w", "wss://zone.icandy.one/demo", "-s", "stun://stun.qq.com"]
