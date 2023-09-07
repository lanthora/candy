FROM ubuntu:rolling as base
RUN apt-get -y update && apt-get -y install ca-certificates libspdlog-dev libssl-dev libconfig++-dev liburiparser-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*

FROM base as builder
RUN apt-get update && apt-get -y install git cmake ninja-build pkgconf g++ libconfig++-dev liburiparser-dev zlib1g-dev linux-headers-generic
COPY . candy
RUN cd candy/build && cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && cmake --build . && cmake --install .

FROM base as production
COPY --from=builder /usr/local/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-m", "client", "-w", "wss://zone.icandy.one/demo", "-s", "stun://stun.cloudflare.com"]
