FROM alpine AS base
RUN apk update
RUN apk add spdlog openssl poco

FROM base AS build
RUN apk add git cmake ninja pkgconf g++ spdlog-dev openssl-dev poco-dev linux-headers
COPY . candy
RUN cd candy && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build && cmake --install build

FROM base AS product
RUN install -D /dev/null /var/lib/candy/lost
COPY --from=build /usr/local/bin/candy /usr/bin/candy
COPY candy.cfg /etc/candy.cfg
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.cfg"]
