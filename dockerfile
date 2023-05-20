FROM archlinux as base
ARG MIRROR
RUN if [[ $MIRROR ]]; then printf "Server = %s/\$repo/os/\$arch\n" $MIRROR > /etc/pacman.d/mirrorlist ; fi
RUN pacman -Syyu --noconfirm
RUN pacman -S --needed --noconfirm spdlog openssl libconfig uriparser

FROM base as builder
WORKDIR root
COPY . .
RUN pacman -S --needed --noconfirm git cmake make pkgconf clang
RUN cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release .. && make -j install

FROM base as production
COPY --from=builder /usr/bin/candy /usr/bin/candy
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
