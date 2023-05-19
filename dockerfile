FROM archlinux

ARG MIRROR

WORKDIR /root/build
COPY . .

RUN if [[ $MIRROR ]]; then printf "Server = %s/\$repo/os/\$arch\n" $MIRROR > /etc/pacman.d/mirrorlist ; fi
RUN pacman -Syyu --noconfirm && \
    pacman -S --needed --noconfirm git cmake make pkgconf clang spdlog openssl libconfig uriparser && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release .. && \
    make -j install && \
    pacman -Rsc --noconfirm git cmake make pkgconf clang && \
    rm -rf /var/cache/pacman/pkg/* && \
    rm -rf /root/build

WORKDIR /root

ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
