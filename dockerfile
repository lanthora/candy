FROM archlinux

ARG MIRROR

WORKDIR /tmp/build
COPY . .

RUN if [[ $MIRROR ]]; then printf "Server = %s/\$repo/os/\$arch\n" $MIRROR > /etc/pacman.d/mirrorlist ; fi
RUN pacman -Syyu --noconfirm && \
    pacman -S --needed --noconfirm git cmake make pkgconf clang spdlog openssl libconfig uriparser && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j install && \
    pacman -Rsc --noconfirm git cmake make pkgconf clang && \
    rm -rf /var/cache/pacman/pkg/*

ENTRYPOINT ["/usr/local/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
