FROM archlinux:base-devel

ARG MIRROR

RUN if [[ $MIRROR ]]; then printf "Server = %s/\$repo/os/\$arch\n" $MIRROR > /etc/pacman.d/mirrorlist ; fi

RUN pacman -Syu --needed --noconfirm git

ARG user=candy
RUN useradd --system --create-home $user && echo "$user ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/$user
USER $user
WORKDIR /home/$user

RUN git clone https://aur.archlinux.org/candy.git && cd candy && makepkg --syncdeps --rmdeps --install --needed --noconfirm

USER root
ENTRYPOINT ["/usr/bin/candy"]
CMD ["-c", "/etc/candy.conf"]
