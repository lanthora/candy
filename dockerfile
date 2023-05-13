FROM archlinux/archlinux:base-devel

ARG MIRROR

RUN if [[ $MIRROR ]]; then echo $MIRROR > /etc/pacman.d/mirrorlist ; fi

RUN pacman -Syu --needed --noconfirm git libconfig openssl spdlog uriparser clang cmake

ARG user=candy
RUN useradd --system --create-home $user && echo "$user ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/$user
USER $user
WORKDIR /home/$user

RUN git clone https://aur.archlinux.org/ixwebsocket.git && cd ixwebsocket && makepkg --install --needed --noconfirm
RUN git clone https://aur.archlinux.org/candy.git && cd candy && makepkg --install --needed --noconfirm

USER root

CMD ["/usr/bin/candy", "-c", "/etc/candy.conf"]
