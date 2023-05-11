FROM archlinux/archlinux:base-devel

# Change to the fastest mirror site for you
RUN echo 'Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/$repo/os/$arch' > /etc/pacman.d/mirrorlist

RUN pacman -Syu --needed --noconfirm git libconfig openssl spdlog uriparser clang cmake

ARG user=candy
RUN useradd --system --create-home $user && echo "$user ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/$user
USER $user
WORKDIR /home/$user

RUN git clone https://aur.archlinux.org/ixwebsocket.git && cd ixwebsocket && makepkg --install --needed --noconfirm
RUN git clone https://aur.archlinux.org/candy.git && cd candy && makepkg --install --needed --noconfirm

USER root

CMD ["/usr/bin/candy", "-c", "/etc/candy.conf"]
