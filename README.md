# Trick Or Treat

A WebSocket and TUN based VPN for Linux.

## Target

At present, the traffic characteristics of mainstream VPNs are obvious, which makes it easy for firewalls to identify and block them. [This project](docs/design.md) tries to solve this problem.

## Install

### Arch Linux

I maintain this project on AUR, choose your favorite AUR Helper to install.

```bash
yay -S trick-or-treat
# or
yay -S trick-or-treat-git
```

### Manual

Manual compilation requires the following dependencies.

- ixwebsocket
- libconfig
- openssl
- spdlog
- uriparser
- cmake
- make
- pkgconf

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make install
```

## Usage

```bash
candy --help
```
