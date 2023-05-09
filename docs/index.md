# Candy

A WebSocket and TUN based VPN for Linux.

## Target

At present, mainstream VPN traffic has obvious characteristics and is easily identified and blocked by firewalls. This project tries to solve this problem.

For more details, refer to the [design document](https://lanthora.github.io/candy/design) and [specification document](https://lanthora.github.io/candy/specification)

## Install

### Arch Linux

This project has been maintained on [AUR](https://aur.archlinux.org/packages/candy), choose your favorite [AUR Helper](https://wiki.archlinux.org/title/AUR_helpers) to install this software.

```bash
yay -S candy
```

### Manual

Manual compilation requires the following dependencies.

- [ixwebsocket](https://github.com/machinezone/IXWebSocket): websocket and http client and server library, with TLS support and very few dependencies
- [libconfig](https://github.com/hyperrealm/libconfig): C/C++ library for processing configuration files
- [spdlog](https://github.com/gabime/spdlog): Fast C++ logging library
- [uriparser](https://github.com/uriparser/uriparser): Strictly RFC 3986 compliant URI parsing and handling library written in C89
- [openssl](https://github.com/openssl/openssl): TLS/SSL and crypto library
- [pkgconf](https://github.com/pkgconf/pkgconf): package compiler and linker metadata toolkit 
- [cmake](https://cmake.org): CMake is an open-source, cross-platform family of tools designed to build, test and package software
- [make](https://www.gnu.org/software/make/): GNU Make is a tool which controls the generation of executables and other non-source files of a program from the program's source files

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make install
```

## Usage

Please ensure that the difference between the client time and the server time is less than 30 seconds.

```bash
candy --help
```

## Stargazers over time

[![Stargazers over time](https://starchart.cc/lanthora/candy.svg)](https://starchart.cc/lanthora/candy)
