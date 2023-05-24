# Candy

A WebSocket and TUN based VPN for Linux.

## Target

At present, mainstream VPN traffic has obvious characteristics and is easily identified and blocked by firewalls. This project tries to solve this problem.

For more details, refer to the [design document](https://lanthora.github.io/candy/design) and [specification document](https://lanthora.github.io/candy/specification). You are also welcome to join our [discussion group](https://t.me/CandyVPNGroup).

## Install

### Docker

```bash
docker pull lanthora/candy
docker run --rm lanthora/candy --help
docker run --rm --device /dev/net/tun --privileged --net=host lanthora/candy -m client -w wss://zone.icandy.one/default -t 172.16.1.1/16 -p default -n docker
```

### Arch Linux

This project has been maintained on [AUR](https://aur.archlinux.org/packages/candy), choose your favorite [AUR Helper](https://wiki.archlinux.org/title/AUR_helpers) to install this software.

```bash
yay -S candy
```

### Build From Source

Dependencies of this project:

- [ixwebsocket](https://github.com/machinezone/IXWebSocket): websocket and http client and server library, with TLS support and very few dependencies
- [libconfig](https://github.com/hyperrealm/libconfig): C/C++ library for processing configuration files
- [spdlog](https://github.com/gabime/spdlog): Fast C++ logging library
- [uriparser](https://github.com/uriparser/uriparser): Strictly RFC 3986 compliant URI parsing and handling library written in C89
- [openssl](https://github.com/openssl/openssl): TLS/SSL and crypto library
- [pkgconf](https://github.com/pkgconf/pkgconf): package compiler and linker metadata toolkit 
- [cmake](https://cmake.org): CMake is an open-source, cross-platform family of tools designed to build, test and package software
- [make](https://www.gnu.org/software/make/): GNU Make is a tool which controls the generation of executables and other non-source files of a program from the program's source files

Get the [source code](https://github.com/lanthora/candy) in the way you like, and enter the project root directory. Then,

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make install
```

## Usage

```bash
candy --help
```

You can use command line arguments directly, or specify a configuration file, or use systemd service.

Please make sure that the difference between the client time and the server time is less than 30 seconds, otherwise the authentication will fail. In order to avoid being detected, no error message will be returned.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=lanthora/candy&type=Date)](https://star-history.com/#lanthora/candy&Date)
