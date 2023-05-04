# Candy

A WebSocket and TUN based VPN for Linux.

## Target

At present, mainstream VPN traffic has obvious characteristics and is easily identified and blocked by firewalls. This project tries to solve this problem.

For more details, please refer to [the documentation](https://lanthora.github.io/candy).

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

```txt
Usage: candy [OPTION...]

  -c, --config=PATH          Configuration file path
  -m, --mode=MODE            Select work mode. MODE must choose one of the
                             following values: server, client, mixed. When MODE
                             is server, the websocket service will be started.
                             When MODE is client, a connection will be
                             initiated to the websocket service. At the same
                             time, IP layer data forwarding will be performed
                             through tun. When MODE is mixed, it works as
                             server and client at the same time.
  -p, --password=TEXT        Password for simple authentication
  -t, --tun=IP               Set local virtual IP and subnet mask. IP is
                             address and subnet in CIDR notation. e.g.
                             10.0.0.1/24
  -w, --websocket=URI        Set websocket address and port. when running as a
                             server, You can choose to encrypt traffic with
                             nginx. This service only handles unencrypted data.
                             You can configure ws://127.0.0.1:80 only to
                             monitor local requests. Except for testing needs,
                             it is recommended that the client configure TLS
                             Encryption. e.g. wss://domain:443
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
