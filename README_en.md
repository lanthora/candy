# Candy

[中文](README.md) | English

A WebSocket and TUN based VPN for Linux.

This project aims to overcome the problem of mainstream VPN traffic being easily detected and blocked by firewalls.

## Usage

You only need one command to join our virtual private network.

```bash
podman run --rm --privileged=true --net=host --device /dev/net/tun docker.io/lanthora/candy:latest
```

If you want to set up your own virtual private network, it's also easy. For details, please refer to the help document.

```bash
podman run --rm docker.io/lanthora/candy:latest --help
```

We also welcome you to join our [Telegram Group](https://t.me/+xR4K-Asvjz0zMjU1) and share your feedback with us.
