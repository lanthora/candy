# Candy

English | [中文](README_zh.md)

A WebSocket and TUN based VPN for Linux.

This project aims to overcome the problem of mainstream VPN traffic being easily detected and blocked by firewalls.

## Usage

Please ensure that the time difference between the server host and the client host does not exceed 30 seconds, otherwise the connection will fail. The server will not send any feedback if the connection is unsuccessful, to avoid being detected.

You only need one command to join our virtual private network.

```bash
docker run --rm --privileged=true --net=host --device /dev/net/tun --volume /var/lib/candy:/var/lib/candy lanthora/candy
```

If you want to set up your own virtual private network, it's also easy. For details, please refer to the help document.

```bash
docker run --rm lanthora/candy --help
```

We also welcome you to join our [Telegram Group](https://t.me/+xR4K-Asvjz0zMjU1) and share your feedback with us.
