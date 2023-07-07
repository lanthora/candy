# Candy

A WebSocket and TUN based VPN for Linux.

This project aims to overcome the problem of mainstream VPN traffic being easily detected and blocked by firewalls.

## Usage

Please ensure that the server and the client are synchronized within 30 seconds, otherwise the connection will fail. The server will not send any feedback if the connection is unsuccessful, to avoid being detected.

You will be able to join our virtual private network with a single command.

```bash
docker run --rm --privileged=true --net=host --device /dev/net/tun --volume /var/lib/candy:/var/lib/candy lanthora/candy
```

Setting up your own virtual private network is easy. For instructions, please see the help document.

```bash
docker run --rm lanthora/candy --help
```

We also invite you to join our [Telegram Group](https://t.me/+xR4K-Asvjz0zMjU1) and share your feedback with us.
