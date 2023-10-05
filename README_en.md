# Candy

[中文](README.md) | English

A easy-to-deploy, firewall-penetrating, and peer-to-peer virtual private network.

## Usage

You only need one command to join our virtual private network.

```bash
docker run --rm --privileged=true --net=host --device /dev/net/tun docker.io/lanthora/candy:latest
```

If you want to set up your own virtual private network, it's also easy. For details, please refer to the help document.

```bash
docker run --rm docker.io/lanthora/candy:latest --help
```
