# Candy

[中文](README.md) | English

A easy-to-deploy and peer-to-peer virtual private network.

## Usage

We offer you a test network 172.16.0.0/16, which automatically assigns IP addresses after you connect. You can easily join this network with a simple command.

```bash
docker run --rm --privileged=true --net=host docker.io/lanthora/candy:latest
```

If you want to set up your own virtual private network, it's also easy. For details, please refer to the help document.

```bash
docker run --rm docker.io/lanthora/candy:latest --help
```
