# Candy

[中文](README.md) | English

A easy-to-deploy and peer-to-peer virtual private network.

## Usage

We provide a network for testing, 172.16.0.0/16, which dynamically assigns addresses from the server side. You can join this network with one command. For more usage, please refer to the [document](https://icandy.one).

```bash
docker run --rm --privileged=true --net=host docker.io/lanthora/candy:latest
```
