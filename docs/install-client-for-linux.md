# Install Linux Client

**[中文文档](install-client-for-linux.zh-CN.md)**

We provide installation packages in various formats for different Linux distributions. For distributions not yet supported, you can choose container deployment or statically linked executables.
We are committed to supporting Linux systems of all architectures.

## Docker

Images have been uploaded to [Docker Hub](https://hub.docker.com/r/lanthora/candy) and [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

Get the latest image:

```bash
docker pull docker.io/lanthora/candy:latest
```

The container requires administrator privileges to read devices, create virtual network interfaces, and set up routing. It also needs to share the Host network namespace for virtual network interfaces.

Starting with the default configuration file will join the community network. The specified parameter `--rm` means the container will be automatically destroyed when the process ends, and logs will be output to the console, which is helpful for initial debugging.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

Start with a custom configuration file. Please customize the configuration file based on the [default configuration](https://raw.githubusercontent.com/lanthora/candy/refs/heads/master/candy.cfg).

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy --volume /path/to/candy.cfg:/etc/candy.cfg docker.io/lanthora/candy:latest
```

After everything is working properly, start as a daemon process:

```bash
docker run --detach --restart=always --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy --volume /path/to/candy.cfg:/etc/candy.cfg docker.io/lanthora/candy:latest
```

## Arch Linux

Use [AUR](https://aur.archlinux.org/packages/candy) or [archlinuxcn](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/candy) repository

```bash
# AUR
paru candy
# archlinuxcn
pacman -S candy
```

## Gentoo

```bash
emerge --sync gentoo && emerge -av candy
```

## Standalone Executable

When none of the above methods work, try the [standalone executable](https://github.com/lanthora/candy/releases/latest).

This program is built by the [cross-compilation script](https://github.com/lanthora/candy/tree/master/scripts/build-standalone.sh).

If your system uses Systemd for process management, please copy the following files to the specified directories:

```bash
cp candy.service /usr/lib/systemd/system/candy.service
cp candy@.service /usr/lib/systemd/system/candy@.service
cp candy.cfg /etc/candy.cfg
```

Then manage the process according to the process management section below.

To determine if Systemd is being used: check if the output of `ps -p 1 -o comm=` contains "systemd".

## Process Management

Each distribution comes with Service files after installation. It is strongly recommended to use Systemd to manage processes rather than your own scripts.

For users with custom configurations, you can start processes in the following way without modifying the default configuration:

```bash
mkdir /etc/candy.d
# Copy a default configuration and modify it. File name is one.cfg
cp /etc/candy.cfg /etc/candy.d/one.cfg
# Start process with one.cfg as configuration
systemctl start candy@one

# Copy another default configuration and modify it. File name is two.cfg
# Note that the name field in different configuration files cannot be duplicated
cp /etc/candy.cfg /etc/candy.d/two.cfg
# Start process with two.cfg as configuration
systemctl start candy@two
```
