# 如何安装

这个项目编译出的命令行版本可执行文件根据参数区分以服务端模式运行还是客户端模式运行,因此安装不区分客户端与服务端.

## Linux

针对 Linux 环境差异,提供多种安装方式.请选择适合自己的方式安装.

### Docker

建议使用 Docker 镜像,已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

```bash
docker run --rm --privileged=true --net=host docker.io/lanthora/candy:latest --help
```

### Arch Linux

使用 [AUR](https://aur.archlinux.org/packages/candy) 或者 [archlinuxcn](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/candy) 仓库

```bash
# AUR
paru candy
# archlinuxcn
pacman -S candy
```

### Gentoo

使用 [GURU](https://github.com/gentoo/guru/tree/master/net-vpn/candy) 仓库

```bash
eselect repository enable guru
emerge --sync guru && emerge -av candy
```

### openSUSE 

使用 [OBS](https://software.opensuse.org/download/package?package=candy&project=home:lanthora:candy) 仓库

```bash
# 以 Tumbleweed 为例,更新仓库缓存时选择信任签名
zypper addrepo https://download.opensuse.org/repositories/home:lanthora:candy/openSUSE_Tumbleweed/home:lanthora:candy.repo
zypper refresh && zypper install candy
```

### Debian/Ubuntu

下载 [DEB](https://github.com/lanthora/candy/releases/latest) 安装包后通过以下命令安装

```bash
apt install --fix-broken ./xxx.deb
```

### 单文件可执行程序

当上述所有方式都不适用时,尝试[单文件可执行程序](https://github.com/lanthora/candy/releases/latest).

该程序由[交叉编译脚本](https://github.com/lanthora/candy/tree/master/scripts/build-standalone.sh)构建.

## macOS

请参考 [Homebrew](https://github.com/lanthora/homebrew-repo) 中提供的方法安装.

## Windows

### 图形用户界面

以本项目作为依赖构建 [Cake](https://github.com/lanthora/cake) 提供[图形用户界面](https://github.com/lanthora/cake/releases/latest).

### 命令行

本项目仅提供[命令行版本](https://github.com/lanthora/candy/releases/latest),用户可以在此基础上自行定制.

## 从源码构建

### 构建本机单文件可执行程序

依赖 `C++20` 的编译器.

```bash
cmake -B build -DCANDY_STATIC=1
cmake --build build
cmake --install build
```

### 交叉编译 Linux 单文件可执行程序

根据实际情况设置以下环境变量,查看[受支持的系统和架构](https://github.com/lanthora/candy/tree/master/scripts/standalone.json).

```bash
# 下载和编译所用目录的绝对路径
export CANDY_WORKSPACE=$HOME/workspace
# 操作系统
export CANDY_OS=linux
# 目标文件的架构
export CANDY_ARCH=x86_64
```

执行构建脚本.构建时将下载编译工具链及依赖库,请确保网络通畅.

```bash
scripts/build-standalone.sh
```

生成的二进制文件为 `$CANDY_WORKSPACE/output/$CANDY_OS-$CANDY_ARCH/candy`.
