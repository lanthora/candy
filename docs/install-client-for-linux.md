# 安装 Linux 客户端

我们针对不同 Linux 发行版提供了多种格式的安装包.对于暂未支持的发行版,可以选择容器部署或者静态链接的可执行文件.
我们致力于支持所有架构的 Linux 系统.

## Docker

镜像已上传 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

获取最新镜像

```bash
docker pull docker.io/lanthora/candy:latest
```

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

以默认配置文件启动将加入社区网络.指定的参数为 `--rm` 当进程结束时会自动销毁容器,且日志会在控制台输出,这有利于初次运行调试.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

以自定义配置文件启动.请在[默认配置](https://raw.githubusercontent.com/lanthora/candy/refs/heads/master/candy.cfg)基础上自定义配置文件.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy --volume /path/to/candy.cfg:/etc/candy.cfg docker.io/lanthora/candy:latest
```

一切正常后,以守护进程的形式启动.

```bash
docker run --detach --restart=always --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy --volume /path/to/candy.cfg:/etc/candy.cfg docker.io/lanthora/candy:latest
```

## Arch Linux

使用 [AUR](https://aur.archlinux.org/packages/candy) 或者 [archlinuxcn](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/candy) 仓库

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

## 单文件可执行程序

当上述所有方式都不适用时,尝试[单文件可执行程序](https://github.com/lanthora/candy/releases/latest).

该程序由[交叉编译脚本](https://github.com/lanthora/candy/tree/master/scripts/build-standalone.sh)构建.

如果你的系统在使用 Systemd 管理进程.请复制以下文件到指定目录.

```bash
cp candy.service /usr/lib/systemd/system/candy.service
cp candy@.service /usr/lib/systemd/system/candy@.service
cp candy.cfg /etc/candy.cfg
```

然后按照后续进程管理的方式管理进程.

判断 Systemd 的方法: 检查 `ps -p 1 -o comm=` 输出的内容里是否为 systemd 

## 进程管理

各发行版安装后自带 Service 文件,强烈建议使用 Systemd 管理进程,不要使用自己编写的脚本.

对于自定义配置的用户,可以通过以下方式启动进程,不要修改默认配置.

```bash
mkdir /etc/candy.d
# 复制一份默认配置,并修改.文件名为 one.cfg
cp /etc/candy.cfg /etc/candy.d/one.cfg
# 以 one.cfg 为配置启动进程
systemctl start candy@one

# 复制一份默认配置,并修改.文件名为 two.cfg
# 需要注意不同配置文件中的 name 字段不能重复
cp /etc/candy.cfg /etc/candy.d/two.cfg
# 以 two.cfg 为配置启动进程
systemctl start candy@two
```
