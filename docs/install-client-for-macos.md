# 安装 macOS 客户端

macOS 客户端通过 [Homebrew](https://brew.sh) 安装并提供服务.

## 安装 Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## 添加第三方仓库

```bash
brew tap lanthora/repo
```

## 安装 Candy

```bash
brew install candy
```

## 修改配置

对于 M 系列处理器,配置文件在 `/opt/homebrew/etc/candy.cfg`, Intel 系列处理器,配置文件在 `/usr/local/etc/candy.cfg`

通过以下命令进行测试:

```bash
sudo candy -c /path/to/candy.cfg
```

## 启动服务

测试成功后以服务的形式运行.

```bash
sudo brew services start lanthora/repo/candy
```
