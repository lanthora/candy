# Install macOS Client

**[中文文档](install-client-for-macos.zh-CN.md)**

The macOS client is installed and serviced via [Homebrew](https://brew.sh).

## Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## Add Third-Party Repository

```bash
brew tap lanthora/repo
```

## Install Candy

```bash
brew install candy
```

## Modify Configuration

For M-series processors, the configuration file is at `/opt/homebrew/etc/candy.cfg`. For Intel series processors, the configuration file is at `/usr/local/etc/candy.cfg`.

Test with the following command:

```bash
sudo candy -c /path/to/candy.cfg
```

## Start Service

After successful testing, run as a service:

```bash
sudo brew services start lanthora/repo/candy
```
