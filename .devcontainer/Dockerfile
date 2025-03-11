FROM ubuntu:24.04

# 安装必要的工具
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    ninja-build \
    g++ \
    clangd \
    pkg-config \
    libssl-dev \
    libspdlog-dev \
    libpoco-dev

# 设置工作目录
WORKDIR /workspace
