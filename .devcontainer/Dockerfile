FROM rust:latest

# 更新并安装常用工具
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    cmake \
    llvm \
    nasm \
    libclang-dev \
    libssl-dev



# 清理缓存以减少镜像大小
RUN apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspace
