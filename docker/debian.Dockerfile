FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    cmake \
    autoconf \
    automake \
    libtool \
    git \
    pkg-config \
    time \
    mosquitto \
    mosquitto-clients \
    libmosquitto-dev

# RUN apt-get install -y libssl-dev

RUN apt-get install -y lsb-release wget software-properties-common gnupg \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-22 main" > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y clang-22 lldb-22 lld-22 clangd-22 libc++-22-dev libc++abi-22-dev

RUN ln -sf /usr/lib/llvm-22/bin/clang /usr/bin/clang \
    && ln -sf /usr/lib/llvm-22/bin/clang++ /usr/bin/clang++

ENV CC="clang" \
    CXX="clang++"

WORKDIR /app
