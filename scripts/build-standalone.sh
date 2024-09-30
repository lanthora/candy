#!/bin/bash -e

if [ -z $CANDY_WORKSPACE ];then echo "CANDY_WORKSPACE is not exist";exit 1;fi

if [[ -z $TARGET || -z $TARGET_OPENSSL ]];then
    if [ -z $CANDY_ARCH ];then echo "CANDY_ARCH is not exist";exit 1;fi
    if [ -z $CANDY_OS ];then echo "CANDY_OS is not exist";exit 1;fi
    echo "CANDY_ARCH: $CANDY_ARCH"
    echo "CANDY_OS: $CANDY_OS"
    if [[ "$CANDY_OS" == "linux" ]]; then
        if [[ "$CANDY_ARCH" == "aarch64" ]]; then TARGET="aarch64-unknown-linux-musl";TARGET_OPENSSL="linux-aarch64";UPX=1
        elif [[ "$CANDY_ARCH" == "arm" ]]; then TARGET="arm-unknown-linux-musleabi";TARGET_OPENSSL="linux-armv4";UPX=1
        elif [[ "$CANDY_ARCH" == "armhf" ]]; then TARGET="arm-unknown-linux-musleabihf";TARGET_OPENSSL="linux-armv4";UPX=1
        elif [[ "$CANDY_ARCH" == "loongarch64" ]]; then TARGET="loongarch64-unknown-linux-musl";TARGET_OPENSSL="linux64-loongarch64";UPX=0
        elif [[ "$CANDY_ARCH" == "s390x" ]]; then TARGET="s390x-ibm-linux-musl";TARGET_OPENSSL="linux64-s390x";UPX=0
        elif [[ "$CANDY_ARCH" == "mips" ]]; then TARGET="mips-unknown-linux-musl";TARGET_OPENSSL="linux-mips32";UPX=1
        elif [[ "$CANDY_ARCH" == "mipssf" ]]; then TARGET="mips-unknown-linux-muslsf";TARGET_OPENSSL="linux-mips32";UPX=1
        elif [[ "$CANDY_ARCH" == "mipsel" ]]; then TARGET="mipsel-unknown-linux-musl";TARGET_OPENSSL="linux-mips32";UPX=1
        elif [[ "$CANDY_ARCH" == "mipselsf" ]]; then TARGET="mipsel-unknown-linux-muslsf";TARGET_OPENSSL="linux-mips32";UPX=1
        elif [[ "$CANDY_ARCH" == "mips64" ]]; then TARGET="mips64-unknown-linux-musl";TARGET_OPENSSL="linux64-mips64";UPX=0
        elif [[ "$CANDY_ARCH" == "mips64el" ]]; then TARGET="mips64el-unknown-linux-musl";TARGET_OPENSSL="linux64-mips64";UPX=0
        elif [[ "$CANDY_ARCH" == "riscv32" ]]; then TARGET="riscv32-unknown-linux-musl";TARGET_OPENSSL="linux32-riscv32";UPX=0
        elif [[ "$CANDY_ARCH" == "riscv64" ]]; then TARGET="riscv64-unknown-linux-musl";TARGET_OPENSSL="linux64-riscv64";UPX=0
        elif [[ "$CANDY_ARCH" == "x86_64" ]]; then TARGET="x86_64-multilib-linux-musl";TARGET_OPENSSL="linux-x86_64";UPX=1
        else echo "Unknown CANDY_ARCH: $CANDY_ARCH";exit 1;fi
    elif [[ "$CANDY_OS" == "macos" ]]; then
        echo "macos is not supported yet";exit 1
    elif [[ "$CANDY_OS" == "windows" ]]; then
        echo "windows is not supported yet";exit 1
    else echo "Unknown CANDY_OS: $CANDY_OS";exit 1;fi
fi

echo "CANDY_WORKSPACE: $CANDY_WORKSPACE"
echo "TARGET: $TARGET"
echo "TARGET_OPENSSL: $TARGET_OPENSSL"

TOOLCHAINS="$CANDY_WORKSPACE/toolchains"
COMPILER_ROOT="$TOOLCHAINS/$TARGET"

if [ ! -d "$COMPILER_ROOT" ]; then
    mkdir -p $TOOLCHAINS
    RESPONSE=$(curl -s https://api.github.com/repos/musl-cross/musl-cross/releases/latest)
    VERSION=$(echo "$RESPONSE" | grep 'tag_name' | cut -d'"' -f4)
    wget -q -c https://github.com/musl-cross/musl-cross/releases/download/$VERSION/$TARGET.tgz -P $TOOLCHAINS
    tar xf $COMPILER_ROOT.tgz -C $TOOLCHAINS
fi

export CC="$COMPILER_ROOT/bin/$TARGET-gcc"
export CXX="$COMPILER_ROOT/bin/$TARGET-g++"
export AR="$COMPILER_ROOT/bin/$TARGET-ar"
export LD="$COMPILER_ROOT/bin/$TARGET-ld"
export RANLIB="$COMPILER_ROOT/bin/$TARGET-ranlib"
export STRIP="$COMPILER_ROOT/bin/$TARGET-strip"
export CFLAGS="-I $COMPILER_ROOT/$TARGET/include -L $COMPILER_ROOT/$TARGET/lib"
export LDFLAGS="-static $CFLAGS"

if [[ $CANDY_OS && $CANDY_ARCH ]];then
    BUILD_DIR="$CANDY_WORKSPACE/build/$CANDY_OS-$CANDY_ARCH"
    OUTPUT_DIR="$CANDY_WORKSPACE/output/$CANDY_OS-$CANDY_ARCH"
else
    BUILD_DIR="$CANDY_WORKSPACE/build/$TARGET"
    OUTPUT_DIR="$CANDY_WORKSPACE/output/$TARGET"
fi

if which ninja >/dev/null 2>&1;then GENERATOR="Ninja";else GENERATOR="Unix Makefiles";fi
SOURCE_DIR="$(dirname $(readlink -f "$0"))/../"
cmake -G "$GENERATOR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCANDY_STATIC=1 -DTARGET_OPENSSL=$TARGET_OPENSSL $SOURCE_DIR
cmake --build $BUILD_DIR --parallel $(nproc)
mkdir -p $OUTPUT_DIR && cp $BUILD_DIR/src/main/candy $OUTPUT_DIR/candy

if [[ $CANDY_STRIP && $CANDY_STRIP -eq 1 ]];then
    $STRIP $OUTPUT_DIR/candy
fi

if [[ $CANDY_UPX && $CANDY_UPX -eq 1 && $UPX -eq 1 ]];then
    upx --lzma --best -q $OUTPUT_DIR/candy
fi

if [[ $CANDY_TGZ && $CANDY_TGZ -eq 1 && $CANDY_OS && $CANDY_ARCH ]];then
    cp $SOURCE_DIR/{candy.cfg,candy.service,candy@.service,candy.initd} $OUTPUT_DIR
    tar zcvf $CANDY_WORKSPACE/output/candy-$CANDY_OS-$CANDY_ARCH.tar.gz -C $OUTPUT_DIR .
fi
