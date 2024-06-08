#!/bin/bash -e

if [ -z $CANDY_WORKSPACE ];then echo "CANDY_WORKSPACE is not exist";exit 1;fi

if [[ -z $TARGET || -z $TARGET_OPENSSL ]];then
    if [ -z $CANDY_ARCH ];then echo "CANDY_ARCH is not exist";exit 1;fi
    if [ -z $CANDY_OS ];then echo "CANDY_OS is not exist";exit 1;fi
    echo "CANDY_ARCH: $CANDY_ARCH"
    echo "CANDY_OS: $CANDY_OS"
    if [[ "$CANDY_OS" == "linux" ]]; then
        if [[ "$CANDY_ARCH" == "aarch64" ]]; then TARGET="aarch64-linux-musl";TARGET_OPENSSL="linux-aarch64"
        elif [[ "$CANDY_ARCH" == "arm" ]]; then TARGET="arm-linux-musleabi";TARGET_OPENSSL="linux-armv4"
        elif [[ "$CANDY_ARCH" == "mips" ]]; then TARGET="mips-linux-musl";TARGET_OPENSSL="linux-mips32"
        elif [[ "$CANDY_ARCH" == "mipsel" ]]; then TARGET="mipsel-linux-musl";TARGET_OPENSSL="linux-mips32"
        elif [[ "$CANDY_ARCH" == "x86_64" ]]; then TARGET="x86_64-linux-musl";TARGET_OPENSSL="linux-x86_64"
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

MUSL_DIR="$CANDY_WORKSPACE/musl-gcc"
COMPILER_ROOT="$MUSL_DIR/$TARGET-cross"

if [ ! -d "$COMPILER_ROOT" ]; then
    mkdir -p $CANDY_WORKSPACE/musl-gcc
    echo "Cross compiler download started"
    wget -q -c https://musl.cc/$TARGET-cross.tgz -P $MUSL_DIR
    echo "Cross compiler download completed"
    tar zxf $COMPILER_ROOT.tgz -C $MUSL_DIR
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
cmake -G "$GENERATOR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCANDY_STATIC=1 -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$OUTPUT_DIR -DTARGET_OPENSSL=$TARGET_OPENSSL $SOURCE_DIR
cmake --build $BUILD_DIR --parallel $(nproc)

if [ $CANDY_STRIP ];then
    $STRIP $OUTPUT_DIR/candy
fi
