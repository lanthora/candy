#!/bin/bash -e
if [ -z $WORKSPACE ];then
    echo "WORKSPACE is not exist"
    exit 1
fi

if [ -z $TARGET ];then
    echo "TARGET is not exist"
    exit 1
fi

if [[ "$TARGET" == "aarch64" ]]; then
    BUILD_TARGET="aarch64-linux-musl"
    OPENSSL_TARGET="linux-aarch64"
elif [[ "$TARGET" == "armv7l-eabihf" ]]; then
    BUILD_TARGET="armv7l-linux-musleabihf"
    OPENSSL_TARGET="linux-armv4"
elif [[ "$TARGET" == "armv7m-eabi" ]]; then
    BUILD_TARGET="armv7m-linux-musleabi"
    OPENSSL_TARGET="linux-armv4"
elif [[ "$TARGET" == "arm-eabi" ]]; then
    BUILD_TARGET="arm-linux-musleabi"
    OPENSSL_TARGET="linux-armv4"
elif [[ "$TARGET" == "arm-eabihf" ]]; then
    BUILD_TARGET="arm-linux-musleabihf"
    OPENSSL_TARGET="linux-armv4"
elif [[ "$TARGET" == "mips" ]]; then
    BUILD_TARGET="mips-linux-muslsf"
    OPENSSL_TARGET="linux-mips32"
elif [[ "$TARGET" == "mipsel" ]]; then
    BUILD_TARGET="mipsel-linux-muslsf"
    OPENSSL_TARGET="linux-mips32"
elif [[ "$TARGET" == "i686" ]]; then
    BUILD_TARGET="i686-linux-musl"
    OPENSSL_TARGET="linux-generic32"
elif [[ "$TARGET" == "x86_64" ]]; then
    BUILD_TARGET="x86_64-linux-musl"
    OPENSSL_TARGET="linux-x86_64"
else
    echo "Unknown TARGET: $TARGET"
    exit 1
fi

MUSL_DIR=$WORKSPACE/musl-gcc
COMPILER_ROOT="$MUSL_DIR/$BUILD_TARGET-cross"

if [ ! -d "$COMPILER_ROOT" ]; then
    mkdir -p $WORKSPACE/musl-gcc
    wget -q -c https://musl.cc/$BUILD_TARGET-cross.tgz -P $MUSL_DIR
    tar zxf $COMPILER_ROOT.tgz -C $MUSL_DIR
fi

export CC="$COMPILER_ROOT/bin/$BUILD_TARGET-gcc"
export CXX="$COMPILER_ROOT/bin/$BUILD_TARGET-g++"
export AR="$COMPILER_ROOT/bin/$BUILD_TARGET-ar"
export LD="$COMPILER_ROOT/bin/$BUILD_TARGET-ld"
export RANLIB="$COMPILER_ROOT/bin/$BUILD_TARGET-ranlib"
export STRIP="$COMPILER_ROOT/bin/$BUILD_TARGET-strip"
export C_INCLUDE_PATH="$COMPILER_ROOT/$BUILD_TARGET/include"
export LD_LIBRARY_PATH="$COMPILER_ROOT/$BUILD_TARGET/lib"
export CFLAGS="-I$C_INCLUDE_PATH -L$LD_LIBRARY_PATH"
export LDFLAGS="-static $CFLAGS"

SOURCE_DIR="$(dirname $(readlink -f "$0"))/../"
BUILD_DIR="$WORKSPACE/build/$TARGET"
OUTPUT_DIR="$WORKSPACE/output/$TARGET"
cmake -B $BUILD_DIR -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$OUTPUT_DIR -DCMAKE_INSTALL_PREFIX="$OUTPUT_DIR" -DCANDY_STATIC=1 -DOPENSSL_TARGET=$OPENSSL_TARGET $SOURCE_DIR
cmake --build $BUILD_DIR

if [ $ENABLE_STRIP ];then
    $STRIP $OUTPUT_DIR/candy
fi
