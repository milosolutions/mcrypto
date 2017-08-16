#!/bin/bash

# include common part
. `dirname $0`/prepare_openssl_common.sh

GIT_TAG="OpenSSL_1_0_2j"
LINUX_ARCH=`uname -m`

check_openssl_sources

cd $OPENSSL_SRC_DIR
git checkout $GIT_TAG

./Configure --prefix=$SCRIPT_DIR/OpenSSL/linux/$LINUX_ARCH linux-$LINUX_ARCH
make clean
make -j$JOBS
make install
