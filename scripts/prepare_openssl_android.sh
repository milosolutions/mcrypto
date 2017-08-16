#!/bin/bash

# include common part
. `dirname $0`/prepare_openssl_common.sh

GIT_TAG="OpenSSL_1_0_2j"

check_openssl_sources

cd $OPENSSL_SRC_DIR
git checkout $GIT_TAG

source $SCRIPT_DIR/setenv-android.sh

./Configure --prefix=$SCRIPT_DIR/OpenSSL/android/armeabi-v7a android-armv7 shared
make clean
make
make install
