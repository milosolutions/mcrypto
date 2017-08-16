#!/bin/bash

JOBS=`getconf _NPROCESSORS_ONLN`

SCRIPT_DIR=$PWD/`dirname $0`
SRC_DIR=$SCRIPT_DIR/src

mkdir -p $SRC_DIR
cd $SRC_DIR

OPENSSL_SRC_DIR=$SRC_DIR/openssl

function check_openssl_sources() {
  if [ -d "$OPENSSL_SRC_DIR" ]; then
    cd $OPENSSL_SRC_DIR
    git status > /dev/null
    TEST_RESULT=$?

    if [ $TEST_RESULT -eq 128 ]; then
      echo "$OPENSSL_SRC_DIR exists but it's not openssl repo clone."
      cd ..

      echo "Preparing fresh OpenSSL clone"
      rm -rf openssl > /dev/null
      git clone https://github.com/openssl/openssl.git
    else
      echo "Pulling recent changes"
      git pull
    fi
  else
    git clone https://github.com/openssl/openssl.git
  fi
}
