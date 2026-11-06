#!/bin/sh

# in C:\msys64\msys2.ini: MSYS2_PATH_TYPE=inherit
# pacman -S vim make zip

# Build xca on Windows 
# OpenSSL 4.1 from source, the tarball checked against its SHA-256 (BTD-252)
do_openssl() {
  major="${OSSL#openssl-}"
  test -f "$INSTALL_DIR/bin/libcrypto-${major%%.*}-x64.dll" && return
  test -f "$OSSL".tar.gz || curl -fL -O https://github.com/openssl/openssl/releases/download/"$OSSL"/"$OSSL".tar.gz
  echo "$OSSL_SHA256  $OSSL.tar.gz" | sha256sum -c - || exit 1
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  cd "$OSSL"
  ./Configure mingw64 --prefix=$INSTALL_DIR --libdir=lib no-module
  make -j4
  make install
}

OSSL="openssl-4.1.0"
OSSL_SHA256="50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
BUILDDIR="$TOP_DIR/w64-release"
INSTALL_DIR="$TOP_DIR/OpenSSL"
JOBS=7

cd $TOP_DIR
do_openssl

cd $TOP_DIR
cmake -B "$BUILDDIR" -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="$INSTALL_DIR" $XCA_DIR
cmake --build "$BUILDDIR" -j$JOBS
cmake --build "$BUILDDIR" -t install
cd "$BUILDDIR" && cpack
