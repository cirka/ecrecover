#!/bin/sh
cd c_src
if test ! -d secp256k1; then git clone https://github.com/bitcoin-core/secp256k1.git ; fi
cd secp256k1
./autogen.sh
./configure --enable-module-recovery --disable-tests --disable-benchmark
make
cd ..
gcc -Isecp256k1/include -o ecrecover_server ecrecover_server.c secp256k1/.libs/libsecp256k1.a
mv ecrecover_server ../priv

