# Get OpenSSL source
wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
tar -xf openssl-1.1.1w.tar.gz
cd openssl-1.1.1w

# Set environment for musl
export CC=musl-gcc
export CFLAGS="-static"
export OPENSSL_DIR=$(pwd)/opt/openssl-musnl

./Configure linux-x86_64 no-shared no-dso --prefix=$OPENSSL_DIR
make -j$(nproc)


