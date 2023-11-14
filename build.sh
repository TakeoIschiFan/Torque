set -xe

DEBUG=true

CC="clang"

if [ "$DEBUG" = true ]; then
    CFLAGS="-g -DTESTS -Wall -Wextra -pedantic"
else
    CFLAGS=""
fi

SRC="src/main.c src/bencode.c src/network.c src/torrent.c src/sha1.c"

$CC $CFLAGS -o torque $SRC

if [ "$DEBUG" = true ]; then
    ./torque
fi