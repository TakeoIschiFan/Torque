set -xe

DEBUG=true

CC="clang"

if [ "$DEBUG" = true ]; then
    CFLAGS="-g -DTESTS -Wall -Wextra -pedantic"
else
    CFLAGS=""
fi


LIBS=""
SRC="src/main.c src/bencode.c src/network.c src/torrent.c"

$CC $CFLAGS -o torque $SRC $LIBS

if [ "$DEBUG" = true ]; then
    ./torque
fi