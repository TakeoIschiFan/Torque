set -xe

DEBUG=true

CC="clang"

if [ "$DEBUG" = true ]; then
    CFLAGS="-g -DTESTS -Wall -Wextra -pedantic"
else
    CFLAGS=""
fi


LIBS=""
SRC="main.c bencode.c network.c"

$CC $CFLAGS -o torque $SRC $LIBS

if [ "$DEBUG" = true ]; then
    ./torque
fi