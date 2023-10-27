set -xe

# C compiler
CC="clang"

# Flags for the C compiler.
CFLAGS="-Wall -Wextra"

LIBS=""
SRC="main.c"

$CC $CFLAGS -o torque $SRC $LIBS