#include "bencode.h"
#include "torrent.h"
#include <stdbool.h>

void tests(void) {
    bencode_tests();
    torrent_tests();
}

int main(void) {
#ifdef TESTS
    tests();
#endif
    // http_stuff();
    // socket_stuff();
    return 0;
}
