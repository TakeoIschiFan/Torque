#include "bencode.h"
#include "network.h"
#include "torrent.h"
#include <stdbool.h>
#include <stdlib.h>

void tests(void) {
    bencode_tests();
    torrent_tests();
    network_tests();
}

int main(void) {
#ifdef TESTS
    tests();
    exit(1);
#endif
    // http_stuff();
    // socket_stuff();
    return 0;
}
