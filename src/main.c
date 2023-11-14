#include <stdbool.h>
#include "bencode.h"
#include "torrent.h"

void tests(void){
    bool out = bencode_tests();
    out = torrent_tests();
}

int main(void){
#ifdef TESTS
    tests();
#endif
    //http_stuff();
    //socket_stuff();
    return 0;
}