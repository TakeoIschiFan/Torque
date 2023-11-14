#include <stdbool.h>
#include "bencode.h"

void tests(){
    bool out = bencode_tests();
}

int main(void){
#ifdef TESTS
    tests();
#endif
    //http_stuff();
    //socket_stuff();
    return 0;
}