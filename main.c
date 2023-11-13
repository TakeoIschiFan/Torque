#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "bencode.h"
#include "network.h"

void torrent_stuff(void){
    FILE* torrent_file = fopen("test.torrent", "rb");

    //get file size
    fseek(torrent_file, 0, SEEK_END);
    long size = ftell(torrent_file);
    rewind(torrent_file);

    printf("found .torrent file of length %ld bytes\n", size);

    //read the entire file into memory
    char* contents = malloc(size);
    fread(contents, size, 1, torrent_file);

    bencode_context context = {
        .raw = contents,
        .length = size,
        .cursor = contents,
        .root = 0
    };

    bencode_item* item = decode_bencode_item(&context);
    bencode_print(item);

}

void socket_stuff(void){
    connection_context context = {
        .adress = "127.0.0.1",
        .port = 6969
    };
    bool succes = connection_init(&context);
    if (!succes){
        exit(1);
    }
    printf("socket initialized succesfully.\n");

    succes = connection_connect(&context);
    if (!succes){
        exit(1);
    }
    printf("socket connected succesfully.\n");

    const char* message = "hello server\n";

    connection_send_string(&context, message);
    char* str = connection_receive_string(&context);
    printf("received: %s\n", str);
    free(str);
}

void http_stuff(void){
    http1_get("google.com", "", 0, 0);
}

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