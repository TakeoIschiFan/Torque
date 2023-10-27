#include <stdio.h>
#include <stdlib.h>
#include "bencode.h"

int main(void){
    printf("Hello, mom\n");

    FILE* torrent_file = fopen("test.torrent", "rb");

    //get file size
    fseek(torrent_file, 0, SEEK_END);
    long size = ftell(torrent_file);
    rewind(torrent_file);

    printf("found .torrent file of length %ld bytes\n", size);

    char* contents = malloc(size);
    fread(contents, size, 1, torrent_file);


    bencode_context context = {
        .raw = contents,
        .length = size,
        .cursor = contents,
        .root = 0
    };

    bencode_item* item = decode_bencode_item(&context);
    print_bencode(item);

    return 0;
}