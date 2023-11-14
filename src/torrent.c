#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "torrent.h"
#include "bencode.h"
#include "sha1.h"

void parse_torrent_file(const char* file_path){

    FILE* torrent_file = fopen(file_path, "rb");
    if (torrent_file == NULL){
        fprintf(stderr, "Error, Could not open torrent file at %s", file_path);
        exit(1);
    }

    //get file size
    fseek(torrent_file, 0, SEEK_END);
    long size = ftell(torrent_file);
    rewind(torrent_file);

    //read the entire file into memory
    char* contents = malloc(size);
    fread(contents, size, 1, torrent_file);

    bencode_context* context = bencode_context_get(contents, size);
    bencode_item* item = decode_bencode_item(context);

    // find general stuff
    bencode_item* announce = bencode_search(item, "announce");
    if (announce == NULL){
        fprintf(stderr, "Error: could not find *announce* field in .torrent file, it might be wrongly formatted.");
        exit(1);
    }
    printf("found announce url: %s\n", announce->string_data);

    // find info dictionary
    bencode_item* info = bencode_search(item, "info");
    if (info == NULL){
        fprintf(stderr, "Error: could not find *info* field in .torrent file, it might be wrongly formatted.");
        exit(1);
    }

    // check for multi file torrents. they have a "files" field in info instead of a "name" field.
    bencode_item* files = bencode_search(info, "files");
     if (!(files == NULL)){
        fprintf(stderr, "Error: detected multifiles torrent file, unsupported for now.");
        //exit(1);
    }

    // check for private tracker
    bencode_item* private = bencode_search(info, "private");
     if (!(private == NULL)){
        if (private->int_data == 1){
            fprintf(stderr, "Error: Torrent file requested private tracker, unsupported for now.");
            exit(1);
        }
    }

    //get raw info dictionary
    const unsigned char* raw_info = malloc(context->_info_length);
    memcpy((void*) raw_info, context->_info_start_ptr, context->_info_length);

    // sha1 encode that raw info dict
    SHA1_CTX sha;
    unsigned char results[20];

    SHA1Init(&sha);
    SHA1Update(&sha, raw_info, context->_info_length);
    SHA1Final(results, &sha);

    /*
    printf("0x");
    for (int n = 0; n < 20; n++)
            printf("%02x", results[n]);
    putchar('\n');
    */




    //bencode_print(item);
    bencode_free(item);
    free(contents);
    free(context);
}

bool torrent_tests(void){
    parse_torrent_file("test2.torrent");
    return true;
}

