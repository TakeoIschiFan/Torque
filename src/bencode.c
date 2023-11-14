#include "bencode.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bencode_context* bencode_context_get(const unsigned char* buffer, const unsigned int size){
    bencode_context* context = malloc(sizeof(bencode_context));

    context->raw = buffer;
    context->cursor = (unsigned char*) buffer;
    context->length = size;
    context->_info_start_idx = NULL;
    context->_info_length = 0;

    return context;
}
void bencode_context_free();

void bencode_print(bencode_item* src){
    switch (src->type) {
        case BENCODE_INT:
            printf("%d\n", src->int_data);
            break;
        case BENCODE_STRING:
            printf("%s\n", src->string_data);
            break;
        case BENCODE_LIST:{
            bencode_list* list = (bencode_list*)(src->list_data);
            for (int i = 0; i < list->size; i++){
                    printf("\t item %d\n", i);
                    bencode_print(list->data[i]);
            }
        }
        break;
        case BENCODE_DICT: {
            bencode_dict* dict = (bencode_dict*)(src->list_data);
            for (int i = 0; i < dict->size; i++){
                printf("\t%s:", dict->keys[i]);
                bencode_print(dict->values[i]);
            }
        }
        break;
    }
}

bencode_item* bencode_search(bencode_item* root, const char* key_name){
    if (!(root->type == BENCODE_DICT)){
        return NULL;
    }

    bencode_dict* dict_data = (bencode_dict*) root->dict_data;

    for (int i = 0; i < dict_data->size; i++){
        char* key = dict_data->keys[i];
        bencode_item* item = dict_data->values[i];
        printf("searching for key %s, found %s\n", key_name, key);
        if (!strcmp(key, key_name)){
            return item;
        }

        bencode_item* result = bencode_search(item, key_name);
        if (result != NULL){
            return result;
        }
    }
    return NULL;
}
void bencode_free(bencode_item* item){
    switch (item->type) {
        case BENCODE_INT: {
            // ints are stack allocated, so just remove the struct itself
            break;
        }
        case BENCODE_STRING: {
            free(item->string_data);
            break;
        }
        case BENCODE_LIST: {
            // free children first, then free itself
            bencode_list* list = (bencode_list*) item->list_data;
            for (unsigned int i = 0; i < list->size; i++){
                bencode_free(list->data[i]);
            }
            free(list->data);
            free(list);
            break;
        }
        case BENCODE_DICT: {
            // free children first, then free itself
            bencode_dict* dict = (bencode_dict*) item->dict_data;
            for (unsigned int i = 0; i < dict->size; i++){
                free(dict->keys[i]);
                bencode_free(dict->values[i]);
            }

            free(dict->keys);
            free(dict->values);
            free(dict);
            break;
        }
    }

    free(item);
}

bencode_item* decode_bencode_item(bencode_context* context){
    switch (*(context->cursor)) {
        case 'i': // integer
            printf("decoding int\n");
            return decode_bencode_int(context);
        case 'l': // list
            printf("decoding list\n");
            return decode_bencode_list(context);
        case 'd':
            printf("decoding dict\n");
            return decode_bencode_dict(context);
        default: // all other cases should be strings
            printf("decoding string\n");
            return decode_bencode_string(context);
    }
}

bencode_item* decode_bencode_cstring(const char* cstr){
    bencode_context string_context = {
        .raw = cstr,
        .length = strlen(cstr),
        .cursor = cstr
    };

    bencode_item* result = decode_bencode_item(&string_context);
    return result;
}

bencode_item* decode_bencode_int(bencode_context* context){
    //skip i
    context->cursor++;

    // TODO: negative numbers can be encoded by starting the string of digits with -
    // TODO: zero leading numbers aren't allowed except for 0 itself (i.e. "i0e")

    unsigned int i = 0;
    while (!(*(context->cursor) == 'e')){
        i = i * 10 + (*(context->cursor++) - '0');
    }

    // do some sanity checks
    if((i < 0) || (i > (2 << 16))){
        // NOTE: Unix timestamps can trigger this branch...
        fprintf(stderr, "Warning: while decoding bencode int, found weird int of %d\n", i);
    }

    //skip e
    context->cursor++;
    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_INT;
    out->int_data = i;
    return out;

}
bencode_item* decode_bencode_string(bencode_context* context){
    int length = 0;

    char int_buf[16];
    unsigned int i = 0;

    while(*(context->cursor) != ':'){
        int_buf[i++] = *(context->cursor++);
    }

    int_buf[i] = '\0';
    length = atoi(int_buf);

    // do some sanity checks
    if((length < 0) || (length > (1e16))){
        fprintf(stderr, "Warning: while decoding size of string, found size of %d\n", i);
    }

    char* str = malloc(length + 1); // add extra byte for \0
    context->cursor++; // skip :
    memcpy(str, context->cursor, length);
    str[length] = '\0';

    // remove :
    // advance cursor to after the memcopy
    context->cursor += length;

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_STRING;
    out->string_data = str;
    return out;

}
bencode_item* decode_bencode_list(bencode_context* context){
    context->cursor++; // skip the first l

    bencode_list* list = malloc(sizeof(bencode_list));
    list->size = 0;
    list->data = NULL;

    while(!(*(context->cursor) == 'e')){
        list->data = realloc(list->data, (list->size+1) * sizeof(bencode_item));
        list->data[list->size] = decode_bencode_item(context);
        list->size++;
    };

    context->cursor++; // skip the last e

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_LIST;
    out->list_data = list;
    return out;

}
bencode_item* decode_bencode_dict(bencode_context* context){
     context->cursor++; // skip the first d

    bencode_dict* dict = malloc(sizeof(bencode_list));
    dict->size = 0;
    dict->keys = NULL;
    dict->values = NULL;

    while(!(*(context->cursor) == 'e')){
        dict->keys = realloc(dict->keys, (dict->size+1) * sizeof(char*));
        dict->values = realloc(dict->values, (dict->size+1) * sizeof(bencode_item));

        dict->keys[dict->size] = decode_bencode_item(context)->string_data;
        // check for info dict
        dict->values[dict->size] = decode_bencode_item(context);

        dict->size++;
    };

    context->cursor++; // skip the last e

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_DICT;
    out->dict_data = dict;
    return out;
}

bool bencode_tests(void){

    //test int
    bencode_item* result = decode_bencode_cstring("i7e");
    assert(result->type == BENCODE_INT);
    assert(result->int_data == 7);

    result = decode_bencode_cstring("i42069e");
    assert(result->type == BENCODE_INT);
    assert(result->int_data == 42069);

    //test string
    result = decode_bencode_cstring("4:test");
    assert(result->type == BENCODE_STRING);
    assert(!strcmp(result->string_data, "test"));

    // this fails! TODO: how do we test this?
    //result = decode_bencode_cstring("0:");
    //assert(result->type == BENCODE_STRING);
    //assert(!strcmp(result->string_data, ""));

    result = decode_bencode_cstring("678:Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec placerat ultricies auctor. Donec vestibulum nibh id lectus elementum ultricies. Donec accumsan massa ipsum, a sollicitudin ex tempor non. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Donec aliquet sapien in mi dignissim sodales. Donec at diam et purus lacinia euismod id ut ligula. Etiam elementum consequat posuere. In eget turpis quis sapien elementum finibus. Vestibulum malesuada nulla at turpis tincidunt faucibus. Nulla sed sapien risus. In hac habitasse platea dictumst. Duis sit amet arcu tincidunt, molestie lorem in, luctus augue. Morbi in congue nulla. Aliquam.");

    assert(result->type == BENCODE_STRING);
    assert(strlen(result->string_data) == 678);
    assert(result->string_data[0] == 'L');
    assert(result->string_data[strlen(result->string_data) - 1 ] == '.');

    // test bencode bencode_search
    bencode_item* root = decode_bencode_cstring("d4:test3:4203:loli69e6:nestedd5:nest12:ok5:nest23:notee");

    bencode_item* found = bencode_search(root, "lol");
    assert(found != NULL);
    assert(found->type == BENCODE_INT);
    assert(found->int_data == 69);

    found = bencode_search(root, "nest1");
    assert(found != NULL);
    assert(found->type == BENCODE_STRING);
    assert(!strcmp(found->string_data, "ok"));

    printf("bencode tests succesful\n");
    return true;
}
