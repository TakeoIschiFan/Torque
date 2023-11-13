#include "bencode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void print_bencode(bencode_item* src){
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
                    print_bencode(list->data[i]);
            }
        }
        break;
        case BENCODE_DICT: {
            bencode_dict* dict = (bencode_dict*)(src->list_data);
            for (int i = 0; i < dict->size; i++){
                printf("\t%s:", dict->keys[i]);
                print_bencode(dict->values[i]);
            }
        }
        break;
    }
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

bencode_item* decode_bencode_int(bencode_context* context){
    int i = 0;
    //skip i
    context->cursor++;

    while (!(*(context->cursor) == 'e')){
        i = i * 10 + (*(context->cursor++) - '0');
    }

    //skip e
    context->cursor++;

    printf("found int %d\n", i);

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_INT;
    out->int_data = i;
    return out;

}
bencode_item* decode_bencode_string(bencode_context* context){
    printf("cursor at %c\n", *(context->cursor));
    int length = 0;

    char int_buf[24];
    int i = 0;

    while(*(context->cursor) != ':'){
        int_buf[i++] = *(context->cursor++);
    }

    int_buf[i] = '\0';
    length = atoi(int_buf);
    if (length == 0){
        exit(1);
    }

    char* str = malloc(length + 2); // add extra bytes for : and \0
    memcpy(str, context->cursor, length + 1);
    str[length+2] = '\0';

    // remove :
    str++;
    // advance cursor to after the memcopy
    context->cursor += (length + 1);
    if (length < 500){
        printf("found string %s\n", str);
    }else{
        printf("found binary blob");
    }

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
    printf("this test runs \n");
    return true;
}
