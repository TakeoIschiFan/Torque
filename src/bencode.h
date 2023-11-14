#pragma once

#include <stdbool.h>

typedef enum {
    BENCODE_INT,
    BENCODE_STRING,
    BENCODE_LIST,
    BENCODE_DICT
} bencode_type;

typedef struct {
    bencode_type type;
    union {
        struct bencode_dict* dict_data;
        struct bencode_list* list_data;
        unsigned int int_data;
        char* string_data;
    };
} bencode_item;

typedef struct {
    unsigned int size;
    bencode_item** data;
} bencode_list;

typedef struct {
    unsigned int size;
    char** keys;
    bencode_item** values;
} bencode_dict;

typedef struct {
    const unsigned char* raw;
    unsigned int length;
    unsigned char* cursor;
    unsigned char* _info_start_ptr;
    unsigned int _info_length;
} bencode_context;

// if you just need to decode a string, use this function
// you have to free the bencode_item afterwards using bencode_free
bencode_item* decode_bencode_cstring(const char* cstr);

// for lower level acces, request and free a bencode_context
bencode_context* bencode_context_get(const unsigned char* buffer, const unsigned int size);

// you should only need to call the general _item function.
// you have to free the bencode_item using bencode_free
bencode_item* decode_bencode_item(bencode_context* context);
bencode_item* decode_bencode_string(bencode_context* context);
bencode_item* decode_bencode_int(bencode_context* context);
bencode_item* decode_bencode_list(bencode_context* context);
bencode_item* decode_bencode_dict(bencode_context* context);
void bencode_free(bencode_item* item);


// utility functions
void bencode_print(bencode_item* src);
bencode_item* bencode_search(bencode_item* root, const char* key_name);


bool bencode_tests(void);

