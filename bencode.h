#pragma once

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
    char* raw;
    unsigned int length;
    char* cursor;
    bencode_item* root;
    unsigned int info_start_idx;
    unsigned int info_end_idx;
} bencode_context;

bencode_item* search(bencode_context* context, char* key_name);
void print_bencode(bencode_item* src);
void free_bencode_item(bencode_item* item);

bencode_item* decode_bencode_item(bencode_context* context);
bencode_item* decode_bencode_string(bencode_context* context);
bencode_item* decode_bencode_int(bencode_context* context);
bencode_item* decode_bencode_list(bencode_context* context);
bencode_item* decode_bencode_dict(bencode_context* context);

