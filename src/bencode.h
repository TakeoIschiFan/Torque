#pragma once

#include "defines.h"

typedef enum {
    BENCODE_INT,
    BENCODE_STRING,
    BENCODE_LIST,
    BENCODE_DICT,
    BENCODE_INVALID
} bencode_type;

typedef enum {
    BENCODE_ERROR_NULL_ROOT_VALUE,
    BENCODE_ERROR_NON_SINGULAR_ROOT_ITEM,
    BENCODE_ERROR_INVALID_TYPE,
    BENCODE_MISSING_E_TERMINATOR,
    BENCODE_ERROR_INT_LEADING_ZERO,
    BENCODE_ERROR_INT_CONTAINS_NON_DIGIT_CHARACTER,
    BENCODE_ERROR_INT_NEGATIVE_ZERO,
    BENCODE_ERROR_INT_OUT_OF_BOUNDS, // not in the official spec but we do have bounds limits
    BENCODE_ERROR_BYTE_STRING_NEGATIVE_LENGTH, // unused, returns BENCODE_ERROR_INVALID_TYPE instead
    BENCODE_ERROR_BYTE_STRING_NOT_FOLLOWED_BY_COLON,
    BENCODE_ERROR_BYTE_STRING_EOF_BEFORE_COMPLETING_STRING,
    BENCODE_ERROR_BYTE_STRING_LENGTH_NOT_IN_BYTES, // not checked
    BENCODE_ERROR_DICT_KEY_IS_NOT_A_STRING,
    BENCODE_ERROR_DICT_DUPLICATE_KEYS,
    BENCODE_ERROR_DICT_KEYS_NOT_SORTED,
    BENCODE_ERROR_DICT_KEYS_NOT_SORTED_BY_ORDINAL,
    BENCODE_ERROR_DICT_MISSING_VALUE_FOR_KEY
} bencode_error;

typedef struct bencode_item bencode_item;
typedef struct bencode_list bencode_list;
typedef struct bencode_dict bencode_dict;
typedef struct bencode_byte_string bencode_byte_string;

struct bencode_byte_string {
    usize size;
    u8* data;
};

struct bencode_list {
    usize size;
    bencode_item** data;   // now valid
};

struct bencode_dict {
    usize size;
    bencode_byte_string** keys;
    bencode_item** values; // now valid
};

struct bencode_item {
    bencode_type type;
    union {
        bencode_dict* dict_data;
        bencode_list* list_data;
        bencode_byte_string* byte_string_data;
        i64 int_data;
        bencode_error error;
    };
};

typedef struct {
    const u8* raw;
    usize length;
    u8* cursor;
    u8* _info_start_ptr;
    usize _info_length;
} bencode_context;


void bencode_print(bencode_item* src);
void bencode_free(bencode_item* item);
bencode_item* bencode_search(bencode_item* root, const char* key_name);


/*
 *  Request a bencode context to decode binary buffers. You get ownership of the struct and
 * need to free.
 * If you have a cstring to decode without any non-ascii characters, consider using the ergonomic
 * decode_bencode_cstring
 */
bencode_context* bencode_context_get(const u8* buffer,
                                     const usize size);

/*
 *  All these functions return a bencode item struct. You get ownership of the struct and need to free with bencode_free.
 *  If parsing fails, will return a bencode_item with type BENCODE_INVALID, which you need to check before proceeding.
 */
bencode_item* decode_bencode_cstring(const char* cstr);
bencode_item* decode_bencode_item(bencode_context* context);
bencode_item* decode_bencode_byte_string(bencode_context* context);
bencode_item* decode_bencode_int(bencode_context* context);
bencode_item* decode_bencode_list(bencode_context* context);
bencode_item* decode_bencode_dict(bencode_context* context);

