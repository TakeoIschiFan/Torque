#include "defines.h"
#include "bencode.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>

bencode_item* _make_bencode_error(bencode_error error) {
    bencode_item* item = malloc(sizeof(bencode_item));
    item->type = BENCODE_INVALID;
    item->error = error;
    return item;
}



bencode_context* bencode_context_get(const u8* buffer,
                                     const usize size){
    bencode_context* context = malloc(sizeof(bencode_context));

    context->raw = buffer;
    context->cursor = (u8*) buffer;
    context->length = size;
    context->_info_start_ptr = null;
    context->_info_length = 0;

    return context;
}

void bencode_print(bencode_item* src) {
    switch (src->type) {
        case BENCODE_INT:
            printf("%lld", (long long)src->int_data);
            break;

        case BENCODE_BYTE_STRING: {
            bencode_byte_string* bs = src->byte_string_data;
            fwrite(bs->data, 1, bs->size, stdout);
            break;
        }

        case BENCODE_LIST: {
            bencode_list* list = src->list_data;
            printf("[");
            for (usize i = 0; i < list->size; i++) {
                if (i > 0) printf(", ");
                bencode_print(list->data[i]);
            }
            printf("]");
            break;
        }

        case BENCODE_DICT: {
            bencode_dict* dict = src->dict_data;
            printf("{");
            for (usize i = 0; i < dict->size; i++) {
                if (i > 0) printf(", ");
                fwrite(dict->keys[i]->data, 1, dict->keys[i]->size, stdout);
                printf(": ");
                bencode_print(dict->values[i]);
            }
            printf("}");
            break;
        }

        case BENCODE_INVALID:
            printf("<invalid:%d>", src->error);
            break;
    }
}

bencode_item* bencode_search(bencode_item* root, const char* key_name) {
    if (root->type != BENCODE_DICT) {
        return NULL;
    }

    bencode_dict* dict_data = root->dict_data;

    for (usize i = 0; i < dict_data->size; i++) {
        bencode_byte_string* key_bs = dict_data->keys[i];
        bencode_item* item = dict_data->values[i];

        // compare key with byte string
        if (strlen(key_name) == key_bs->size &&
            memcmp(key_name, key_bs->data, key_bs->size) == 0) {
            return item;
            }

            // recurse into nested dicts or lists
            bencode_item* result = bencode_search(item, key_name);
        if (result != NULL) {
            return result;
        }
    }

    return NULL;
}

void bencode_free(bencode_item* item) {
    switch (item->type) {
        case BENCODE_INT: break;

        case BENCODE_BYTE_STRING: {
            bencode_byte_string* bs = item->byte_string_data;
            if (bs) {
                free(bs->data);
                free(bs);
            }
            break;
        }

        case BENCODE_LIST: {
            bencode_list* list = item->list_data;
            if (list) {
                for (usize i = 0; i < list->size; i++) {
                    bencode_free(list->data[i]);
                }
                free(list->data);
                free(list);
            }
            break;
        }

        case BENCODE_DICT: {
            bencode_dict* dict = item->dict_data;
            if (dict) {
                for (usize i = 0; i < dict->size; i++) {
                    free(dict->keys[i]->data);
                    free(dict->keys[i]);
                }
                for (usize i = 0; i < dict->size; i++) {
                    bencode_free(dict->values[i]);
                }
                free(dict->keys);
                free(dict->values);
                free(dict);
            }
            break;
        }

        case BENCODE_INVALID: break;
    }

    free(item);
}

bencode_item* decode_bencode_cstring(const char* cstr) {
    bencode_context string_context = {.raw = (const u8*)cstr,
        .length = strlen(cstr),
        .cursor = (u8*)cstr};

        bencode_item* result = decode_bencode_item(&string_context);
        return result;
}

bencode_item* decode_bencode_item(bencode_context* context) {
    if (context->length == 0){
        bencode_item* out = malloc(sizeof(bencode_item));
        out->type = BENCODE_INVALID;
        out->error = BENCODE_ERROR_NULL_ROOT_VALUE;
    }

    if (context->cursor == context->raw + context->length){
        bencode_item* out = malloc(sizeof(bencode_item));
        out->type = BENCODE_INVALID;
        out->error = BENCODE_ERROR_NON_SINGULAR_ROOT_ITEM;
    }

    switch (*(context->cursor)) {
        case 'i':
            return decode_bencode_int(context);
        case 'l':
            return decode_bencode_list(context);
        case 'd':
            return decode_bencode_dict(context);
        default: // all other cases should be strings
            if(isdigit(*(context->cursor))){
                return decode_bencode_byte_string(context);
            }else {
                // or an invalid item
                bencode_item* out = malloc(sizeof(bencode_item));
                out->type = BENCODE_INVALID;
                out->error = BENCODE_ERROR_INVALID_TYPE;

                return out;
            }
    }
}

bencode_item* decode_bencode_int(bencode_context* context) {
    context->cursor++; // skip 'i'

    i8 positive = 1;

    // Handle optional sign
    if (*context->cursor == '-') {
        positive = -1;
        context->cursor++;
        // Check for "-0" specifically
        if (*context->cursor == '0' && *(context->cursor + 1) == 'e') {
            return _make_bencode_error(BENCODE_ERROR_INT_NEGATIVE_ZERO);
        }
    }

    // Leading zero check (for positive numbers only)
    if (*context->cursor == '0' && *(context->cursor + 1) != 'e') {
        return _make_bencode_error(BENCODE_ERROR_INT_LEADING_ZERO);
    }

    uint64_t value = 0;      // use unsigned to simplify overflow detection
    b8 has_digits = false;

    // Parse digits until 'e' or invalid character
    while (*context->cursor && *context->cursor != 'e') {
        if (!isdigit(*(context->cursor))) {
            return _make_bencode_error(BENCODE_ERROR_INT_CONTAINS_NON_DIGIT_CHARACTER);
        }

        has_digits = true;
        uint64_t digit = *context->cursor - '0';

        // Overflow check
        if (positive == 1) {
            if (value > ((u64)INT64_MAX - digit) / 10) {
                return _make_bencode_error(BENCODE_ERROR_INT_OUT_OF_BOUNDS);
            }
        } else { // negative
            if (value > ((u64)INT64_MAX + 1 - digit) / 10) {
                return _make_bencode_error(BENCODE_ERROR_INT_OUT_OF_BOUNDS);
            }
        }

        value = value * 10 + digit;
        context->cursor++;
    }

    if (*context->cursor != 'e') {
        return _make_bencode_error(BENCODE_MISSING_E_TERMINATOR);
    }

    if (!has_digits) {
        return _make_bencode_error(BENCODE_ERROR_INT_CONTAINS_NON_DIGIT_CHARACTER);
    }

    // Skip 'e'
    context->cursor++;

    bencode_item* item = malloc(sizeof(bencode_item));
    item->type = BENCODE_INT;
    // cast to signed after parsing
    item->int_data = positive == 1 ? (int64_t)value : -(int64_t)value;
    return item;
}

bencode_item* decode_bencode_byte_string(bencode_context* context) {
    char int_buf[20];
    usize i = 0;

    // Parse digits until colon
    while (*context->cursor && *context->cursor != ':') {
        if (!isdigit(*context->cursor)) {
            return _make_bencode_error(BENCODE_ERROR_BYTE_STRING_NOT_FOLLOWED_BY_COLON);
        }

        if (i >= sizeof(int_buf) - 1) {
            return _make_bencode_error(BENCODE_ERROR_INT_OUT_OF_BOUNDS);
        }

        int_buf[i++] = *context->cursor++;
    }

    if (*context->cursor != ':') {
        return _make_bencode_error(BENCODE_ERROR_BYTE_STRING_NOT_FOLLOWED_BY_COLON);
    }

    int_buf[i] = '\0';

    i64 length = 0;
    for (usize j = 0; j < i; j++) {
        int digit = int_buf[j] - '0';
        if ((u64)length > (SIZE_MAX - digit) / 10) {
            return _make_bencode_error(BENCODE_ERROR_INT_OUT_OF_BOUNDS);
        }
        length = length * 10 + digit;
    }

    context->cursor++; // skip ':'

    if ((usize)(context->cursor - context->raw) + (usize)length > context->length) {
        return _make_bencode_error(BENCODE_ERROR_BYTE_STRING_EOF_BEFORE_COMPLETING_STRING);
    }

    bencode_byte_string* bs = malloc(sizeof(bencode_byte_string));
    bs->size = (usize)length;
    bs->data = malloc(length);
    memcpy(bs->data, context->cursor, length);
    context->cursor += length;

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_BYTE_STRING;
    out->byte_string_data = bs;

    return out;
}

bencode_item* decode_bencode_list(bencode_context* context) {
    context->cursor++; // skip 'l'

    bencode_list* list = malloc(sizeof(bencode_list));
    list->size = 0;
    list->data = null;

    while ((usize)(context->cursor - context->raw) < context->length &&
        *context->cursor != 'e') {
        bencode_item* element = decode_bencode_item(context);

        // propagate errors upward
        if (element->type == BENCODE_INVALID) {
            for (usize j = 0; j < list->size; j++) bencode_free(list->data[j]);
            free(list->data);
            free(list);
            return element;
        }

        bencode_item** new_data =
        realloc(list->data, (list->size + 1) * sizeof(bencode_item*));
        list->data = new_data;
        list->data[list->size++] = element;
    }

    if ((usize)(context->cursor - context->raw) >= context->length || *context->cursor != 'e') {
        for (usize j = 0; j < list->size; j++) bencode_free(list->data[j]);
        free(list->data);
        free(list);
        return _make_bencode_error(BENCODE_MISSING_E_TERMINATOR);
    }

    context->cursor++; // skip 'e'

    bencode_item* out = malloc(sizeof(bencode_item));

    out->type = BENCODE_LIST;
    out->list_data = list;
    return out;
}

bencode_item* decode_bencode_dict(bencode_context* context) {
    context->cursor++; // skip 'd'

    bencode_dict* dict = malloc(sizeof(bencode_dict));
    dict->size = 0;
    dict->keys = NULL;
    dict->values = NULL;

    while ((usize)(context->cursor - context->raw) < context->length &&
        *context->cursor != 'e') {
        // decode key
        bencode_item* key_item = decode_bencode_item(context);

        if (key_item->type != BENCODE_BYTE_STRING) {
            bencode_free(key_item);
            for (usize i = 0; i < dict->size; i++) {
                free(dict->keys[i]->data);  // internal buffer
                free(dict->keys[i]);                    // the struct itself
            }
            for (usize i = 0; i < dict->size; i++) {
                bencode_free(dict->values[i]);
            }

            // Free the arrays and dict struct itself
            free(dict->keys);
            free(dict->values);
            free(dict);
            return _make_bencode_error(BENCODE_ERROR_DICT_KEY_IS_NOT_A_STRING);
        }

        bencode_byte_string* key_bs = key_item->byte_string_data;
        free(key_item); // free wrapper, keep byte string

        // realloc keys and values arrays
        dict->keys = realloc(dict->keys, (dict->size + 1) * sizeof(bencode_byte_string*));
        dict->values = realloc(dict->values, (dict->size + 1) * sizeof(bencode_item*));

        dict->keys[dict->size] = key_bs;
        bencode_item* value;

        // special handling for "info" key
        if (key_bs->size == 4 &&
            !memcmp(key_bs->data, "info", 4) &&
            context->_info_start_ptr == NULL) {
            context->_info_start_ptr = context->cursor; // record start BEFORE decoding
            }

        // decode value
        value = decode_bencode_item(context);

        if (key_bs->size == 4 && !memcmp(key_bs->data, "info", 4) && context->_info_start_ptr != NULL) {
            context->_info_length = context->cursor - context->_info_start_ptr;
        }

        dict->values[dict->size] = value;

        // propagate errors
        if (value->type == BENCODE_INVALID) {
            // free keys
            for (usize i = 0; i <= dict->size; i++) {
                free(dict->keys[i]->data);
                free(dict->keys[i]);
            }
            // free values
            for (usize i = 0; i < dict->size; i++) {
                bencode_free(dict->values[i]);
            }
            free(dict->keys);
            free(dict->values);
            free(dict);

            return value;
        }

        dict->size++;

    }

    if ((usize)(context->cursor - context->raw) >= context->length || *context->cursor != 'e') {
        // free keys
        for (usize i = 0; i < dict->size; i++) {
            free(dict->keys[i]->data);
            free(dict->keys[i]);
        }
        // free values
        for (usize i = 0; i < dict->size; i++) {
            bencode_free(dict->values[i]);
        }
        free(dict->keys);
        free(dict->values);
        free(dict);
        return _make_bencode_error(BENCODE_MISSING_E_TERMINATOR);
    }

    context->cursor++; // skip 'e'

    bencode_item* out = malloc(sizeof(bencode_item));
    out->type = BENCODE_DICT;
    out->dict_data = dict;
    return out;
}





