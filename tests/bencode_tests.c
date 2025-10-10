#include "../src/bencode.h"
#include "napoleon.h"
#include "stdbool.h"
#include <string.h>


NAP_TEST bencode_int_tests(void) {
    bencode_item* r;

    // valid integers
    r = decode_bencode_cstring("i0e");
    nap_assert(r->type == BENCODE_INT && r->int_data == 0);
    bencode_free(r);

    r = decode_bencode_cstring("i42e");
    nap_assert(r->type == BENCODE_INT && r->int_data == 42);
    bencode_free(r);

    r = decode_bencode_cstring("i-7e");
    nap_assert(r->type == BENCODE_INT && r->int_data == -7);
    bencode_free(r);

    // leading zero (invalid)
    r = decode_bencode_cstring("i042e");
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_LEADING_ZERO);
    bencode_free(r);

    // negative zero (invalid)
    r = decode_bencode_cstring("i-0e");
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_NEGATIVE_ZERO);
    bencode_free(r);

    // non-digit characters
    r = decode_bencode_cstring("ice");
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_CONTAINS_NON_DIGIT_CHARACTER);
    bencode_free(r);

    r = decode_bencode_cstring("i4:teste");
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_CONTAINS_NON_DIGIT_CHARACTER);
    bencode_free(r);

    // missing 'e'
    r = decode_bencode_cstring("i42");
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_MISSING_E_TERMINATOR);
    bencode_free(r);

    // extremely large integers (within bounds)
    char buf[32];
    snprintf(buf, sizeof(buf), "i%lde", INT64_MAX); // TODO: this formatting is platform specific
    r = decode_bencode_cstring(buf);
    nap_assert(r->type == BENCODE_INT && r->int_data == INT64_MAX);
    bencode_free(r);

    snprintf(buf, sizeof(buf), "i%lde", INT64_MIN);
    r = decode_bencode_cstring(buf);
    nap_assert(r->type == BENCODE_INT && r->int_data == INT64_MIN);
    bencode_free(r);

    // integers exceeding bounds (overflow)
    snprintf(buf, sizeof(buf), "i%llu0e", (unsigned long long)INT64_MAX); // overflow
    r = decode_bencode_cstring(buf);
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_OUT_OF_BOUNDS);
    bencode_free(r);

    snprintf(buf, sizeof(buf), "i-%llu0e", (unsigned long long)INT64_MAX + 1); // underflow
    r = decode_bencode_cstring(buf);
    nap_assert(r->type == BENCODE_INVALID && r->error == BENCODE_ERROR_INT_OUT_OF_BOUNDS);
    bencode_free(r);

    // single digit numbers
    for (int d = 0; d <= 9; d++) {
        snprintf(buf, sizeof(buf), "i%de", d);
        r = decode_bencode_cstring(buf);
        nap_assert(r->type == BENCODE_INT && r->int_data == d);
        bencode_free(r);
    }

    // negative single digits
    for (int d = 1; d <= 9; d++) {
        snprintf(buf, sizeof(buf), "i-%de", d);
        r = decode_bencode_cstring(buf);
        nap_assert(r->type == BENCODE_INT && r->int_data == -d);
        bencode_free(r);
    }

    // multi-digit negative number
    r = decode_bencode_cstring("i-1234567890e");
    nap_assert(r->type == BENCODE_INT && r->int_data == -1234567890);
    bencode_free(r);

    // multi-digit positive number
    r = decode_bencode_cstring("i9876543210e");
    nap_assert(r->type == BENCODE_INT && r->int_data == 9876543210);
    bencode_free(r);
}

NAP_TEST bencode_byte_string_tests(void) {
    bencode_item* r;
    bencode_context* ctx;

    // Valid ASCII
    r = decode_bencode_cstring("4:spam");
    nap_assert(r->type == BENCODE_BYTE_STRING);
    nap_assert(r->byte_string_data->size == 4);
    nap_assert(memcmp(r->byte_string_data->data, "spam", 4) == 0);
    bencode_free(r);

    // Zero-length string
    r = decode_bencode_cstring("0:");
    nap_assert(r->type == BENCODE_BYTE_STRING);
    nap_assert(r->byte_string_data->size == 0);
    bencode_free(r);

    // Binary data with null bytes
    const u8 binary_bytes[] = {'a','\0','b','\0','c'};
    const u8 bin_bencode[] = {'5', ':', 'a','\0','b','\0','c'};
    ctx = bencode_context_get(bin_bencode, sizeof(bin_bencode));
    r = decode_bencode_item(ctx);
    nap_assert(r->type == BENCODE_BYTE_STRING);
    nap_assert(r->byte_string_data->size == 5);
    nap_assert(memcmp(r->byte_string_data->data, binary_bytes, 5) == 0);
    bencode_free(r);
    free(ctx);

    // UTF-8 / non-ASCII
    const u8 utf8_bytes[] = {0xe3,0x81,0x82, 0xe3,0x81,0x84}; // "あい"
    const u8 utf8_bencode[] = {'6', ':', 0xe3,0x81,0x82,0xe3,0x81,0x84};
    ctx = bencode_context_get(utf8_bencode, sizeof(utf8_bencode));
    r = decode_bencode_item(ctx);
    nap_assert(r->type == BENCODE_BYTE_STRING);
    nap_assert(r->byte_string_data->size == 6);
    nap_assert(memcmp(r->byte_string_data->data, utf8_bytes, 6) == 0);
    bencode_free(r);
    free(ctx);

    // Negative length
    r = decode_bencode_cstring("-1:abc");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_INVALID_TYPE);
    bencode_free(r);

    // Missing colon
    r = decode_bencode_cstring("3abc");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_BYTE_STRING_NOT_FOLLOWED_BY_COLON);
    bencode_free(r);

    // EOF before completing string
    const u8 incomplete_bytes[] = {'5', ':', 'a','b'};
    ctx = bencode_context_get(incomplete_bytes, sizeof(incomplete_bytes));
    r = decode_bencode_item(ctx);
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_BYTE_STRING_EOF_BEFORE_COMPLETING_STRING);
    bencode_free(r);
    free(ctx);

    // ridiculous length
    r = decode_bencode_cstring("123456789123456789123456789123456789123456789:abc");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_INT_OUT_OF_BOUNDS);
    bencode_free(r);
}

NAP_TEST bencode_list_tests(void) {
    bencode_item* r;

    // empty list
    r = decode_bencode_cstring("le");
    nap_assert(r->type == BENCODE_LIST);
    nap_assert(r->list_data->size == 0);
    bencode_free(r);

    // list with integers
    r = decode_bencode_cstring("li1ei42ee");
    nap_assert(r->type == BENCODE_LIST);
    nap_assert(r->list_data->size == 2);
    nap_assert(r->list_data->data[0]->int_data == 1);
    nap_assert(r->list_data->data[1]->int_data == 42);
    bencode_free(r);

    // list with mixed types: int, string, nested list
    r = decode_bencode_cstring("li5e4:spamli3eee");
    nap_assert(r->type == BENCODE_LIST);
    nap_assert(r->list_data->size == 3);
    nap_assert(r->list_data->data[0]->int_data == 5);
    nap_assert(r->list_data->data[1]->type == BENCODE_BYTE_STRING);
    nap_assert(r->list_data->data[1]->byte_string_data->size == 4);
    nap_assert(memcmp(r->list_data->data[1]->byte_string_data->data, "spam", 4) == 0);
    nap_assert(r->list_data->data[2]->type == BENCODE_LIST);
    nap_assert(r->list_data->data[2]->list_data->size == 1);
    nap_assert(r->list_data->data[2]->list_data->data[0]->int_data == 3);
    bencode_free(r);

    // nested empty list
    r = decode_bencode_cstring("llee");
    nap_assert(r->type == BENCODE_LIST);
    nap_assert(r->list_data->size == 1);
    nap_assert(r->list_data->data[0]->type == BENCODE_LIST);
    nap_assert(r->list_data->data[0]->list_data->size == 0);
    bencode_free(r);

    // deeply nested valid (4 levels of lists, then i1e)
    r = decode_bencode_cstring("lllli1eeeee"); // l l l l i1e e e e e

    nap_assert(r && r->type == BENCODE_LIST);
    // walk down four list layers to the integer
    bencode_item* p = r;
    for (int depth = 0; depth < 4; ++depth) {
        nap_assert(p->type == BENCODE_LIST);
        nap_assert(p->list_data->size == 1);
        p = p->list_data->data[0];
    }
    nap_assert(p->type == BENCODE_INT && p->int_data == 1);
    bencode_free(r);

    // deeply nested truncated (missing one trailing 'e') -> should return MISSING_E_TERMINATOR
    r = decode_bencode_cstring("lllli1eeee"); // one fewer 'e' than needed
    nap_assert(r && r->type == BENCODE_INVALID && r->error == BENCODE_MISSING_E_TERMINATOR);
    bencode_free(r);

    // list with invalid integer (leading zero)
    r = decode_bencode_cstring("li01ee");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_INT_LEADING_ZERO);
    bencode_free(r);

    // list with invalid byte string (missing colon)
    r = decode_bencode_cstring("l3spam e");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_ERROR_BYTE_STRING_NOT_FOLLOWED_BY_COLON);
    bencode_free(r);

    // list with dict inside (valid dict)
    r = decode_bencode_cstring("ld3:cow3:moo4:spam4:eggsee");
    nap_assert(r->type == BENCODE_LIST);
    nap_assert(r->list_data->size == 1);
    nap_assert(r->list_data->data[0]->type == BENCODE_DICT);
    bencode_free(r);

    // list missing 'e' terminator
    r = decode_bencode_cstring("li1e");
    nap_assert(r->type == BENCODE_INVALID);
    nap_assert(r->error == BENCODE_MISSING_E_TERMINATOR);
    bencode_free(r);
}

NAP_TEST bencode_dict_tests(void) {
    bencode_item* r;
    bencode_dict* dict;

    // empty dict
    r = decode_bencode_cstring("de");
    nap_assert(r && r->type == BENCODE_DICT);
    dict = r->dict_data;
    nap_assert(dict->size == 0);
    bencode_free(r);

    // simple key-value: {"key": 42}
    r = decode_bencode_cstring("d3:keyi42ee");
    nap_assert(r && r->type == BENCODE_DICT);
    dict = r->dict_data;
    nap_assert(dict->size == 1);
    nap_assert(dict->keys[0]->size == 3 &&
    memcmp(dict->keys[0]->data, "key", 3) == 0);
    nap_assert(dict->values[0]->type == BENCODE_INT &&
    dict->values[0]->int_data == 42);
    bencode_free(r);

    // multiple entries: {"foo": "bar", "baz": 99}
    r = decode_bencode_cstring("d3:foo3:bar3:bazi99ee");
    nap_assert(r && r->type == BENCODE_DICT);
    dict = r->dict_data;
    nap_assert(dict->size == 2);

    nap_assert(dict->keys[0]->size == 3 &&
    memcmp(dict->keys[0]->data, "foo", 3) == 0);
    nap_assert(dict->values[0]->type == BENCODE_BYTE_STRING &&
    dict->values[0]->byte_string_data->size == 3 &&
    memcmp(dict->values[0]->byte_string_data->data, "bar", 3) == 0);

    nap_assert(dict->keys[1]->size == 3 &&
    memcmp(dict->keys[1]->data, "baz", 3) == 0);
    nap_assert(dict->values[1]->type == BENCODE_INT &&
    dict->values[1]->int_data == 99);
    bencode_free(r);

    // nested dict
    r = decode_bencode_cstring("d3:food3:bari1eee");
    nap_assert(r && r->type == BENCODE_DICT);
    dict = r->dict_data;
    nap_assert(dict->size == 1);
    nap_assert(dict->values[0]->type == BENCODE_DICT);
    nap_assert(dict->values[0]->dict_data->size == 1);
    nap_assert(dict->values[0]->dict_data->values[0]->type == BENCODE_INT &&
    dict->values[0]->dict_data->values[0]->int_data == 1);
    bencode_free(r);

    // non-string key -> error
    r = decode_bencode_cstring("di1ei2ee");
    nap_assert(r && r->type == BENCODE_INVALID &&
    r->error == BENCODE_ERROR_DICT_KEY_IS_NOT_A_STRING);
    bencode_free(r);

    // missing 'e' at end -> error
    r = decode_bencode_cstring("d3:keyi1e");
    nap_assert(r && r->type == BENCODE_INVALID &&
    r->error == BENCODE_MISSING_E_TERMINATOR);
    bencode_free(r);

    // error in value (invalid integer)
    r = decode_bencode_cstring("d3:keyi01ee");
    nap_assert(r && r->type == BENCODE_INVALID &&
    r->error == BENCODE_ERROR_INT_LEADING_ZERO);
    bencode_free(r);

    // malformed key (not followed by colon)
    r = decode_bencode_cstring("d1a1bee"); // bad: "1a" not a valid length:colon
    nap_assert(r && r->type == BENCODE_INVALID &&
    r->error == BENCODE_ERROR_DICT_KEY_IS_NOT_A_STRING);
    bencode_free(r);

    // "info" key special handling
    bencode_context* ctx;
    const char* input = "d4:infod3:fooi123ee3:bari99eee";
    ctx = bencode_context_get((u8*) input, strlen(input));
    r = decode_bencode_item(ctx);
    nap_assert(r && r->type == BENCODE_DICT);
    nap_assert(ctx->_info_start_ptr != NULL);
    nap_assert(ctx->_info_length > 0);
    bencode_free(r);
    free(ctx);
}

NAP_TEST bencode_search_tests(void) {
    // simple flat dictionary
    bencode_item* dict = decode_bencode_cstring("d3:foo3:bar3:bazi42ee");
    nap_assert(dict->type == BENCODE_DICT);

    bencode_item* result = bencode_search(dict, "foo");
    nap_assert(result != NULL);
    nap_assert(result->type == BENCODE_BYTE_STRING);
    nap_assert(result->byte_string_data->size == 3);
    nap_assert(memcmp(result->byte_string_data->data, "bar", 3) == 0);

    result = bencode_search(dict, "baz");
    nap_assert(result != NULL);
    nap_assert(result->type == BENCODE_INT);
    nap_assert(result->int_data == 42);

    // key not present
    result = bencode_search(dict, "nonexistent");
    nap_assert(result == NULL);

    bencode_free(dict);

    // nested dictionary
    dict = decode_bencode_cstring("d4:nestd3:key3:vale3:foo3:bar3:bazi99ee");
    nap_assert(dict->type == BENCODE_DICT);

    result = bencode_search(dict, "key");
    nap_assert(result != NULL);
    nap_assert(result->type == BENCODE_BYTE_STRING);
    nap_assert(memcmp(result->byte_string_data->data, "val", 3) == 0);

    result = bencode_search(dict, "foo");
    nap_assert(result != NULL);
    nap_assert(result->type == BENCODE_BYTE_STRING);
    nap_assert(memcmp(result->byte_string_data->data, "bar", 3) == 0);

    result = bencode_search(dict, "baz");
    nap_assert(result != NULL);
    nap_assert(result->type == BENCODE_INT);
    nap_assert(result->int_data == 99);

    bencode_free(dict);

    // nested list containing a dict
    bencode_item* list = decode_bencode_cstring("l4:spamd3:onei1e3:twoi2eee");
    nap_assert(list->type == BENCODE_LIST);

    result = bencode_search(list, "one");
    nap_assert(result == NULL);

    bencode_free(list);
}
