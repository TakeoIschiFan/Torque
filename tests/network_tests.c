#include "../src/defines.h"
#include "../src/network.h"
#include "napoleon.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>

NAP_TEST url_parse_tests(void) {
    url* result;

    // full URL with port and path
    result = url_parse("http://localhost:9405/path");
    nap_assert(result != null);
    nap_assert(strcmp(result->scheme, "http") == 0);
    nap_assert(strcmp(result->host, "localhost") == 0);
    nap_assert(result->port == 9405);
    nap_assert(strcmp(result->path, "/path") == 0);
    free(result);

    // default port and path
    result = url_parse("http://localhost");
    nap_assert(result != null);
    nap_assert(strcmp(result->scheme, "http") == 0);
    nap_assert(strcmp(result->host, "localhost") == 0);
    nap_assert(result->port == 80);
    nap_assert(strcmp(result->path, "/") == 0);
    free(result);

    // path without explicit port
    result = url_parse("http://example.com/some/path");
    nap_assert(result != null);
    nap_assert(strcmp(result->scheme, "http") == 0);
    nap_assert(strcmp(result->host, "example.com") == 0);
    nap_assert(result->port == 80);
    nap_assert(strcmp(result->path, "/some/path") == 0);
    free(result);

    // https with explicit port
    result = url_parse("https://secure.site:443/login");
    nap_assert(result != null);
    nap_assert(strcmp(result->scheme, "https") == 0);
    nap_assert(strcmp(result->host, "secure.site") == 0);
    nap_assert(result->port == 443);
    nap_assert(strcmp(result->path, "/login") == 0);
    free(result);

    // invalid port (>65535)
    result = url_parse("http://badport.com:99999");
    nap_assert(result == null);
    free(result);

    // missing host
    result = url_parse("http://:8080");
    nap_assert(result == null);
    free(result);

    // missing scheme
    result = url_parse("localhost:9405");
    nap_assert(result == null);
    free(result);

    // completely invalid
    result = url_parse("not a url");
    nap_assert(result == null);
    free(result);
}

NAP_TEST url_encode_bytes_tests(void) {
    char* result;

    // null-terminated string
    result = url_encode_bytes((const u8*)"abc 123", 7);
    nap_assert(strcmp(result, "abc+123") == 0);
    free(result);

    // partial buffer
    const char* s = "hello world!";
    result = url_encode_bytes((const u8*)s, 5); // only "hello"
    nap_assert(strcmp(result, "hello") == 0);
    free(result);

    // spaces and special characters, including null byte
    const char buf[] = {'a', ' ', '+', '&', '\0', 'b'};
    result = url_encode_bytes((const u8*)buf, sizeof(buf));
    nap_assert(strcmp(result, "a+%2B%26%00b") == 0);
    free(result);

    // empty buffer
    result = url_encode_bytes((const u8*)"", 0);
    nap_assert(strcmp(result, "") == 0);
    free(result);
}

NAP_TEST url_encode_string_tests(void) {
    char* result;

    // plain alphanumeric
    result = url_encode_string("abc123XYZ");
    nap_assert(strcmp(result, "abc123XYZ") == 0);
    free(result);

    // safe characters
    result = url_encode_string("*-._");
    nap_assert(strcmp(result, "*-._") == 0);
    free(result);

    // space
    result = url_encode_string("hello world");
    nap_assert(strcmp(result, "hello+world") == 0);
    free(result);

    // reserved characters
    result = url_encode_string(":/?#[]@");
    nap_assert(strcmp(result, "%3A%2F%3F%23%5B%5D%40") == 0);
    free(result);

    // mixed characters
    result = url_encode_string("a b+c&d");
    nap_assert(strcmp(result, "a+b%2Bc%26d") == 0);
    free(result);

    // empty string
    result = url_encode_string("");
    nap_assert(strcmp(result, "") == 0);
    free(result);
}

NAP_TEST connection_init_from_url_tests(void) {
    // start temporary server on 9500
    FILE* ncat_proc = popen("ncat -l 9500 -c 'cat'", "r");
    usleep(100 * 1000); // give server time to start

    url* u = url_parse("http://127.0.0.1:9500/");
    connection_context* ctx = connection_init_from_url(u);
    nap_assert(ctx != null);
    free(u);
    connection_close_and_free(ctx);
    pclose(ncat_proc);

    //invalid host should fail
    url* bad = url_parse("http://nonexistent.host:9501/");
    connection_context* ctx_b = connection_init_from_url(bad);
    nap_assert(ctx_b == null);
    free(bad);
}

NAP_TEST connection_init_creation_tests(void) {
    // Start temporary server on 9401
    FILE* ncat_proc = popen("ncat -l 9401 -c 'echo -n test'", "r");
    usleep(100 * 1000); // give server time to start

    // valid loopback IP, arbitrary port
    connection_context* result = connection_init("127.0.0.1", 9401);
    nap_assert(result != null);
    connection_close_and_free(result);
    pclose(ncat_proc);

    // creating two sockets to a host that only accepts one should fail
    FILE* ncat_proc_b = popen("ncat -l 9405 -c 'echo -n test'", "r");
    usleep(100 * 1000);

    // creating two sockets to a host that only accepts one should fail
    result = connection_init("127.0.0.1", 9405);
    nap_assert(result != null);

    connection_context* result_b = connection_init("127.0.0.1", 9401);
    nap_assert(result_b == null);

    connection_close_and_free(result);
    pclose(ncat_proc_b);

    // clearly invalid IP string should fail
    connection_context* result_c = connection_init("not_an_ip", 1234);
    nap_assert(result_c == null);
}

NAP_TEST connection_receive_short_buffer(void) {
    // start temporary server that immediately sends "test"
    FILE* ncat_proc = popen("ncat -l 9700 -c 'echo -n test'", "r");
    usleep(100 * 1000);

    connection_context* ctx = connection_init("127.0.0.1", 9700);
    nap_assert(ctx != null);

    u8 buf[1024];
    usize read = connection_receive(ctx, buf, 4);
    nap_assert(read == 4);
    nap_assert(strncmp((char*)buf, "test", 4) == 0);

    connection_close_and_free(ctx);
    pclose(ncat_proc);
}

NAP_TEST connection_receive_large_buffer(void) {
    // start temporary server that immediately sends "test"
    FILE* ncat_proc = popen("ncat -l 9701 -c 'echo -n test'", "r");
    usleep(100 * 1000);

    connection_context* ctx = connection_init("127.0.0.1", 9701);
    nap_assert(ctx != null);

    u8 buf[1024];
    usize read = connection_receive(ctx, buf, 1024);
    nap_assert(read == 4);
    nap_assert(strncmp((char*)buf, "test", 4) == 0);

    connection_close_and_free(ctx);
    pclose(ncat_proc);
}

void connection_send_and_receive_echo(void) {
    // start temporary echo server
    FILE* ncat_proc = popen("ncat -l 9703 -c 'cat'", "r");
    usleep(100 * 1000);

    connection_context* ctx = connection_init("127.0.0.1", 9703);
    nap_assert(ctx != null);

    // send string
    const char* msg = "hello world";
    connection_send_string(ctx, msg);

    // receive back
    char* buf = connection_receive_string(ctx);
    nap_assert(strcmp(buf, msg) == 0);
    free(buf);

    connection_close_and_free(ctx);
    pclose(ncat_proc);
}

void connection_send_and_receive_bytes(void) {
    // start temporary echo server
    FILE* ncat_proc = popen("ncat -l 9704 -c 'cat'", "r");
    usleep(100 * 1000);

    connection_context* ctx = connection_init("127.0.0.1", 9704);
    nap_assert(ctx != null);

    u8 data[] = {10, 20, 30, 40, 50};
    connection_send(ctx, data, sizeof(data));

    u8 buf[5];
    usize read = connection_receive(ctx, buf, sizeof(buf));
    nap_assert(read == 5);
    for (usize i = 0; i < 5; i++) {
        nap_assert(buf[i] == data[i]);
    }

    connection_close_and_free(ctx);
    pclose(ncat_proc);
}
