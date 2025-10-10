#pragma once

#include "defines.h"

#include <netinet/in.h>
#include <stdbool.h>

typedef struct {
    const char* adress;
    u16 port;

    struct sockaddr_in _server_addr;
    u32 _socket_handle;
    u8 _buffer[1024];

} connection_context;

typedef struct {
    const char* key;
    const char* value;
    const void* next;
} http_url_param;

typedef struct {
    char scheme[16];
    char host[256];
    char path[1024];
    u64 port;
} url;

// you get ownership and need to free the string.
char* url_encode_bytes(const u8* data, usize length);
char* url_encode_string(const char* cstring);

// you get ownership and need to free, can be null if parsing error occured
url* url_parse(const char* url_str);

// returns null when creating connection context fails
connection_context* connection_init(const char* ip_adress, u16 port);
// returns null when creating connection context fails (url has to be alive
// too!)
connection_context* connection_init_addr(in_addr_t address, u16 port);
connection_context* connection_init_from_url(const url* url);

void connection_send(connection_context* context, u8* data,
                      usize length);
void connection_send_string(connection_context* context, const char* cstring);

void connection_send_http_get(connection_context* context, url* url,
                               http_url_param* params);

// receive functions do not terminate
usize connection_receive(connection_context* context, u8* data,
                         usize buffer_size);

// you get ownership and need to free the string.
char* connection_receive_string(connection_context* context);
// you get ownership, can be null, has a max size
char* connection_receive_http(connection_context* context);


void connection_close_and_free(connection_context* context);
