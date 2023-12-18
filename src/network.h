#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>

// low level tcp socket stuff

typedef struct {
    const char* adress;
    const unsigned short port;

    struct sockaddr_in _server_addr;
    unsigned int _socket_handle;
    unsigned char _buffer[1024];
} connection_context;

bool connection_init(connection_context* context);
bool connection_init_override_ip(connection_context* context,
                                 const struct in_addr* ip);
bool connection_connect(connection_context* context);
void connection_send(connection_context* context, unsigned char* data,
                     unsigned int length);
void connection_send_string(connection_context* context, const char* cstring);
long connection_receive(connection_context* context, unsigned char* data,
                        unsigned int buffer_size);
char* connection_receive_string(connection_context* context);
bool connection_close_and_free(connection_context* context);

// high level http stuff
typedef enum { GET, POST } request_verb;

typedef struct {
    const char* key;
    const char* value;
} query_param;

typedef struct {
    request_verb verb;
    const char* host;
    const char* path;
    query_param* params;
    unsigned int params_size;
} request_context;

request_context* get_request_context(request_verb verb, char* url);

void add_request_param(request_context* req, const char* key,
                       const char* value);

bool execute_request(request_context* req, char* response_buffer,
                     unsigned int response_buffer_size);

bool network_tests(void);
