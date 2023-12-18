#include "network.h"
#include <arpa/inet.h> // gives inet_addr function & htons function
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>      // dns lookup util
#include <netinet/in.h> // gives server_addr_sin
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> // give all the socket stuff
#include <unistd.h>     // gives read, send, close and some other stuff

bool connection_init(connection_context* context) {

    context->_server_addr.sin_family = AF_INET;
    context->_server_addr.sin_addr.s_addr = inet_addr(context->adress);
    context->_server_addr.sin_port = htons(context->port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        int errsv = errno;
        fprintf(stderr,
                "Error: could not initialize socket. Error code %d: %s. Check "
                "address and port and try again\n",
                errsv, strerror(errsv));
        return false;
    }
    context->_socket_handle = sock;
    return true;
}
bool connection_init_override_ip(connection_context* context,
                                 const struct in_addr* ip) {
    context->_server_addr.sin_family = AF_INET;
    memcpy(&(context->_server_addr.sin_addr.s_addr), ip,
           sizeof(context->_server_addr.sin_addr.s_addr));
    context->_server_addr.sin_port = htons(context->port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        int errsv = errno;
        fprintf(stderr,
                "Error: could not initialize socket. Error code %d: %s. Check "
                "address and port and try again\n",
                errsv, strerror(errsv));
        return false;
    }
    context->_socket_handle = sock;
    return true;
}

bool connection_connect(connection_context* context) {
    int returncode =
        connect(context->_socket_handle, (void*)(&context->_server_addr),
                sizeof(context->_server_addr));
    if (returncode != 0) {
        int errsv = errno;
        fprintf(stderr,
                "Error: could not open socket. Error code %d: %s. Is the "
                "server available?\n",
                errsv, strerror(errsv));
        return false;
    }
    return true;
}

void connection_send(connection_context* context, unsigned char* data,
                     unsigned int length) {
    long sent = 0;
    while (sent < length) {
        long bytes_sent =
            send(context->_socket_handle, data + sent, length - sent, 0);
        if (bytes_sent < 0) {
            fprintf(stderr, "Error: could not send blob to socket");
        } else if (bytes_sent == 0) {
            break;
        }

        sent += bytes_sent;
    }
}

void connection_send_string(connection_context* context, const char* cstring) {
    connection_send(context, (void*)cstring, strlen(cstring));
}
long connection_receive(connection_context* context, unsigned char* data,
                        unsigned int buffer_size) {
    long max_read = buffer_size - 1;
    long received = 0;

    while (received < max_read) {
        printf("now reading\n");
        long bytes_read =
            read(context->_socket_handle, data + received, max_read - received);
        printf("blob read with bytes %ld\n", bytes_read);
        if (bytes_read < 0) {
            fprintf(stderr, "Error: could not receive blob from socket");
        } else if (bytes_read == 0) {
            break;
        }
        received += bytes_read;
    }

    if (received == max_read) {
        fprintf(stderr, "Error: response too large for the buffer allocated to "
                        "connection_receive");
    }
    return received;
}

char* connection_receive_string(connection_context* context) {
    // alloc
    char* buf = calloc(1, 8192);
    long size = connection_receive(context, (void*)buf, 8192 - 1);
    printf("%ld \n", size);
    buf[size + 1] = '\0';
    return buf;
}

bool connection_close_and_free(connection_context* context) {
    int returncode = close(context->_socket_handle);
    if (returncode < 0) {
        int errsv = errno;
        fprintf(stderr, "Error: could not close socket. Error code %d: %s.\n",
                errsv, strerror(errsv));
        return false;
    }
    return true;
}

// enc should be a zero'd buffer at least 3n+1 times the size of the input data.
char* url_encode(const unsigned char* data, const unsigned int size,
                 char* enc) {

    for (int i = 0; i < size; i++) {
        char c = data[i];
        if (isalnum(c) || c == '*' || c == '-' || c == '.' || c == '_') {
            *enc = c;
        } else if (c == ' ') {
            *enc = '+';
        } else {
            sprintf(enc, "%%%02X", c);
        }
        while (*++enc)
            ;
    }
    return enc;
};

request_context* get_request_context(request_verb verb, char* url) {

    request_context* ctx = malloc(sizeof(request_context));
    ctx->verb = verb;
    // TODO split the URL in host and path;
    ctx->host = url;
    ctx->path = url;
    ctx->params = malloc(sizeof(query_param*));
    ctx->params_size = 0;

    return ctx;
}

void add_request_param(request_context* req, const char* key,
                       const char* value) {
    req->params =
        realloc(req->params, (req->params_size + 1) * sizeof(query_param));
    req->params[req->params_size].key = key;
    req->params[req->params_size].value = value;
    req->params_size++;
}

bool http1_get(request_context* req, char* response_buffer,
               unsigned int response_buffer_size) {

    // STEP 1. use DNS lookup (via netdb.h) to get a valid server IP for the
    // host string.

    // TODO gethostbyname is deprecated in favour of getaddrinfo, but this
    // requires a rewrite of the low level socket stuff above.
    struct hostent* server = gethostbyname(
        req->host); // overwritable static data, doesnt need freeing
    if (server == NULL) {
        int errsv = h_errno;
        fprintf(stderr, "Error: host %s not found. Error code %d: %s.\n",
                req->host, errsv, strerror(errsv));
        return false;
    }

    struct in_addr* first_addr =
        (struct in_addr*)
            server->h_addr_list[0]; // i think this always has at least one ip
                                    // if the step above doesn't error

    // STEP 2. Setup TCP socket

    connection_context http_context = {
        .adress = req->host, // not a valid server ip, but we use
                             // connection_init_override_ip
        .port = 80};

    connection_init_override_ip(&http_context, first_addr);
    connection_connect(&http_context);

    // STEP 3. FORMAT AND SEND REQUEST

    char query_string[1024] = {0}; // TODO this might be too small

    strcat(query_string, req->path);

    for (int i = 0; i < req->params_size; i++) {
        if (i == 0) {
            strcat(query_string, "?");
        }
        strcat(query_string, req->params[i].key);
        strcat(query_string, "=");
        strcat(query_string, req->params[i].value);
        if (!(i == req->params_size - 1)) {
            strcat(query_string, "&");
        }
    }

    const char* get_format = "GET /%s HTTP/1.0\r\n\r\n";
    char msg[4096];

    sprintf(msg, get_format, query_string);

    printf("We will send the following message: \n%s\n", msg);
    exit(1);
    connection_send_string(&http_context, msg);

    // STEP 4. RECEIVE REQUEST
    char* resp = connection_receive_string(&http_context);
    printf("%s\n", resp);

    free(resp);

    connection_close_and_free(&http_context);
    return true;
}

bool execute_request(request_context* req, char* response_buffer,
                     unsigned int response_buffer_size) {
    switch (req->verb) {
    case GET: {
        return http1_get(req, response_buffer, response_buffer_size);
        break;
    }
    case POST:
        break;
    }

    return false;
}

bool network_tests(void) {
    // tests url url_encode
    char* data = "s p a c e";
    char* enc_data = calloc(3 * strlen(data) + 1, 1);
    url_encode(data, strlen(data), enc_data);

    assert(!strcmp(enc_data, "s+p+a+c+e"));
    free(enc_data);

    data = "(lmao)!";
    enc_data = calloc(3 * strlen(data) + 1, 1);
    url_encode(data, strlen(data), enc_data);

    assert(!strcmp(enc_data, "%28lmao%29%21"));
    free(enc_data);

    request_context* test_context = get_request_context(GET, "example.com");
    add_request_param(test_context, "lmao", "5");
    add_request_param(test_context, "indeed", "96");

    execute_request(test_context, (void*)NULL, 0);
    return true;
}
