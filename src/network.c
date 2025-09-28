#include "defines.h"
#include "network.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char* url_encode_bytes(const u8* data, usize length) {
    // worst-case expansion: 3 characters per input byte, plus NUL
    usize max_size = 3 * length + 1;

    char* enc = calloc(max_size, 1);
    if (enc == null) return null;

    char* out = enc;

    for (usize i = 0; i < length; i++) {
        u8 c = data[i];

        if (isalnum(c) || c == '*' || c == '-' || c == '.' || c == '_') {
            *out++ = (char)c;
        } else if (c == ' ') {
            *out++ = '+';
        } else {
            sprintf(out, "%%%02X", c);
            out += 3;
        }
    }

    *out = '\0';
    return enc;
}

char* url_encode_string(const char* cstring) {
    return url_encode_bytes((const u8*)cstring, strlen(cstring));
}

url* url_parse(const char* url_str) {
    if (url_str == null) return null;

    url* parsed = calloc(1, sizeof(url));
    if (parsed == null) return null;

    // Defaults
    strcpy(parsed->scheme, "http");
    strcpy(parsed->path, "/");
    parsed->port = 80;

    // Parse scheme
    const char* p = strstr(url_str, "://");
    if (!p) {
        fprintf(stderr, "Error: Cannot parse url %s, missing scheme\n", url_str);
        free(parsed);
        return null;
    }

    usize scheme_len = p - url_str;
    if (scheme_len >= sizeof(parsed->scheme)) {
        fprintf(stderr, "Error: Cannot parse url %s, scheme too long\n", url_str);
        free(parsed);
        return null;
    }

    strncpy(parsed->scheme, url_str, scheme_len);
    parsed->scheme[scheme_len] = '\0';
    p += 3; // skip "://"

    // Parse host (stop at ':' for port or '/' for path or end of string)
    const char* q = p;
    while (*q && *q != ':' && *q != '/') q++;

    usize host_len = q - p;
    if (host_len == 0 || host_len >= sizeof(parsed->host)) {
        fprintf(stderr, "Error: Cannot parse url %s, invalid host\n", url_str);
        free(parsed);
        return null;
    }

    strncpy(parsed->host, p, host_len);
    parsed->host[host_len] = '\0';
    p = q;

    // Optional port
    if (*p == ':') {
        p++;
        char* endptr;
        long port = strtol(p, &endptr, 10);
        if (endptr == p || port <= 0 || port > 65535) {
            fprintf(stderr, "Error: Cannot parse url %s, invalid port\n", url_str);
            free(parsed);
            return null;
        }
        parsed->port = (u64)port;
        p = endptr;
    }

    // Optional path
    if (*p == '/') {
        if (strlen(p) >= sizeof(parsed->path)) {
            fprintf(stderr, "Error: Cannot parse url %s, path too long\n", url_str);
            free(parsed);
            return null;
        }
        strcpy(parsed->path, p);
    }

    return parsed;
}



connection_context* connection_init(const char* ip_address, u16 port) {
    connection_context* ctx = malloc(sizeof(connection_context));

    in_addr_t address = inet_addr(ip_address);
    if (address == INADDR_NONE) {
        fprintf(stderr,
                "Error: Could not convert address %s into a valid IP address\n",
                ip_address);
        free(ctx);
        return null;
    }

    ctx->adress = ip_address;
    ctx->port = port;

    ctx->_server_addr.sin_family = AF_INET;
    ctx->_server_addr.sin_addr.s_addr = address;
    ctx->_server_addr.sin_port = htons(port);

    i32 sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        i32 errsv = errno;
        fprintf(stderr,
                "Error: could not initialize socket. Error code %d: %s. "
                "Check address and port and try again\n",
                errsv, strerror(errsv));
        free(ctx);
        return null;
    }

    ctx->_socket_handle = (u32)sock;

    i32 returncode = connect(sock, (void*)(&ctx->_server_addr), sizeof(ctx->_server_addr));
    if (returncode != 0) {
        i32 errsv = errno;
        fprintf(stderr, "Error: could not open socket. Error code %d: %s. " "Is the server available?\n", errsv, strerror(errsv));
        close(sock);
        free(ctx);
        return null;
    }
    return ctx;
}

connection_context* connection_init_from_url(const url* url) {
    connection_context* ctx = malloc(sizeof(connection_context));
    if (ctx == null) {
        fprintf(stderr, "Error: failed to allocate memory for connection context\n");
        return null;
    }

    struct addrinfo hints = {0};
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%llu", (unsigned long long)url->port);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    struct addrinfo *result, *rp;
    i32 s = getaddrinfo(url->host, port_str, &hints, &result);
    if (s != 0) {
        fprintf(stderr,
                "Error: did not find a valid IP address for host %s "
                "getaddrinfo: %s\n",
                url->host, gai_strerror(s));
        free(ctx);
        return null;
    }

    i32 sock = -1;
    for (rp = result; rp != null; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
            memcpy(&ctx->_server_addr, rp->ai_addr, rp->ai_addrlen);
            ctx->_socket_handle = (u32)sock;
            break;
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (sock == -1) {
        fprintf(stderr, "Could not connect to %s:%llu\n", url->host,
                (unsigned long long)url->port);
        free(ctx);
        return null;
    }

    ctx->adress = url->host;
    ctx->port = (u16)url->port; // truncate if > 65535
    return ctx;
}

void connection_send(connection_context* context, u8* data, usize length) {
    usize sent = 0;
    while (sent < length) {
        ssize_t bytes_sent = send(context->_socket_handle, data + sent, length - sent, 0);
        if (bytes_sent < 0) {
            fprintf(stderr, "Error: could not send blob to socket\n");
            break;
        } else if (bytes_sent == 0) {
            break;
        }
        sent += (usize)bytes_sent;
    }
}

void connection_send_string(connection_context* context, const char* cstring) {
    connection_send(context, (u8*)cstring, strlen(cstring));
}

void connection_send_http_get(connection_context* context, url* url, http_url_param* params) {
    char query_string[1024] = {0};
    strcat(query_string, url->path);

    http_url_param* param = params;
    if (param != null) {
        strcat(query_string, "?");
        do {
            strcat(query_string, param->key);
            strcat(query_string, "=");
            strcat(query_string, param->value);
            strcat(query_string, "&");
            param = (http_url_param*)param->next;
        } while (param != null);
        query_string[strlen(query_string) - 1] = '\0'; // remove trailing &
    }

    char msg[8192];
    sprintf(msg, "GET %s HTTP/1.0\r\n\r\n", query_string);

    printf("We will send the following message: \n%s\n to host %s\n", msg, url->host);

    connection_send_string(context, msg);
}

usize connection_receive(connection_context* context, u8* data, usize buffer_size) {
    usize max_read = buffer_size;
    usize received = 0;

    while (received < max_read) {
        ssize_t bytes_read = read(context->_socket_handle, data + received, max_read - received);
        if (bytes_read < 0) {
            fprintf(stderr, "Error: could not receive data from socket\n");
            break;
        } else if (bytes_read == 0) {
            break;
        }
        received += (usize)bytes_read;
    }

    if (received == max_read) {
        fprintf(stderr, "Warning: response too large for the buffer allocated to connection_receive\n");
    }

    return received;
}

char* connection_receive_string(connection_context* context) {
    usize buf_size = 2 << 12; // 8 KB
    char* buf = calloc(1, buf_size);
    if (buf == null) return null;

    usize size = connection_receive(context, (u8*)buf, buf_size - 1);
    buf[size] = '\0';
    return buf;
}

char* connection_receive_http(connection_context* context) {
    return null;
}

void connection_close_and_free(connection_context* context) {
    int returncode = close(context->_socket_handle);
    if (returncode < 0) {
        int errsv = errno;
        fprintf(stderr, "Warning: could not close socket. Error code %d: %s.\n",
                errsv, strerror(errsv));
    }
    free(context);
}

