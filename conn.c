#include "conn.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

bool connection_init(connection_context* context){
    context->_server_addr.sin_family = AF_INET;
    context->_server_addr.sin_addr.s_addr = inet_addr(context->adress);
    context->_server_addr.sin_port = htons(context->port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 ){
        int errsv = errno;
        fprintf(stderr, "Error: could not initialize socket. Error code %d: %s. Check address and port and try again\n", errsv, strerror(errsv));
        return false;
    }
    context->_socket_handle = sock;
    return true;
}

bool connection_connect(connection_context* context){
    int returncode = connect(context->_socket_handle,(void*)(&context->_server_addr), sizeof(context->_server_addr));
    if (returncode != 0){
        int errsv = errno;
        fprintf(stderr, "Error: could not open socket. Error code %d: %s. Is the server available?\n", errsv, strerror(errsv));

        return false;
    }
    return true;
}

void connection_send(connection_context* context, unsigned char* data, unsigned int length){
    send(context->_socket_handle, data, length, 0);
}

void connection_send_string(connection_context* context, const char* cstring){
    connection_send(context, (void*) cstring, strlen(cstring));
}
void connection_receive(connection_context* context, unsigned char* data, unsigned int length){
    read(context->_socket_handle, data, length);
}

bool connection_close_and_free(connection_context* context){
    int returncode = close(context->_socket_handle);
    if (returncode < 0){
        int errsv = errno;
        fprintf(stderr, "Error: could not close socket. Error code %d: %s.\n", errsv, strerror(errsv));
    }
    return true;
}