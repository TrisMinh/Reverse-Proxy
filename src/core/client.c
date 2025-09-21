#include "client.h"
#include "logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

int connect_to_backend(const char *host, int port, SOCKET *backend_fd) {
    *backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*backend_fd == INVALID_SOCKET) {
        log_message("ERROR","Create backend socket failed");
        return -1;
    }

    struct sockaddr_in addr;
    struct hostent *he = gethostbyname(host);
    if (he == NULL) {
        log_message("ERROR","DNS lookup failed");
        closesocket(*backend_fd);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);


    if (connect(*backend_fd,(struct sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR) {
        log_message("ERROR","Connect backend failed");
        closesocket(*backend_fd);
        return -1;
    }

    return 0;
}
