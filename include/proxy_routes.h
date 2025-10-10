#ifndef PROXY_ROUTES_H
#define PROXY_ROUTES_H

typedef struct ProxyRoute {
    char domain[256];
    char backend_host[256];
    int  backend_port;
    int  is_https;
    int  port_specified;
} ProxyRoute;

int load_proxy_routes(const char *filename);
const ProxyRoute* find_proxy_routes(const char *domain);

#endif
