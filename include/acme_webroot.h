#include <winsock2.h>

int acme_try_handle_with_root(SOCKET client_fd,
                              const char *method,
                              const char *request_path,
                              const char *webroot);

int acme_webroot_write_token_file(const char *webroot,
                                  const char *token,
                                  const char *thumbprint);
