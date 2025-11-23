#ifndef CLEARANCE_TOKEN_H
#define CLEARANCE_TOKEN_H

#include <stddef.h>

char *generate_clearance_token(const char *ip, const char *ua, const char *secret);
int verify_clearance_token(const char *token, const char *ip, const char *ua, const char *secret, int ttl_sec);
void hexify(const unsigned char *in, size_t len, char *out, size_t outsz);

#endif
