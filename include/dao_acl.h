#ifndef DAO_IPDB_H
#define DAO_IPDB_H

#include "ipset.h"

int dao_acl_add(const char *ip);
int dao_acl_exists(const char *ip);
int dao_acl_remove(const char *ip);
int dao_acl_load_all(ipset_t *s);

#endif
