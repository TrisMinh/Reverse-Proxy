#ifndef ACL_FILTER_H
#define ACL_FILTER_H

#include "ipset.h"
#include "filter_chain.h"

void acl_init(const char *file);
void acl_reload(const char *file);
void acl_add(const char *ip);
void acl_remove(const char *ip);   // nếu muốn bỏ chặn sau
FilterResult acl_filter(FilterContext *ctx);

#endif
