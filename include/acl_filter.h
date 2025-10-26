#ifndef ACL_FILTER_H
#define ACL_FILTER_H

#include "filter_chain.h"
#include "ipset.h"

void acl_init();
void acl_reload();
void acl_add(const char *ip);
void acl_remove(const char *ip);   // nếu muốn bỏ chặn sau
FilterResult acl_filter(FilterContext *ctx);

#endif
