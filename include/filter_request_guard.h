#ifndef FILTER_REQUEST_GUARD_H
#define FILTER_REQUEST_GUARD_H
#include "filter_chain.h"

void frg_set_header_limit(int bytes);
void frg_set_body_limit(long long bytes);
int  validate_http_request(const char *request);

typedef struct {
    long long limit;
    long long seen;
} frg_body_counter;

int frg_body_counter_init(frg_body_counter *c, long long limit_override, const char *req_buf, int total_read, int *initial_body_inbuf);

int frg_body_counter_add(frg_body_counter *c, size_t nbytes);

FilterResult frg_chain_validate(FilterContext *ctx);

#endif
