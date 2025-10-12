#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H
#include "filter_chain.h"

typedef struct rl_entry_s {
    char ip[64];
    double tokens;
    double burst;
    uint64_t last_ms;
    struct rl_entry_s *next;
} rl_entry_t;

void rate_limit_init(void);
void rate_limit_shutdown(void);

FilterResult rate_limit_filter(FilterContext *ctx);


#endif /* RATE_LIMIT_H */
