#ifndef CAPTCHA_FILTER_H
#define CAPTCHA_FILTER_H

#include "filter_chain.h"

void set_captcha_config(const char *center_url, const char *secret_key, const char *recaptcha_key, const char *callback_path, int state_ttl, int pass_ttl);
FilterResult captcha_filter(FilterContext *ctx);

#endif
