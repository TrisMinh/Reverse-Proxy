#include "clearance_token.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

void hexify(const unsigned char *in, size_t len, char *out, size_t outsz) {
    static const char *H = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < len && j + 2 < outsz; ++i) {
        out[j++] = H[(in[i] >> 4) & 0xF];
        out[j++] = H[in[i] & 0xF];
    }
    if (j < outsz) out[j] = '\0';
}

static void build_client_hash(const char *ip, const char *ua, const char *secret, char *out_hex, size_t outsz) {
    char buf[512];
    const char *ua_norm = ua ? ua : "";
    char ua_trim[128];
    snprintf(ua_trim, sizeof(ua_trim), "%.100s", ua_norm);

    snprintf(buf, sizeof(buf), "%s|%s", ip ? ip : "", ua_trim);

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char*)buf, (unsigned int)strlen(buf), mac, &mac_len);

    hexify(mac, mac_len, out_hex, outsz);
}


char *generate_clearance_token(const char *ip, const char *ua, const char *secret) {
    if (!secret) return NULL;

    unsigned ts = (unsigned)time(NULL);
    char chash[65];
    build_client_hash(ip, ua, secret, chash, sizeof(chash));

    char src[128];
    snprintf(src, sizeof(src), "%u|%s", ts, chash);

    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int sig_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char*)src, (unsigned int)strlen(src), sig, &sig_len);

    char sig_hex[65];
    hexify(sig, sig_len, sig_hex, sizeof(sig_hex));

    char *out = malloc(256);
    if (!out) return NULL;
    snprintf(out, 256, "%u|%s|%s", ts, chash, sig_hex);
    return out;
}

static int hex_equals(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    return CRYPTO_memcmp(a, b, la) == 0;
}

int verify_clearance_token(const char *token, const char *ip, const char *ua, const char *secret, int ttl_sec) {
    if (!token || !secret) return 0;

    unsigned ts = 0;
    char chash[65], sig[65];
    if (sscanf(token, "%u|%64[^|]|%64s", &ts, chash, sig) != 3) return 0;

    unsigned now = (unsigned)time(NULL);
    if (now < ts || now - ts > (unsigned)ttl_sec) return 0;

    char expected_chash[65];
    build_client_hash(ip, ua, secret, expected_chash, sizeof(expected_chash));
    if (!hex_equals(expected_chash, chash)) return 0;

    char src[128];
    snprintf(src, sizeof(src), "%u|%s", ts, chash);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char*)src, (unsigned int)strlen(src), mac, &mac_len);

    char mac_hex[65];
    hexify(mac, mac_len, mac_hex, sizeof(mac_hex));

    return hex_equals(sig, mac_hex);
}
