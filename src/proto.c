/* proto.c - AES-256-CBC(b64) 信封 + ClientMessage 组装（与 Go/C# 版互通）
   Windows 版：AES 用 BCrypt（见 win_aes.c），不再依赖 BearSSL。 */
#include "common.h"
#include "b64.h"
#include "proto.h"

static pthread_mutex_t proto_mu = PTHREAD_MUTEX_INITIALIZER;

/* PKCS7 填充 + CBC 加密 + base64 */
char *proto_encrypt(const char *plain, char *out, size_t outn) {
    size_t plen = strlen(plain);
    size_t pad = 16 - (plen % 16);
    size_t total = plen + pad;
    unsigned char *data = malloc(total);
    unsigned char *enc = malloc(total);
    if (!data || !enc) { free(data); free(enc); return NULL; }
    memcpy(data, plain, plen);
    memset(data + plen, (int)pad, pad);
    int rc = aes_cbc_crypt(1, (const unsigned char *)AES_IV, data, total, enc);
    free(data);
    if (rc <= 0) { free(enc); return NULL; }
    if (total * 4 / 3 + 8 >= outn) { free(enc); return NULL; }
    pthread_mutex_lock(&proto_mu);
    b64_encode(enc, total, out);
    pthread_mutex_unlock(&proto_mu);
    free(enc);
    return out;
}

/* base64 解密 + 去 PKCS7/零尾 */
int proto_decrypt(const char *b64, char *out, size_t outn) {
    static unsigned char raw[262144];
    static unsigned char plain[262144];
    int end = -1;
    pthread_mutex_lock(&proto_mu);
    int n = b64_decode(b64, raw, sizeof raw);
    if (n <= 0 || n % 16 != 0) { pthread_mutex_unlock(&proto_mu); return -1; }
    int rc = aes_cbc_crypt(0, (const unsigned char *)AES_IV, raw, (size_t)n, plain);
    if (rc <= 0) { pthread_mutex_unlock(&proto_mu); return -1; }
    int e = n;
    unsigned char pad = plain[n - 1];
    if (pad > 0 && pad <= 16) {
        int ok = 1;
        for (int i = n - pad; i < n; i++) if (plain[i] != pad) { ok = 0; break; }
        if (ok) e = n - pad;
    }
    for (int i = 0; i < e; i++) if (plain[i] == 0) { e = i; break; }
    if ((size_t)e >= outn) e = (int)outn - 1;
    memcpy(out, plain, (size_t)e);
    out[e] = 0;
    end = e;
    pthread_mutex_unlock(&proto_mu);
    return end;
}
