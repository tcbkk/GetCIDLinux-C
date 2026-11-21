/* aes.c - AES-256-CBC（OpenSSL EVP 实现）
   与 Windows 版语义一致：不做 padding，len 必须是 16 的倍数，输出长度等于输入长度。 */
#include "common.h"

int aes_cbc_crypt(int encrypt, const unsigned char *iv,
                  const unsigned char *in, size_t len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char keybuf[32];
    unsigned char ivbuf[16];
    int outl = 0, total = 0;
    int rc = -1;

    if (!in || !out || !iv) return -1;
    if (len == 0 || (len % 16) != 0) return -1;

    /* AES_KEY 是 32 字节字符串常量 */
    memcpy(keybuf, AES_KEY, 32);
    memcpy(ivbuf, iv, 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keybuf, ivbuf) != 1) goto done;
    } else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keybuf, ivbuf) != 1) goto done;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (encrypt) {
        if (EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1) goto done;
        total = outl;
        if (EVP_EncryptFinal_ex(ctx, out + total, &outl) != 1) goto done;
        total += outl;
    } else {
        if (EVP_DecryptUpdate(ctx, out, &outl, in, (int)len) != 1) goto done;
        total = outl;
        if (EVP_DecryptFinal_ex(ctx, out + total, &outl) != 1) goto done;
        total += outl;
    }
    rc = total;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rc;
}
