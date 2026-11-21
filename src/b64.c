/* b64.c - base64 / base64url */
#include "common.h"
#include "b64.h"

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const unsigned char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64[v & 63] : '=';
    }
    out[o] = 0;
    return out;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64_decode(const char *in, unsigned char *out, size_t outn) {
    size_t o = 0;
    unsigned acc = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r') continue;
        int v = b64val(*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outn) return -1;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return (int)o;
}

char *b64url_encode(const unsigned char *in, size_t n, char *out) {
    b64_encode(in, n, out);
    for (char *p = out; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = 0; break; }
    }
    return out;
}

int url_escape(const char *in, char *out, size_t outn) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            if (o + 2 >= outn) return -1;
            out[o++] = *p;
        } else {
            if (o + 4 >= outn) return -1;
            o += (size_t)snprintf(out + o, outn - o, "%%%02X", *p);
        }
    }
    out[o] = 0;
    return (int)o;
}
