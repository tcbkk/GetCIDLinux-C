#ifndef B64_H
#define B64_H
#include <stddef.h>
char *b64_encode(const unsigned char *in, size_t n, char *out);
int   b64_decode(const char *in, unsigned char *out, size_t outn);
char *b64url_encode(const unsigned char *in, size_t n, char *out);
int   url_escape(const char *in, char *out, size_t outn);
#endif
