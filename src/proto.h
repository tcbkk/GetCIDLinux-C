/* proto.h */
#ifndef PROTO_H
#define PROTO_H
#include <stddef.h>
char *proto_encrypt(const char *plain, char *out, size_t outn);
int   proto_decrypt(const char *b64, char *out, size_t outn);
#endif
