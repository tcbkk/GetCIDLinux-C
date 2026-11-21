/* reverse.h */
#ifndef REVERSE_H
#define REVERSE_H
#include <stddef.h>
/* IID → (产品名, PID, groupID, keyAddress)。移植自 CIDPlugin/ReverseIID.cs */
void reverse_key_data(const char *iid, char *name, size_t name_n,
                      char *pid, size_t pid_n, int *group_id, int *key_address);
#endif
