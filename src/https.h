/* https.h */
#ifndef HTTPS_H
#define HTTPS_H
#include "common.h"
/* HTTPS POST（BearSSL，证书校验用内置锚点）。resp 收完整 body（含 NUL）。返回 0 成功。 */
int https_post(const char *url, const char *headers, const char *body, size_t bodyn,
               char *resp, size_t respn, int *status_out);
int https_post_inner(const char *url, const char *headers, const char *body, size_t bodyn,
                     char *resp, size_t respn, int *status_out);
/* 系统 curl 路径（找不到返回 NULL）；mslogin.c 网页登录流程用 */
const char *https_curl_path(void);
#endif
