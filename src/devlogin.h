/* devlogin.h - OAuth 设备码登录 + 密钥(refresh_token)登录（移植自 Rust 版 login.rs） */
#ifndef DEVLOGIN_H
#define DEVLOGIN_H
#include "common.h"
#include "app.h"

/* 申请设备码：成功后 a->dev_code / a->dev_url 有值，后台线程每 interval 秒轮询一次 token 端点。
   返回 0 = 已开始（或已有未过期的等待会话）；-1 = 失败（原因在 a->dev_msg）。 */
int devlogin_start(app_state *a);

/* 密钥登录：拿 refresh_token 换一整套 token 并落盘。返回 0 成功 / -1 失败（原因 a->dev_msg） */
int devlogin_key(app_state *a, const char *refresh_token);

/* GUI 取设备码状态：left = 剩余秒数（-1 表示不在等待）；code/url 可能为空 */
void devlogin_info(app_state *a, int *status, char *code, size_t cn,
                   char *url, size_t un, int *left, char *msg, size_t mn);

/* 清掉等待状态（登录成功/失败后 GUI 收起提示条） */
void devlogin_reset(app_state *a);
#endif
