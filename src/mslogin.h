/* mslogin.h - 微软「账号密码 + 邮箱验证码」网页登录流程（移植自 Go 版 mslogin.go / relogin.go）
   微软对个人账号（MSA）关闭了 ROPC，唯一可行的是照浏览器做法走完整网页登录流程。 */
#ifndef MSLOGIN_H
#define MSLOGIN_H
#include "common.h"
#include "app.h"

/* 第一步：账号密码登录。
   返回 0 = 登录完成（token 已写入该实例的 token 文件）
        1 = 微软要求邮箱验证码（等人工，need_code=1，masked 为掩码邮箱）
       -1 = 失败（errbuf 带原因；*transient 置 1 表示网络类可短退避重试）
   account/password 为空时沿用实例配置里保存的。
   自动重登（auto_login=1）不会打断正在等人工的会话。 */
int ms_pwd_login(app_state *a, const char *account, const char *password, int auto_login,
                 int *need_code, char *masked, size_t mn,
                 char *msg, size_t msgn, char *errbuf, size_t en, int *transient);

/* 第二步：人工提交「收件邮箱」或「6 位验证码」。
   返回 0 = 成功；*sent=1 表示刚发了一封码（等下一次填 6 位码），
              *sent=0 表示登录完成、token 已落盘；
       -1 = 失败（errbuf 带原因）。
   发码只能由人工触发，一次输入只发一封。 */
int ms_verify(app_state *a, const char *input, int *sent, char *msg, size_t msgn,
              char *errbuf, size_t en);

/* 是否有正在等人工（邮箱/验证码）的登录会话 */
int ms_has_pending(app_state *a);

/* 启动自动重登线程（account 模式每实例一个；cfg_path 用于每次读最新配置） */
void ms_start_relogin(app_state *apps, int ninst, const char *cfg_path);
#endif
