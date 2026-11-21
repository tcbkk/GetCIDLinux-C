/* msft.h */
#ifndef MSFT_H
#define MSFT_H
#include "common.h"

/* token 管理器（多实例：每个实例一个 token_manager，管理各自的 vs_tokens 文件） */
typedef struct {
    token_info tok;
    pthread_mutex_t mu;
    int broken;
    char dead_reason[256];
    char path[256];
    char name[64];      /* 实例名，用于日志前缀区分 */
    /* 换票该带哪种 Origin 头：0=Origin+Referer（密码登录拿到的 SPA token）
       1=不带 Origin（设备码登录拿到的 Web token）2=仅 Origin；tm_refresh 会自己纠正 */
    int hdr_variant;
} token_manager;

void  tm_init(token_manager *tm, const char *path, const char *name);
/* 改实例名 / 改服务器地址后重新绑定 token 文件（不重建锁、不清线程正在用的结构） */
void  tm_rebind(token_manager *tm, const char *path, const char *name);
int   tm_load(token_manager *tm);
int   tm_healthy(token_manager *tm);
int   tm_is_broken(token_manager *tm);
const char *tm_dead_reason(token_manager *tm);
int   tm_refresh(token_manager *tm);
int   tm_apply_tokens(token_manager *tm, const char *resp_json, char *account, size_t an);
void *tm_refresh_loop(void *arg);   /* arg = token_manager* */
int   tm_get_id_token(token_manager *tm, char *id_token, size_t idn, char *user_id, size_t un);
/* 网页展示辅助：token 状态 ok/expired/rejected/none + 到期时间(MM-DD HH:MM) + 账号 */
const char *tm_state_text(token_manager *tm);
void  tm_expires_h(token_manager *tm, char *out, size_t n);
void  tm_left_h(token_manager *tm, char *out, size_t n);
void  tm_account_hint(token_manager *tm, char *out, size_t n);
void  tm_logout(token_manager *tm);
char *dpop_token(const char *method, const char *url, const char *bearer);
cid_result fetch_cid(const char *iid, const char *id_token, const char *user_id, int lang);
#endif
