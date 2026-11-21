/* devlogin.c - OAuth 设备码登录 + 密钥(refresh_token)登录
   移植自 Rust 版 login.rs（对齐 Go 版 CIDRouter/login.go 的设备码流程）。
   设备码流程的好处：密码 / 2FA / 验证器验证全在浏览器里完成，客户端只拿 code 轮询 token，
   所以带 2FA 的账号也能用这条路，不需要在客户端实现 TOTP 输入。 */
#include "common.h"
#include "app.h"
#include "config.h"
#include "https.h"
#include "msft.h"
#include "b64.h"
#include "devlogin.h"

#define DEVC_URL   "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
#define DEV_SCOPE  "openid profile offline_access"

/* 设备码授权类型（必须整串 url_escape） */
#define DEV_GRANT  "urn:ietf:params:oauth:grant-type:device_code"

static int dev_http_post(const char *url, const char *body, char *resp, size_t rn, int *st) {
    char headers[512];
    snprintf(headers, sizeof headers,
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Origin: https://visualsupport.microsoft.com\r\n"
             "Referer: https://visualsupport.microsoft.com/\r\n");
    return https_post(url, headers, body, strlen(body), resp, rn, st);
}

static void dev_set(app_state *a, int status, const char *code, const char *url,
                    const char *msg, long deadline) {
    pthread_mutex_lock(&a->dev_mu);
    a->dev_status = status;
    if (code) snprintf(a->dev_code, sizeof a->dev_code, "%s", code);
    if (url) snprintf(a->dev_url, sizeof a->dev_url, "%s", url);
    if (msg) snprintf(a->dev_msg, sizeof a->dev_msg, "%s", msg);
    a->dev_deadline = deadline;
    pthread_mutex_unlock(&a->dev_mu);
}

void devlogin_reset(app_state *a) {
    pthread_mutex_lock(&a->dev_mu);
    a->dev_status = 0;
    a->dev_code[0] = 0;
    a->dev_msg[0] = 0;
    a->dev_deadline = 0;
    pthread_mutex_unlock(&a->dev_mu);
}

void devlogin_info(app_state *a, int *status, char *code, size_t cn,
                   char *url, size_t un, int *left, char *msg, size_t mn) {
    pthread_mutex_lock(&a->dev_mu);
    if (status) *status = a->dev_status;
    if (code) snprintf(code, cn, "%s", a->dev_code);
    if (url) snprintf(url, un, "%s", a->dev_url);
    if (msg) snprintf(msg, mn, "%s", a->dev_msg);
    if (left) {
        long now = (long)time(NULL);
        *left = (a->dev_status == 1 && a->dev_deadline > now)
                    ? (int)(a->dev_deadline - now) : -1;
    }
    pthread_mutex_unlock(&a->dev_mu);
}

/* ---------------- 轮询 ---------------- */

typedef struct {
    app_state *a;
    /* 微软的 device_code 是很长的 base64url 串（实测 1000+ 字符），
       缓冲区给足 —— 截断会被 token 端点判 AADSTS7000014 "device_code is not valid" */
    char device_code[2560];
    int  interval;
    long deadline;
} dev_job;

/* token 端点返回 200 → 落盘 + 上报状态；其他按 error 字段决定继续/放弃 */
static int dev_apply(app_state *a, const char *resp) {
    char acct[128] = "";
    int rc = tm_apply_tokens(&a->tm, resp, acct, sizeof acct);
    if (rc != 0) {
        char msg[256];
        snprintf(msg, sizeof msg, rc == -2 ? "token 里没有 puid（换取结果异常）"
                                           : "token 保存失败（写盘失败或响应缺字段）");
        dev_set(a, 3, NULL, NULL, msg, 0);
        log_err("[设备码:%s] %s", a->cfg.client_name, msg);
        return -1;
    }
    if (acct[0]) snprintf(a->cfg.account, sizeof a->cfg.account, "%s", acct);
    {
        char left[64];
        tm_left_h(&a->tm, left, sizeof left);
        log_print("[设备码:%s] 登录成功 account=%s（token %s，已写入 %s）",
                  a->cfg.client_name, acct, left, a->cfg.token_file);
    }
    dev_set(a, 2, NULL, NULL, "登录成功，token 已保存", 0);
    config_save();
    app_send_status_report(a);
    return 0;
}

static void *dev_poll_thread(void *arg) {
    dev_job *j = arg;
    app_state *a = j->a;
    log_set_instance_log(a->cfg.log_file);
    char ertype[256], edc[6144];
    url_escape(DEV_GRANT, ertype, sizeof ertype);
    while (g_stop == 0) {
        if ((long)time(NULL) >= j->deadline) {
            log_err("[设备码:%s] 验证码已过期，请重新获取", a->cfg.client_name);
            dev_set(a, 3, NULL, NULL, "验证码已过期，请重新获取", 0);
            break;
        }
        sleep(j->interval);
        if (!a->want_run && a->dev_status != 1) break;
        url_escape(j->device_code, edc, sizeof edc);
        char body[7168];
        snprintf(body, sizeof body,
                 "client_id=%s&grant_type=%s&device_code=%s", SPA_CLIENT_ID, ertype, edc);
        char resp[16384];
        int st = 0;
        if (dev_http_post(TOKEN_URL, body, resp, sizeof resp, &st) != 0) continue;  /* 网络抖动 */
        if (st == 200) {
            if (dev_apply(a, resp) == 0)
                a->tm.hdr_variant = 1;   /* 设备码签的是 Web 型 token：换票先试「不带 Origin」 */
            break;
        }
        char err[128] = "";
        parse_json_str(resp, "error", err, sizeof err);
        if (strcmp(err, "authorization_pending") == 0) continue;
        if (strcmp(err, "slow_down") == 0) { j->interval += 5; continue; }
        if (strcmp(err, "expired_token") == 0) {
            log_err("[设备码:%s] 验证码已过期，请重新获取", a->cfg.client_name);
            dev_set(a, 3, NULL, NULL, "验证码已过期，请重新获取", 0);
            break;
        }
        if (strcmp(err, "authorization_declined") == 0) {
            log_err("[设备码:%s] 登录被拒绝（浏览器里点了取消）", a->cfg.client_name);
            dev_set(a, 3, NULL, NULL, "登录被拒绝（浏览器里点了取消）", 0);
            break;
        }
        {
            char amsg[256] = "";
            log_err("[设备码:%s] 登录失败 %s %.200s", a->cfg.client_name, err, resp);
            if (parse_json_str(resp, "error_description", amsg, sizeof amsg) != 0 || !amsg[0])
                snprintf(amsg, sizeof amsg, "登录失败（%.100s）", resp);
            dev_set(a, 3, NULL, NULL, amsg, 0);
        }
        break;
    }
    pthread_mutex_lock(&a->dev_mu);
    a->dev_polling = 0;
    pthread_mutex_unlock(&a->dev_mu);
    log_set_instance_log("");
    free(j);
    return NULL;
}

int devlogin_start(app_state *a) {
    /* 已有未过期的等待会话就复用，避免刷出一堆验证码 */
    int status = 0, left = -1;
    devlogin_info(a, &status, NULL, 0, NULL, 0, &left, NULL, 0);
    if (status == 1 && left > 10) return 0;
    if (status == 1) devlogin_reset(a);

    dev_set(a, 1, "", "", "正在向微软申请登录码…", 0);

    char escope[128];
    url_escape(DEV_SCOPE, escope, sizeof escope);
    char body[512];
    snprintf(body, sizeof body, "client_id=%s&scope=%s", SPA_CLIENT_ID, escope);
    char resp[16384];
    int st = 0;
    if (dev_http_post(DEVC_URL, body, resp, sizeof resp, &st) != 0) {
        dev_set(a, 3, NULL, NULL, "申请登录码失败：网络请求失败", 0);
        log_err("[设备码:%s] 申请登录码失败（网络）", a->cfg.client_name);
        return -1;
    }
    if (st != 200) {
        char amsg[256] = "";
        parse_json_str(resp, "error_description", amsg, sizeof amsg);
        if (!amsg[0]) snprintf(amsg, sizeof amsg, "HTTP %d", st);
        char m[320];
        snprintf(m, sizeof m, "申请登录码失败：%.240s", amsg);
        dev_set(a, 3, NULL, NULL, m, 0);
        log_err("[设备码:%s] %s", a->cfg.client_name, m);
        return -1;
    }
    char dcode[2560] = "", ucode[64] = "", vurl[256] = "";
    parse_json_str(resp, "device_code", dcode, sizeof dcode);
    parse_json_str(resp, "user_code", ucode, sizeof ucode);
    parse_json_str(resp, "verification_uri", vurl, sizeof vurl);
    int expires_in = parse_json_int(resp, "expires_in", 900);
    int interval = parse_json_int(resp, "interval", 5);
    if (interval < 3) interval = 3;
    if (!dcode[0] || !ucode[0]) {
        dev_set(a, 3, NULL, NULL, "申请登录码失败：响应无法解析", 0);
        log_err("[设备码:%s] 申请登录码失败：响应无法解析 %.160s", a->cfg.client_name, resp);
        return -1;
    }
    if (!vurl[0]) snprintf(vurl, sizeof vurl, "https://microsoft.com/devicelogin");

    long deadline = (long)time(NULL) + expires_in;
    dev_set(a, 1, ucode, vurl, "请在浏览器打开链接并输入这个代码，完成后这里会自动更新", deadline);
    log_print("[设备码:%s] 代码 %s，有效期 %d 秒，地址 %s",
              a->cfg.client_name, ucode, expires_in, vurl);

    dev_job *j = calloc(1, sizeof *j);
    if (!j) { dev_set(a, 3, NULL, NULL, "内存不足", 0); return -1; }
    j->a = a;
    snprintf(j->device_code, sizeof j->device_code, "%s", dcode);
    j->interval = interval;
    j->deadline = deadline;
    a->dev_polling = 1;
    pthread_t th;
    thread_spawn(&th, dev_poll_thread, j);
    pthread_detach(th);
    return 0;
}

/* ---------------- 密钥登录 ---------------- */

int devlogin_key(app_state *a, const char *refresh_token) {
    char rt[2048];
    snprintf(rt, sizeof rt, "%s", refresh_token ? refresh_token : "");
    /* 去掉粘贴时带进来的空白/换行 */
    size_t o = 0;
    for (const char *p = rt; *p && o + 1 < sizeof rt; p++)
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') rt[o++] = *p;
    rt[o] = 0;
    if (!rt[0]) { dev_set(a, 3, NULL, NULL, "refresh_token 不能为空", 0); return -1; }

    char ert[2600], escope[128], body[4096];
    url_escape(rt, ert, sizeof ert);
    url_escape(DEV_SCOPE, escope, sizeof escope);
    snprintf(body, sizeof body,
             "client_id=%s&grant_type=refresh_token&refresh_token=%s&scope=%s",
             SPA_CLIENT_ID, ert, escope);
    char resp[16384];
    int st = 0;
    if (dev_http_post(TOKEN_URL, body, resp, sizeof resp, &st) != 0) {
        dev_set(a, 3, NULL, NULL, "密钥登录失败：网络请求失败", 0);
        return -1;
    }
    if (st != 200) {
        char err[128] = "", desc[512] = "";
        parse_json_str(resp, "error", err, sizeof err);
        parse_json_str(resp, "error_description", desc, sizeof desc);
        char m[400];
        if (strstr(err, "invalid_grant") || strstr(desc, "AADSTS70000"))
            snprintf(m, sizeof m, "refresh_token 无效或已过期（invalid_grant）");
        else
            snprintf(m, sizeof m, "密钥登录失败 HTTP %d：%.200s", st, desc[0] ? desc : err);
        dev_set(a, 3, NULL, NULL, m, 0);
        log_err("[密钥:%s] %s", a->cfg.client_name, m);
        return -1;
    }
    if (dev_apply(a, resp) != 0) return -1;
    dev_set(a, 2, NULL, NULL, "密钥登录成功，token 已保存", 0);
    return 0;
}
