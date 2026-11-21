/* msft.c - token 管理 + DPoP(ES256) + validateIID
   Windows 版：DPoP 用 BCrypt/CNG 生成 P-256 密钥并签名（替代 Linux 版的 BearSSL） */
#include "common.h"
#include "b64.h"
#include "https.h"
#include "reverse.h"
#include "msft.h"

void tm_init(token_manager *tm, const char *path, const char *name) {
    memset(tm, 0, sizeof *tm);
    pthread_mutex_init(&tm->mu, NULL);
    snprintf(tm->path, sizeof tm->path, "%s", path);
    snprintf(tm->name, sizeof tm->name, "%s", name && name[0] ? name : "inst");
}

void tm_rebind(token_manager *tm, const char *path, const char *name) {
    pthread_mutex_lock(&tm->mu);
    if (path) snprintf(tm->path, sizeof tm->path, "%s", path);
    snprintf(tm->name, sizeof tm->name, "%s", (name && name[0]) ? name : "inst");
    memset(&tm->tok, 0, sizeof tm->tok);
    tm->broken = 0;
    tm->dead_reason[0] = 0;
    tm->hdr_variant = 0;
    pthread_mutex_unlock(&tm->mu);
}

static int tm_expiry_ts(const char *iso) {
    if (!iso || !*iso) return 0;
    struct tm t;
    memset(&t, 0, sizeof t);
    if (sscanf(iso, "%d-%d-%dT%d:%d:%d", &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec) != 6) return 0;
    t.tm_year -= 1900;
    t.tm_mon -= 1;
    return (int)timegm(&t);
}

static int token_expired(token_manager *tm) {
    int exp = tm_expiry_ts(tm->tok.expires_at);
    return exp == 0 || exp <= (int)time(NULL);
}

static void id_token_claims(const char *id_token, char *puid, size_t pn,
                            char *username, size_t un);

int tm_load(token_manager *tm) {
    FILE *f = fopen(tm->path, "r");
    if (!f) return -1;
    char buf[16384];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    pthread_mutex_lock(&tm->mu);
    parse_json_str(buf, "access_token", tm->tok.access_token, sizeof tm->tok.access_token);
    parse_json_str(buf, "refresh_token", tm->tok.refresh_token, sizeof tm->tok.refresh_token);
    parse_json_str(buf, "id_token", tm->tok.id_token, sizeof tm->tok.id_token);
    parse_json_str(buf, "expires_at", tm->tok.expires_at, sizeof tm->tok.expires_at);
    parse_json_str(buf, "user_id", tm->tok.user_id, sizeof tm->tok.user_id);
    parse_json_str(buf, "account", tm->tok.account, sizeof tm->tok.account);
    /* C# 版 token 文件用的是 account_username，读进来才能显示邮箱而不是 user_id */
    if (!tm->tok.account[0])
        parse_json_str(buf, "account_username", tm->tok.account, sizeof tm->tok.account);
    pthread_mutex_unlock(&tm->mu);
    return 0;
}

/* 落盘 token。返回 1 成功 / 0 失败——调用方必须检查：
   刷新后微软已作废旧 refresh_token，新值只在内存，写盘失败 = 进程一重启就 invalid_grant。
   （内部不写日志，因为调用点都持有 tm->mu，避免与日志锁交叉） */
static int tm_save(token_manager *tm) {
    char esc_a[8192], esc_r[8192], esc_i[8192], esc_e[128], esc_o[128], esc_s[1024], esc_u[256];
    json_escape(tm->tok.access_token, esc_a, sizeof esc_a);
    json_escape(tm->tok.refresh_token, esc_r, sizeof esc_r);
    json_escape(tm->tok.id_token, esc_i, sizeof esc_i);
    json_escape(tm->tok.expires_at, esc_e, sizeof esc_e);
    json_escape(tm->tok.obtained_at, esc_o, sizeof esc_o);
    json_escape(tm->tok.scope, esc_s, sizeof esc_s);
    json_escape(tm->tok.user_id, esc_u, sizeof esc_u);
    char esc_ac[256];
    json_escape(tm->tok.account, esc_ac, sizeof esc_ac);
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.tmp", tm->path);
    FILE *f = fopen(tmp, "w");
    if (!f) return 0;
    fprintf(f,
        "{\n  \"access_token\": \"%s\",\n  \"refresh_token\": \"%s\",\n  \"id_token\": \"%s\",\n"
        "  \"expires_at\": \"%s\",\n  \"obtained_at\": \"%s\",\n  \"scope\": \"%s\",\n"
        "  \"token_type\": \"Bearer\",\n  \"user_id\": \"%s\",\n  \"account\": \"%s\"\n}\n",
        esc_a, esc_r, esc_i, esc_e, esc_o, esc_s, esc_u, esc_ac);
    if (fclose(f) != 0 || rename(tmp, tm->path) != 0) {
        remove(tmp);
        return 0;
    }
    return 1;
}

int tm_healthy(token_manager *tm) {
    pthread_mutex_lock(&tm->mu);
    int ok = tm->tok.id_token[0] != 0 && !token_expired(tm);
    pthread_mutex_unlock(&tm->mu);
    return ok;
}

int tm_is_broken(token_manager *tm) {
    pthread_mutex_lock(&tm->mu);
    int b = tm->broken;
    pthread_mutex_unlock(&tm->mu);
    return b;
}

const char *tm_dead_reason(token_manager *tm) {
    static char buf[256];
    pthread_mutex_lock(&tm->mu);
    snprintf(buf, sizeof buf, "%s", tm->dead_reason);
    pthread_mutex_unlock(&tm->mu);
    return buf;
}

/* 换票（refresh）失败在这一步踩过两次坑，记一下两种 90023：
   ① 密码登录拿到的 token 是 SPA 客户端签的，换票必须带 Origin，不带就
      AADSTS90023 "Tokens issued for the 'Single-Page Application' client-type should only be
      redeemed via cross-origin requests"；
   ② 设备码登录拿到的 token 是 Web 客户端签的（微软不允许 SPA 客户端走设备码），带 Origin 反而
      AADSTS90023 "Cross-origin token redemption is permitted only for the 'Single-Page Application'
      client-type or 'Native' client-type with origin registered in the app registration"。
   所以三种 header 写法依次试，哪种 200 就记住、下次先试它（Rust 版同样做法）。 */
static const char *HDR_VARIANTS[3] = {
    "Origin: https://visualsupport.microsoft.com\r\nReferer: https://visualsupport.microsoft.com/\r\n",
    "",
    "Origin: https://visualsupport.microsoft.com\r\n"
};
static const char *HDR_NAMES[3] = { "Origin+Referer", "无 Origin", "仅 Origin" };

/* 返回 0 成功。-1 网络错，-2 invalid_grant（人工换 token），-3 其他 */
int tm_refresh(token_manager *tm) {
    pthread_mutex_lock(&tm->mu);
    char rt[2048];
    snprintf(rt, sizeof rt, "%s", tm->tok.refresh_token);
    if (!rt[0]) {
        pthread_mutex_unlock(&tm->mu);
        log_err("[token:%s] refresh_token 为空，请在网页上登录该实例", tm->name);
        return -3;
    }
    char ert[4096], escope[512], body[8192];
    url_escape(rt, ert, sizeof ert);
    url_escape("openid profile offline_access", escope, sizeof escope);
    snprintf(body, sizeof body,
        "client_id=%s&grant_type=refresh_token&refresh_token=%s&scope=%s",
        SPA_CLIENT_ID, ert, escope);
    pthread_mutex_unlock(&tm->mu);

    char resp[16384];
    int status = 0;
    int got = 0, net_err = 0;
    int first = tm->hdr_variant;
    if (first < 0 || first > 2) first = 0;
    for (int k = 0; k < 3 && !got; k++) {
        int v = (first + k) % 3;
        resp[0] = 0;
        status = 0;
        if (http_post(TOKEN_URL, "application/x-www-form-urlencoded", body, HDR_VARIANTS[v],
                      resp, sizeof resp, &status) != 0) {
            log_err("[token:%s] 刷新网络错误（%s）", tm->name, HDR_NAMES[v]);
            net_err = 1;
            continue;
        }
        if (status == 200) {
            if (v != tm->hdr_variant) {
                tm->hdr_variant = v;
                log_print("[token:%s] 换票写法「%s」可用，后续先试它", tm->name, HDR_NAMES[v]);
            }
            got = 1;
            break;
        }
        if (strstr(resp, "invalid_grant") || strstr(resp, "AADSTS70000")) {
            pthread_mutex_lock(&tm->mu);
            tm->broken = 1;
            snprintf(tm->dead_reason, sizeof tm->dead_reason,
                "refresh_token 已失效（invalid_grant），需要重新登录并更新 vs_tokens.json");
            pthread_mutex_unlock(&tm->mu);
            log_err("[token:%s] 刷新 invalid_grant（%s）", tm->name, HDR_NAMES[v]);
            return -2;
        }
        /* 剩下的多半是 90023（Origin 写法不匹配这个 token 的来源），换下一种写法继续 */
        log_err("[token:%s] 刷新 HTTP %d（%s）: %.260s", tm->name, status, HDR_NAMES[v], resp);
    }
    if (!got) return net_err ? -1 : -3;
    char new_at[2048] = "", new_rt[2048] = "", new_id[4096] = "", new_uid[128] = "";
    parse_json_str(resp, "access_token", new_at, sizeof new_at);
    parse_json_str(resp, "refresh_token", new_rt, sizeof new_rt);
    parse_json_str(resp, "id_token", new_id, sizeof new_id);
    parse_json_str(resp, "user_id", new_uid, sizeof new_uid);
    int expires_in = 0;
    {
        /* 不要用 atoi(p+12/13)：`"expires_in"` 后面的冒号和空格会让 atoi 直接返回 0，
           于是 expires_at 被写成"现在"，token 立刻被判过期（表现为服务端 busy=true、界面"token 过期"、
           剩余时间空白）。用 parse_json_int 正确跳过 `: `。 */
        expires_in = parse_json_int(resp, "expires_in", 0);
        if (expires_in <= 0) expires_in = 3600;
    }
    if (!new_at[0]) {
        log_err("[token:%s] 刷新响应缺少 access_token: %.200s", tm->name, resp);
        return -3;
    }
    pthread_mutex_lock(&tm->mu);
    snprintf(tm->tok.access_token, sizeof tm->tok.access_token, "%s", new_at);
    if (new_rt[0]) snprintf(tm->tok.refresh_token, sizeof tm->tok.refresh_token, "%s", new_rt);
    if (new_id[0]) snprintf(tm->tok.id_token, sizeof tm->tok.id_token, "%s", new_id);
    iso_now(tm->tok.expires_at, sizeof tm->tok.expires_at, expires_in);
    iso_now(tm->tok.obtained_at, sizeof tm->tok.obtained_at, 0);
    if (new_uid[0]) snprintf(tm->tok.user_id, sizeof tm->tok.user_id, "%s", new_uid);
    if (new_id[0]) {
        char upuid[128] = "", uname[128] = "";
        id_token_claims(new_id, upuid, sizeof upuid, uname, sizeof uname);
        if (uname[0]) snprintf(tm->tok.account, sizeof tm->tok.account, "%s", uname);
    }
    tm->broken = 0;
    tm->dead_reason[0] = 0;
    int saved = tm_save(tm);
    pthread_mutex_unlock(&tm->mu);
    if (!saved)
        log_print("[token] 落盘失败：%s（新 refresh_token 只在内存，重启会退回已作废的旧值，需人工重登）",
                  tm->path);
    return 0;
}

void *tm_refresh_loop(void *arg) {
    token_manager *tm = arg;
    int backoff = 0;
    for (;;) {
        pthread_mutex_lock(&tm->mu);
        int need = tm->tok.refresh_token[0] == 0 || token_expired(tm) ||
                   tm_expiry_ts(tm->tok.expires_at) < (int)time(NULL) + 300;
        pthread_mutex_unlock(&tm->mu);
        if (!need) { sleep(30); continue; }
        int rc = tm_refresh(tm);
        if (rc == 0) { log_print("[token:%s] 刷新成功", tm->name); backoff = 0; sleep(30); continue; }
        if (rc == -2) {
            /* invalid_grant：refresh 这条路已死。不再干等 1 小时——broken 标志
               已置位，自动重登线程（mslogin.c relogin_thread）每 20 秒检查一次，
               会用保存的账号密码走网页登录换一条新授权。这里只做低频兜底轮询。 */
            log_print("[token:%s] %s：等待自动重登处理", tm->name, tm_dead_reason(tm));
            sleep(300);
            continue;
        }
        backoff = backoff ? backoff * 2 : 60;
        if (backoff > 1800) backoff = 1800;
        log_print("[token:%s] 刷新失败 rc=%d，退避 %d 秒", tm->name, rc, backoff);
        sleep(backoff);
    }
    return NULL;
}

int tm_get_id_token(token_manager *tm, char *id_token, size_t idn, char *user_id, size_t un) {
    pthread_mutex_lock(&tm->mu);
    int rc = 0;
    if (tm->tok.refresh_token[0] == 0 || token_expired(tm)) rc = -1;
    if (rc == 0) {
        snprintf(id_token, idn, "%s", tm->tok.id_token);
        snprintf(user_id, un, "%s", tm->tok.user_id);
        tm->broken = 0;
    } else {
        tm->broken = 1;
    }
    pthread_mutex_unlock(&tm->mu);
    return rc;
}

/* 解析 JWT id_token payload 的 puid / preferred_username（httpd 登录用） */
static void id_token_claims(const char *id_token, char *puid, size_t pn,
                            char *username, size_t un) {
    puid[0] = username[0] = 0;
    const char *p1 = strchr(id_token, '.');
    if (!p1) return;
    const char *p2 = strchr(p1 + 1, '.');
    if (!p2) return;
    size_t pl = (size_t)(p2 - p1 - 1);
    if (pl == 0 || pl > 6000) return;
    char *seg = malloc(pl + 1);
    if (!seg) return;
    memcpy(seg, p1 + 1, pl);
    seg[pl] = 0;
    /* JWT 是 base64url：- → +，_ → / */
    for (char *q = seg; *q; q++) {
        if (*q == '-') *q = '+';
        else if (*q == '_') *q = '/';
    }
    unsigned char *payload = malloc(pl);
    if (!payload) { free(seg); return; }
    int n = b64_decode(seg, payload, pl);
    free(seg);
    if (n <= 0) { free(payload); return; }
    payload[n] = 0;
    parse_json_str((const char *)payload, "puid", puid, pn);
    parse_json_str((const char *)payload, "preferred_username", username, un);
    free(payload);
}

/* 把 token 端点响应 JSON 应用到本机 token 管理器并落盘（设备码/密钥登录共用）
   返回 0 成功，account 填 preferred_username */
int tm_apply_tokens(token_manager *tm, const char *resp_json, char *account, size_t an) {
    char new_at[2048] = "", new_rt[2048] = "", new_id[4096] = "", new_scope[512] = "";
    parse_json_str(resp_json, "access_token", new_at, sizeof new_at);
    parse_json_str(resp_json, "refresh_token", new_rt, sizeof new_rt);
    parse_json_str(resp_json, "id_token", new_id, sizeof new_id);
    parse_json_str(resp_json, "scope", new_scope, sizeof new_scope);
    if (!new_at[0] || !new_id[0]) return -1;
    int expires_in = parse_json_int(resp_json, "expires_in", 0);
    if (expires_in <= 0) expires_in = 3600;   /* 缺字段时给个保守默认，别把 token 判成"立刻过期" */
    char puid[128] = "", username[128] = "";
    id_token_claims(new_id, puid, sizeof puid, username, sizeof username);
    if (!puid[0]) return -2;

    pthread_mutex_lock(&tm->mu);
    snprintf(tm->tok.access_token, sizeof tm->tok.access_token, "%s", new_at);
    if (new_rt[0]) snprintf(tm->tok.refresh_token, sizeof tm->tok.refresh_token, "%s", new_rt);
    snprintf(tm->tok.id_token, sizeof tm->tok.id_token, "%s", new_id);
    if (new_scope[0]) snprintf(tm->tok.scope, sizeof tm->tok.scope, "%s", new_scope);
    iso_now(tm->tok.expires_at, sizeof tm->tok.expires_at, expires_in);
    iso_now(tm->tok.obtained_at, sizeof tm->tok.obtained_at, 0);
    snprintf(tm->tok.user_id, sizeof tm->tok.user_id, "%s", puid);
    if (username[0]) snprintf(tm->tok.account, sizeof tm->tok.account, "%s", username);
    tm->broken = 0;
    tm->dead_reason[0] = 0;
    int saved2 = tm_save(tm);
    pthread_mutex_unlock(&tm->mu);
    snprintf(account, an, "%s", username);
    if (!saved2) {
        log_print("[token] 落盘失败：%s（新 refresh_token 只在内存，重启会退回已作废的旧值，需人工重登）",
                  tm->path);
        return -1; /* 让调用方显示「登录成功但保存 token 失败」，不要谎报已写入 */
    }
    return 0;
}

/* ---------- 网页展示辅助 ---------- */

const char *tm_state_text(token_manager *tm) {
    pthread_mutex_lock(&tm->mu);
    const char *s;
    if (tm->broken) s = "rejected";
    else if (tm->tok.refresh_token[0] == 0 && tm->tok.id_token[0] == 0) s = "none";
    else if (token_expired(tm)) s = "expired";
    else s = "ok";
    pthread_mutex_unlock(&tm->mu);
    return s;
}

void tm_expires_h(token_manager *tm, char *out, size_t n) {
    out[0] = 0;
    pthread_mutex_lock(&tm->mu);
    /* expires_at: 2026-11-18T13:40:00Z → 11-18 13:40 */
    if (strlen(tm->tok.expires_at) >= 16 && tm->tok.expires_at[4] == '-')
        snprintf(out, n, "%.5s %.5s", tm->tok.expires_at + 5, tm->tok.expires_at + 11);
    pthread_mutex_unlock(&tm->mu);
}

/* token 剩余有效时长（人读串，如「剩 45 分钟」「剩 0.9 小时」「已过期」），无效时为空 */
void tm_left_h(token_manager *tm, char *out, size_t n) {
    out[0] = 0;
    pthread_mutex_lock(&tm->mu);
    long exp = tm_expiry_ts(tm->tok.expires_at);
    if (exp > 0) {
        long left = exp - (long)time(NULL);
        if (left <= 0)
            snprintf(out, n, "已过期");
        else if (left < 3600)
            snprintf(out, n, "剩 %ld 分钟", (left + 59) / 60);
        else
            snprintf(out, n, "剩 %.1f 小时", left / 3600.0);
    }
    pthread_mutex_unlock(&tm->mu);
}

void tm_account_hint(token_manager *tm, char *out, size_t n) {
    if (!out || n == 0) return;
    out[0] = 0;
    pthread_mutex_lock(&tm->mu);
    if (tm->tok.account[0]) {
        snprintf(out, n, "%s", tm->tok.account);
    } else if (tm->tok.id_token[0]) {
        char puid[64];
        id_token_claims(tm->tok.id_token, puid, sizeof puid, out, n);
    }
    pthread_mutex_unlock(&tm->mu);
}   /* 什么都没解析出来就留空，调用方退回配置里的账号 */

void tm_logout(token_manager *tm) {
    pthread_mutex_lock(&tm->mu);
    memset(&tm->tok, 0, sizeof tm->tok);
    tm->broken = 0;
    tm->dead_reason[0] = 0;
    pthread_mutex_unlock(&tm->mu);
    unlink(tm->path);
    log_print("[登录:%s] 已清除本机 token（网页操作）", tm->name);
}

/* ---------- DPoP (ES256, BCrypt) ---------- */

static const char *b64url_part(const unsigned char *in, size_t n, char *out) {
    b64url_encode(in, n, out);
    return out;
}

/* 生成 P-256 临时密钥并导出公钥坐标 x/y（各 32 字节），返回 EC_KEY*（用完 EC_KEY_free） */
static EC_KEY *ec_keygen(unsigned char x[32], unsigned char y[32]) {
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *pub;
    BIGNUM *bx = NULL, *by = NULL;
    int ok = 0;

    if (!k) return NULL;
    if (EC_KEY_generate_key(k) != 1) goto done;
    pub = EC_KEY_get0_public_key(k);
    bx = BN_new();
    by = BN_new();
    if (!bx || !by) goto done;
    if (EC_POINT_get_affine_coordinates(EC_KEY_get0_group(k), pub, bx, by, NULL) != 1) goto done;
    if (BN_bn2binpad(bx, x, 32) != 32) goto done;
    if (BN_bn2binpad(by, y, 32) != 32) goto done;
    ok = 1;

done:
    BN_free(bx);
    BN_free(by);
    if (!ok) {
        EC_KEY_free(k);
        return NULL;
    }
    return k;
}

/* 生成 DPoP JWT，返回 malloc 缓冲（调用方 free），失败 NULL */
char *dpop_token(const char *method, const char *url, const char *bearer) {
    unsigned char x[32], y[32];
    EC_KEY *key = ec_keygen(x, y);
    if (!key) {
        log_err("[dpop] keygen 失败");
        return NULL;
    }

    /* JWK 公钥坐标（各 32 字节） */
    char jx[64], jy[64];
    b64url_part(x, 32, jx);
    b64url_part(y, 32, jy);

    char hdr[256], pl[512];
    snprintf(hdr, sizeof hdr,
        "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}}",
        jx, jy);

    /* path = url 去掉 scheme://host */
    const char *path = url;
    const char *s3 = strstr(url, "://");
    if (s3) {
        path = strchr(s3 + 3, '/');
        path = path ? path : "/";
    }
    char ath[64] = "";
    if (bearer && *bearer) {
        const char *bt = strncmp(bearer, "Bearer ", 7) == 0 ? bearer + 7 : bearer;
        unsigned char hb[32];
        br_sha256_context hc;
        br_sha256_init(&hc);
        br_sha256_update(&hc, bt, strlen(bt));
        br_sha256_out(&hc, hb);
        b64url_part(hb, 32, ath);
    }
    unsigned char jti[8];
    platform_random_bytes(jti, sizeof jti);
    char jtis[16];
    b64url_part(jti, 8, jtis);
    if (ath[0])
        snprintf(pl, sizeof pl, "{\"htu\":\"%s\",\"htm\":\"%s\",\"jti\":\"%s\",\"iat\":%lld,\"ath\":\"%s\"}",
            path, method, jtis, (long long)time(NULL), ath);
    else
        snprintf(pl, sizeof pl, "{\"htu\":\"%s\",\"htm\":\"%s\",\"jti\":\"%s\",\"iat\":%lld}",
            path, method, jtis, (long long)time(NULL));

    /* signing = b64url(hdr) "." b64url(payload) */
    char b64h[512], b64p[1024];
    b64url_part((const unsigned char *)hdr, strlen(hdr), b64h);
    b64url_part((const unsigned char *)pl, strlen(pl), b64p);
    char signing[2048];
    snprintf(signing, sizeof signing, "%s.%s", b64h, b64p);

    /* SHA-256 + ECDSA 签名（OpenSSL 给 DER，转成 r||s 裸签名，与 ES256 JWS 一致） */
    unsigned char hb[32];
    br_sha256_context hc;
    br_sha256_init(&hc);
    br_sha256_update(&hc, signing, strlen(signing));
    br_sha256_out(&hc, hb);

    unsigned char sig[64];
    int ok = 0;
    {
        ECDSA_SIG *es = ECDSA_do_sign(hb, sizeof hb, key);
        if (es) {
            const BIGNUM *r = NULL, *s = NULL;
            ECDSA_SIG_get0(es, &r, &s);
            if (r && s && BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(s, sig + 32, 32) == 32)
                ok = 1;
            ECDSA_SIG_free(es);
        }
    }
    EC_KEY_free(key);
    if (!ok) {
        log_err("[dpop] 签名失败");
        return NULL;
    }
    char b64sig[128];
    b64url_part(sig, sizeof sig, b64sig);

    size_t total = strlen(signing) + strlen(b64sig) + 2;
    char *jwt = malloc(total);
    if (!jwt) return NULL;
    snprintf(jwt, total, "%s.%s", signing, b64sig);
    return jwt;
}

/* ---------- validateIID ---------- */

static const char *guid32(void) {
    static char buf[40];
    unsigned char b[16];
    platform_random_bytes(b, sizeof b);
    for (int i = 0; i < 16; i++) sprintf(buf + i * 2, "%02x", b[i]);
    return buf;
}

/* JSON 里的布尔字段：`"activationSuccessful":true` 是 bool，不是数字。
   ⚠️ 以前这里用 parse_json_int（atoi）：atoi("true") == 0，于是**每一次成功**
   都被当成失败，一路走到重试，最后把 message 字段（成功时微软填的是
   "Clearinghouse Supplied Confirmation ID" 这类枚举描述）当成确认ID 回给上游
   —— 表现就是"CID 不是数字"。这里必须按 true/1/"true" 三种写法都认。 */
static int json_field_true(const char *json, const char *key) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        p += strlen(pat);
        if (*q != ':') continue;
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (!strncmp(q, "true", 4)) return 1;
        if (*q == '1') return 1;
        if (*q == '"' && !strncmp(q + 1, "true", 4)) return 1;
        if (*q == '"' && q[1] == '1' && q[2] == '"') return 1;
        return 0;
    }
    return 0;
}

static const char *reason_text(const char *code, int lang);

/* 把接口回来的 message 原文映射成给人看的原因（与桌面/服务端实现对齐）。
   返回 "" 表示"这不是能回传的结果"，调用方应当按失败处理（空 CID → 上层
   failover 换客户端或走 API 兜底），绝不能把英文原文当确认ID 发出去。 */
static const char *message_text(const char *msg, int lang) {
    if (!msg[0]) return "";
    if (strstr(msg, "DMAK activation override limit reached")) return reason_text("45270", lang);
    if (strstr(msg, "ROT activation override limit reached")) return reason_text("45269", lang);
    if (strstr(msg, "product key is blocked")) return reason_text("45090", lang);
    if (strstr(msg, "Default Key was provided during installation")) return reason_text("45090", lang);
    if (strstr(msg, "Invalid IID") || strstr(msg, "Invaild IID")) return reason_text("45112", lang);
    if (strstr(msg, "evaluate")) return reason_text("45057", lang);
    return "";
}

static void parse_validate(const char *body, char *cid, size_t cidn,
                           char *msg, size_t msgn, char *reason, size_t rsn) {
    cid[0] = msg[0] = reason[0] = 0;
    const char *t = body;
    while (*t == ' ' || *t == '\n' || *t == '\r' || *t == '\t') t++;
    if (strstr(body, "The request is blocked.") ||
        strstr(body, "The requested resource is not found.") ||
        strstr(body, "Our services aren't available right now.") ||
        *t == '<') return;
    if (json_field_true(body, "activationSuccessful")) {
        parse_json_str(body, "cid", cid, cidn);
        return;
    }
    parse_json_str(body, "message", msg, msgn);
    parse_json_str(body, "reasonCode", reason, rsn);
}

static const char *reason_text(const char *code, int lang) {
    if (lang != 0) {
        if (!strcmp(code, "45270")) return "多次激活密钥已超出其限制(0xC004C060)";
        if (!strcmp(code, "45090") || !strcmp(code, "45167")) return "密钥已被封禁(0xC004C003)";
        if (!strcmp(code, "45112")) return "安装ID输入错误";
        if (!strcmp(code, "45057")) return "试用版安装ID不支持获取确认ID(0xC004C004)";
        if (!strcmp(code, "45269")) return "密钥已失效(0xC004C060)";
    } else {
        if (!strcmp(code, "45270")) return "This product key has exceeded the set number of activations(0xC004C060)";
        if (!strcmp(code, "45090") || !strcmp(code, "45167")) return "This product key is blocked(0xC004C003)";
        if (!strcmp(code, "45112")) return "The InstallationID input error";
        if (!strcmp(code, "45057")) return "This evaluate version InstallationID cannot be obtained(0xC004C004)";
        if (!strcmp(code, "45269")) return "The key is invalid(0xC004C060)";
    }
    return "";
}

/* 一次 validateIID POST；成功 body 写入 resp。返回 0 OK */
static int post_validate(const char *iid, const char *id_token, const char *user_id,
                         const char *payload, char *resp, size_t respn) {
    char hdrs[4096];
    char uid[64];
    if (user_id && *user_id) {
        /* 大写 */
        for (char *p = (char *)user_id; *p; p++) *p = (char)((*p >= 'a' && *p <= 'z') ? *p - 32 : *p);
        snprintf(uid, sizeof uid, "%s", user_id);
    } else {
        snprintf(uid, sizeof uid, "00000000-0000-0000-D0E8-D27817F01031");
    }
    snprintf(hdrs, sizeof hdrs,
        "sec-ch-ua: \"Microsoft Edge\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"\r\n"
        "sec-ch-ua-mobile: ?0\r\n"
        "sec-ch-ua-platform: \"Windows\"\r\n"
        "Cache-Control: max-age=0\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0\r\n"
        "X-Edge-Shopping-Flag: 1\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Accept: application/json, text/plain, */*\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
        "Authorization: Bearer %s\r\n"
        "Referer: https://visualsupport.microsoft.com/activate\r\n"
        "X-User-Id: %s\r\n"
        "request-id: |%s\r\n"
        "traceparent: 00-%s-01\r\n"
        "X-Session-Id: app_%.8s\r\n",
        id_token, uid, guid32(), guid32(), guid32());

    char dp[2048] = "";
    char *jwt = dpop_token("POST", VALIDATE_URL, id_token);
    if (jwt) {
        snprintf(dp, sizeof dp, "DPoP: %s\r\n", jwt);
        free(jwt);
    } else {
        log_err("[dpop] DPoP 生成失败");
        return -1;
    }
    char all[6144];
    snprintf(all, sizeof all, "%s%s", hdrs, dp);
    int status = 0;
    if (https_post(VALIDATE_URL, all, payload, strlen(payload), resp, respn, &status) != 0) {
        log_err("[validate] POST 失败");
        return -1;
    }
    if (status != 200) log_err("[validate] HTTP %d 响应: %.300s", status, resp);
    return 0;
}

cid_result fetch_cid(const char *iid, const char *id_token, const char *user_id, int lang) {
    cid_result res;
    memset(&res, 0, sizeof res);
    char name[128], pid[128];
    int gid, ka;
    reverse_key_data(iid, name, sizeof name, pid, sizeof pid, &gid, &ka);
    snprintf(res.pid, sizeof res.pid, "%s", pid);
    snprintf(res.title, sizeof res.title, "%s", name);

    int num_digits = 7;
    const char *product = "Windows 11";
    if (strlen(iid) != 63) { num_digits = 6; product = "Windows 7"; }

    char payload[1024];
    snprintf(payload, sizeof payload,
        "{\"IID\":\"%s\",\"ProductType\":\"windows\",\"productGroup\":\"Windows\",\"productName\":\"%s\","
        "\"numberOfDigits\":%d,\"Country\":\"GBR\",\"Region\":\"EMEA\"}",
        iid, product, num_digits);

    char resp[16384], cid[256], msg[512], reason[64];
    if (post_validate(iid, id_token, user_id, payload, resp, sizeof resp) != 0) return res;
    parse_validate(resp, cid, sizeof cid, msg, sizeof msg, reason, sizeof reason);
    if (cid[0]) { snprintf(res.cid, sizeof res.cid, "%s", cid); return res; }
    if (reason[0]) {
        const char *fixed = reason_text(reason, lang);
        if (fixed[0]) { snprintf(res.cid, sizeof res.cid, "%s", fixed); return res; }
    }
    if (!msg[0]) return res;

    /* 手动重试（OverrideStatusCode=MUL） */
    const char *retry_name = "Office 2021";
    int rd = 7;
    if (strlen(iid) != 63) { retry_name = "Office 2010"; rd = 6; }
    snprintf(payload, sizeof payload,
        "{\"IID\":\"%s\",\"ProductType\":\"windows\",\"productGroup\":\"Windows\",\"productName\":\"%s\","
        "\"numberOfDigits\":%d,\"Country\":\"GBR\",\"Region\":\"EMEA\","
        "\"InstalledDevices\":0,\"OverrideStatusCode\":\"MUL\",\"InitialReasonCode\":\"45092\"}",
        iid, retry_name, rd);
    if (post_validate(iid, id_token, user_id, payload, resp, sizeof resp) != 0) return res;
    parse_validate(resp, cid, sizeof cid, msg, sizeof msg, reason, sizeof reason);
    if (cid[0]) { snprintf(res.cid, sizeof res.cid, "%s", cid); return res; }
    if (reason[0]) {
        const char *fixed = reason_text(reason, lang);
        if (fixed[0]) { snprintf(res.cid, sizeof res.cid, "%s", fixed); return res; }
    }
    /* 只在能映射成可读原因时才回传；微软原文（如成功时的
       "Clearinghouse Supplied Confirmation ID"）一律不回传，
       留空让上层 failover —— 空 CID 会被判 empty 并改派/兜底。 */
    if (msg[0]) {
        const char *fixed = message_text(msg, lang);
        if (fixed[0]) snprintf(res.cid, sizeof res.cid, "%s", fixed);
    }
    return res;
}
