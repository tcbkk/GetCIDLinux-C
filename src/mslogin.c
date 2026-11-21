/* mslogin.c - 微软「账号密码 + 邮箱验证码」网页登录流程
   完整移植自 Go 版 CIDRouter/mslogin.go（权威参考实现），所有 URL、表单字段、
   页面分类与坑（purpose=eOTT_OneTimePassword、PPFT 用 MFA 页原始 sFT、KMSI 必须
   LoginOptions=3、授权码 URL 解码、exchange 三连兜底、TOU/passkey/fmHF/i5030/
   account.live.com WLX 流程）一一对应。
   HTTP 层走系统 curl（OpenSSL 栈），-b/-c cookie jar（/tmp/getcid_mscookies_<账号>.dat）
   + -D dump 响应头取 Location，重定向手动逐跳跟（Location 里可能带授权码）。
   密码只在内存用一次，不写日志、不写配置以外的文件。 */
#include "common.h"
#include "app.h"
#include "msft.h"
#include "mslogin.h"
#include <sys/wait.h>
#include "b64.h"
#include "https.h"
#include <bearssl.h>

#define MS_AUTHORIZE_URL  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
#define MS_AUTHORIZE_MSA  "https://login.live.com/oauth20_authorize.srf"
#define MS_REDIRECT_URI   "https://visualsupport.microsoft.com/"
#define MS_UA             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
#define MS_OTC_LOGIN      "https://login.live.com/GetOneTimeCode.srf"
#define MSL_TOKEN_MSA     "https://login.live.com/oauth20_token.srf"
#define MSL_RELOGIN_AT    (23 * 3600)     /* 授权满 23 小时主动重登（绝对寿命 ~24h45m） */
#define MSL_PENDING_WAIT  (15 * 60)       /* 等人工填邮箱/验证码最多这么久 */
#define MSL_RETRY_AUTH    (30 * 60)       /* 认证类失败首次重试间隔 */
#define MSL_RETRY_AUTH_MAX (4 * 3600)
#define MSL_RETRY_NET     60              /* 网络类失败首次重试间隔（秒） */
#define MSL_RETRY_NET_MAX 600

/* ---------- 动态字符串缓冲 ---------- */
typedef struct { char *p; size_t len, cap; } sbuf;

static void sb_init(sbuf *b) {
    b->cap = 4096;
    b->p = malloc(b->cap);
    if (!b->p) { b->cap = 0; b->len = 0; return; }
    b->p[0] = 0;
    b->len = 0;
}

static void sb_append_len(sbuf *b, const char *s, size_t n) {
    if (!b->p) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (b->len + n + 1 > nc) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) { free(b->p); b->p = NULL; b->cap = 0; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_append(sbuf *b, const char *s) { if (s) sb_append_len(b, s, strlen(s)); }

static void sb_fmt(sbuf *b, const char *fmt, ...) {
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    sb_append(b, tmp);
}

static void sb_free(sbuf *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* 追加 k=v（v 做 URL 转义，任意长度安全） */
static void sb_form_add(sbuf *b, const char *k, const char *v) {
    if (b->len) sb_append(b, "&");
    sb_append(b, k);
    sb_append(b, "=");
    size_t vn = strlen(v);
    char *esc = malloc(vn * 3 + 1);
    if (!esc) return;
    url_escape(v, esc, vn * 3 + 1);
    sb_append(b, esc);
    free(esc);
}

/* 追加 JSON 字符串值（带引号，任意长度安全） */
static void sb_json_str(sbuf *b, const char *v) {
    sb_append(b, "\"");
    for (const unsigned char *p = (const unsigned char *)v; p && *p; p++) {
        char tmp[8];
        if (*p == '"' || *p == '\\') { tmp[0] = '\\'; tmp[1] = (char)*p; tmp[2] = 0; sb_append(b, tmp); }
        else if (*p == '\n') sb_append(b, "\\n");
        else if (*p == '\r') sb_append(b, "\\r");
        else if (*p == '\t') sb_append(b, "\\t");
        else { tmp[0] = (char)*p; tmp[1] = 0; sb_append(b, tmp); }
    }
    sb_append(b, "\"");
}

/* ---------- 会话 ---------- */
typedef struct {
    app_state *owner;        /* 归属实例：token 落盘写进该实例的 token 文件 */
    time_t created;          /* 会话创建时间：等人工会话的保鲜期判断用 */
    char username[128];
    char password[128];      /* 只在内存，用于验码后微软要求回到密码步骤时补交 */

    char jar[320];           /* cookie jar 文件（数据目录） */

    char urlPost[512];
    char urlCredType[512];
    char urlGoToAAD[512];
    char authURL[512];
    char sFT[16384];
    char sFTName[64];
    char sCtx[16384];
    char sCanary[16384];
    char country[64];
    char pageID[64];
    char siteID[64];
    char siteClient[64];
    char uaid[128];
    char verifier[64];
    char challenge[64];

    char epidEmail[1024];
    char partialEmail[256];  /* 页面上的掩码邮箱 */
    char fullEmail[256];     /* 人工填的完整邮箱：ProofConfirmation 必须用它，用掩码会 State=204 */
    int  codeSent;
    int  otcMode;            /* i5030 一次性验证码登录（passwordless） */
    int  emailAsked;         /* 已停在等人工提供收件邮箱；此后绝不自动发码 */
    char emailSent[256];     /* 人工上一次指定的收件邮箱（网页回显用） */
    char otcLcid[16];
    char otcReferer[256];
    int  pwdResumes;         /* 验码后回到密码页的补交次数，防死循环 */
    int  pwdSubmitted;       /* 决定发码 purpose 与 AltEmailE/UIMode */
    char otcOrigFT[16384];   /* 发码前 MFA 页原始 sFT；提交验证码必须用它当 PPFT */
    char otcNewFT[16384];    /* GetOneTimeCode 返回的新 FlowToken：原始 sFT 被拒时的备选 PPFT */
    int  otcFTTried;         /* 已经用 otcNewFT 重试过 PPFT，防死循环 */
    char rawQuery[1024];     /* 页面 sRawQueryString：i5030 提交验证码的 post.srf 查询串 */

    int  wlxMode;            /* account.live.com「验证你的账户」流程 */
    char wlxCanary[16384];
    char wlxCanaryOrig[16384];
    int  verifyFails;
    char wlxUAID[128];
    char wlxScid[32];
    char wlxHpgid[32];
    char wlxTcxt[1024];
    char wlxEipt[1024];
    char wlxEpid[1024];
    char wlxPartial[256];
    char urlRef[512];

    char errbuf[512];
} ms_session;

static ms_session *SESS[MAX_INST];
static pthread_mutex_t SESS_MU = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t LOGIN_MU = PTHREAD_MUTEX_INITIALIZER;   /* 整条登录链路串行化 */
static char MSL_CFG_PATH[256] = "";

/* 前向声明（流程函数相互调用） */
static int sess_start_login(ms_session *s);
static int sess_submit_password(ms_session *s, const char *password, char **html_out);
static int sess_finish_page(ms_session *s, const char *html_in);
static int sess_resume_password(ms_session *s, const char *html);
static int sess_exchange_save(ms_session *s, const char *code);
static int sess_send_otc(ms_session *s, const char *html);
static int ms_continue_after_wlx(ms_session *s);
static void dump_html(const char *tag, const char *html);
static int page_cookie_mismatch(const char *html);
static void purge_cookie_jar(ms_session *s);

static void SETERR(ms_session *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s->errbuf, sizeof s->errbuf, fmt, ap);
    va_end(ap);
}

/* ---------- 小工具 ---------- */

static void rand_bytes(unsigned char *b, size_t n) {
    if (platform_random_bytes(b, n) == 0) return;
    /* 兜底：毫秒时钟 + pid 混合 */
    long long ms = now_ms();
    for (size_t i = 0; i < n; i++) {
        ms = ms * 6364136223846793005LL + 1442695040888963407LL + getpid();
        b[i] = (unsigned char)(ms >> 33);
    }
}

/* guid36：client-request-id 用 */
static void guid36(char *out, size_t n) {
    unsigned char b[16];
    rand_bytes(b, sizeof b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, n,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static void pkce_pair(ms_session *s) {
    unsigned char b[32];
    rand_bytes(b, sizeof b);
    b64url_encode(b, sizeof b, s->verifier);          /* 43 字符，无填充 */
    br_sha256_context hc;
    br_sha256_init(&hc);
    br_sha256_update(&hc, s->verifier, strlen(s->verifier));
    unsigned char sum[32];
    br_sha256_out(&hc, sum);
    b64url_encode(sum, sizeof sum, s->challenge);
}

static void html_unescape(const char *in, char *out, size_t outn) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < outn; p++) {
        if (*p == '&') {
            if (!strncmp(p, "&amp;", 5)) { out[o++] = '&'; p += 4; }
            else if (!strncmp(p, "&lt;", 4)) { out[o++] = '<'; p += 3; }
            else if (!strncmp(p, "&gt;", 4)) { out[o++] = '>'; p += 3; }
            else if (!strncmp(p, "&quot;", 6)) { out[o++] = '"'; p += 5; }
            else if (!strncmp(p, "&#39;", 5)) { out[o++] = '\''; p += 4; }
            else out[o++] = *p;
        } else out[o++] = *p;
    }
    out[o] = 0;
}

/* QueryUnescape：%XX 解码，'+' 还原成空格（与 Go url.QueryUnescape 一致） */
static int url_decode(const char *in, char *out, size_t outn) {
    size_t o = 0;
    static const char hex[] = "0123456789abcdefABCDEF";
    for (const char *p = in; *p; p++) {
        if (o + 1 >= outn) return -1;
        if (*p == '+') { out[o++] = ' '; continue; }
        if (*p == '%' && p[1] && p[2] && strchr(hex, p[1]) && strchr(hex, p[2])) {
            char h[3] = { p[1], p[2], 0 };
            out[o++] = (char)strtol(h, NULL, 16);
            p += 2;
            continue;
        }
        out[o++] = *p;
    }
    out[o] = 0;
    return 0;
}

static int str_icontains(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t nl = strlen(needle);
    if (!nl) return 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i]) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            i++;
        }
        if (i == nl) return 1;
    }
    return 0;
}

static void mask_email(const char *email, char *out, size_t n) {
    const char *at = strchr(email, '@');
    if (at && at > email + 1)
        snprintf(out, n, "%c***%s", email[0], at);
    else
        snprintf(out, n, "%s", email);
}

static int is_code_html(const char *h) { return h && strncmp(h, "CODE:", 5) == 0; }

/* 从 Location/URL 里取授权码（URL 解码；拿不到返回 -1） */
static int code_from_str(const char *loc, char *out, size_t n) {
    if (!loc) return -1;
    const char *p = strstr(loc, "code=");
    while (p) {
        if (p == loc || p[-1] == '?' || p[-1] == '&') break;
        p = strstr(p + 5, "code=");
    }
    if (!p) return -1;
    p += 5;
    char raw[2048];
    size_t o = 0;
    while (*p && *p != '&' && o + 1 < sizeof raw) raw[o++] = *p++;
    raw[o] = 0;
    char un[2048];
    html_unescape(raw, un, sizeof un);
    /* 授权码在 Location 里是 URL 编码的（常见 %2B/%2F/%3D），不解码会被判 AADSTS70000 */
    return url_decode(un, out, n);
}

/* 相对 Location → 绝对 URL */
static void abs_url(const char *base, const char *loc, char *out, size_t n) {
    if (strncmp(loc, "https://", 8) == 0 || strncmp(loc, "http://", 7) == 0) {
        snprintf(out, n, "%s", loc);
        return;
    }
    if (loc[0] == '/') {
        const char *s3 = strstr(base, "://");
        if (s3) {
            const char *h = s3 + 3;
            const char *sl = strchr(h, '/');
            if (sl) { snprintf(out, n, "%.*s%s", (int)(sl - base), base, loc); return; }
        }
    }
    snprintf(out, n, "%s", loc);
}

/* ---------- HTTP（系统 curl） ---------- */

typedef struct {
    int status;
    char *location;   /* malloc，可能 NULL */
    char *body;       /* malloc，NUL 结尾 */
} ms_resp;

static void ms_resp_free(ms_resp *r) {
    free(r->location);
    free(r->body);
    memset(r, 0, sizeof *r);
}

static int msl_seq = 0;

static void msl_tmp(char *buf, size_t n, const char *what) {
    snprintf(buf, n, "%s/.msl_%d_%d_%s", G_DATA_DIR[0] ? G_DATA_DIR : ".",
             (int)getpid(), ++msl_seq, what);
}

/* 起一个子进程（curl），stdout/stderr 重定向到文件；返回退出码，起不来返回 -1 */
static int msl_run_process(const char *exe, const char *const *args, int n,
                           const char *stdout_path) {
    char *argv[64];
    pid_t pid;
    int i, st = 0;

    if (n > 62) n = 62;
    argv[0] = (char *)exe;
    for (i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    argv[n + 1] = NULL;

    pid = fork();
    if (pid < 0) {
        log_err("[MSLOGIN] fork 失败: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        int fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) close(fd);
        }
        execv(exe, argv);
        _exit(127);
    }

    /* 最多等 60 秒，超时杀掉 */
    for (i = 0; i < 60; i++) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        if (r < 0) return -1;
        sleep(1);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    log_err("[MSLOGIN] curl 超时被杀: %s", exe);
    return -1;
}

static int msl_read_int_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[32] = {0};
    int v = 0;
    if (fgets(buf, sizeof buf, f)) v = atoi(buf);
    fclose(f);
    return v;
}

/* 一次 HTTP 请求。返回 0 成功（status 可能是 3xx/4xx），-1 网络/执行失败。 */
static int ms_request(ms_session *s, const char *method, const char *url,
                      const char *body, size_t bodyn, const char *ctype,
                      const char *accept, const char *referer, const char *origin,
                      const char *extra_headers, ms_resp *out) {
    memset(out, 0, sizeof *out);
    const char *curl = https_curl_path();
    if (!curl) { SETERR(s, "未找到系统 curl，无法执行登录请求"); return -1; }

    char tb[320], th[320], hd[320], tr[320], ts[320];
    msl_tmp(tb, sizeof tb, "body");
    msl_tmp(th, sizeof th, "hdr");
    msl_tmp(hd, sizeof hd, "dump");
    msl_tmp(tr, sizeof tr, "resp");
    msl_tmp(ts, sizeof ts, "st");
    int ret = -1;
    FILE *f = NULL;

    /* 请求头文件 */
    f = fopen(th, "w");
    if (!f) goto out;
    fprintf(f, "User-Agent: %s\n", MS_UA);
    fprintf(f, "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\n");
    fprintf(f, "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"\n");
    fprintf(f, "sec-ch-ua-mobile: ?0\n");
    fprintf(f, "sec-ch-ua-platform: \"Windows\"\n");
    fprintf(f, "Accept: %s\n", accept && *accept ? accept :
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    if (ctype && *ctype) fprintf(f, "Content-Type: %s\n", ctype);
    if (referer && *referer) fprintf(f, "Referer: %s\n", referer);
    if (origin && *origin) fprintf(f, "Origin: %s\n", origin);
    if (extra_headers && *extra_headers) {
        const char *p = extra_headers;
        while (*p) {
            size_t l = strcspn(p, "\r\n");
            if (l) fprintf(f, "%.*s\n", (int)l, p);
            p += l;
            while (*p == '\r' || *p == '\n') p++;
        }
    }
    fclose(f);
    f = NULL;

    /* 请求体 */
    if (body && bodyn) {
        FILE *bf = fopen(tb, "wb");
        if (!bf) goto out;
        if (fwrite(body, 1, bodyn, bf) != bodyn) { fclose(bf); goto out; }
        fclose(bf);
    }

    unlink(hd); unlink(tr);

    char hopt[160], bopt[160];
    snprintf(hopt, sizeof hopt, "@%s", th);
    int is_post = (strcmp(method, "POST") == 0 && body && bodyn) ? 1 : 0;
    if (is_post) snprintf(bopt, sizeof bopt, "@%s", tb);

    const char *args[24];
    int ac = 0;
    args[ac++] = "-s";
    args[ac++] = "-m";
    args[ac++] = "40";
    args[ac++] = "--connect-timeout";
    args[ac++] = "15";
    args[ac++] = "-b"; args[ac++] = s->jar;
    args[ac++] = "-c"; args[ac++] = s->jar;
    args[ac++] = "-D"; args[ac++] = hd;
    args[ac++] = "-H"; args[ac++] = hopt;
    if (is_post) { args[ac++] = "--data-binary"; args[ac++] = bopt; }
    args[ac++] = "-o"; args[ac++] = tr;
    args[ac++] = "-w"; args[ac++] = "%{http_code}";
    args[ac++] = url;
    args[ac] = NULL;

    int rc = msl_run_process(curl, args, ac, ts);
    int status = msl_read_int_file(ts);
    unlink(ts);
    if (rc != 0 && status == 0) {
        log_print("[MSLOGIN] curl 执行失败 rc=%d url=%.160s", rc, url);
        goto out;
    }

    /* 解析响应头：Location（取第一个） */
    f = fopen(hd, "r");
    if (f) {
        char line[8192];
        while (fgets(line, sizeof line, f)) {
            size_t l = strlen(line);
            while (l && (line[l-1] == '\r' || line[l-1] == '\n')) line[--l] = 0;
            if (!strncasecmp(line, "location:", 9) && !out->location) {
                const char *v = line + 9;
                while (*v == ' ') v++;
                out->location = strdup(v);
            }
        }
        fclose(f);
        f = NULL;
    }
    unlink(hd);

    /* 读响应体 */
    f = fopen(tr, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0) sz = 0;
        char *buf = malloc((size_t)sz + 1);
        if (buf) {
            size_t rd = fread(buf, 1, (size_t)sz, f);
            buf[rd] = 0;
            out->body = buf;
        }
        fclose(f);
        f = NULL;
    }
    unlink(tr);
    out->status = status;
    ret = 0;

out:
    if (f) fclose(f);
    unlink(tb);
    unlink(th);
    unlink(hd);
    unlink(tr);
    unlink(ts);
    return ret;
}

/* GET 跟随 3xx 抓最终 HTML；Location 带 code 直接返回授权码。
   返回 malloc 字符串："CODE:<code>" 或 HTML；NULL = 失败（errbuf 已填）。 */
static char *ms_get_html(ms_session *s, const char *url, const char *referer, int hops) {
    char cur[2048];
    snprintf(cur, sizeof cur, "%s", url);
    char code[2048];
    for (int i = 0; i < hops; i++) {
        ms_resp r;
        if (ms_request(s, "GET", cur, NULL, 0, NULL, NULL, referer, NULL, NULL, &r) != 0) {
            SETERR(s, "网络请求失败（GET %.120s）", cur);
            return NULL;
        }
        int have_code = r.location && code_from_str(r.location, code, sizeof code) == 0;
        char *loc = r.location ? strdup(r.location) : NULL;
        char *body = r.body;   /* 接管：先把 r.body 置空，ms_resp_free 才不会把它 free 掉 */
        r.body = NULL;
        int st = r.status;
        ms_resp_free(&r);
        if (have_code) {
            free(loc); free(body);
            char *out = malloc(strlen(code) + 8);
            sprintf(out, "CODE:%s", code);
            return out;
        }
        if (st >= 300 && st < 400) {
            if (!loc || !*loc) { free(loc); free(body); return body ? body : strdup(""); }
            char next[2048];
            abs_url(cur, loc, next, sizeof next);
            free(loc); free(body);
            snprintf(cur, sizeof cur, "%s", next);
            continue;
        }
        free(loc);
        return body ? body : strdup("");
    }
    SETERR(s, "重定向次数过多（%.120s）", cur);
    return NULL;
}

/* ---------- 页面解析 ---------- */

/* extractConfigJSON：优先 var ServerData = {...}，否则 $Config={...}；括号配平扫描 */
static char *extract_config_json(const char *html) {
    static const char *markers[] = { "var ServerData", "$Config=", "$Config =", "ServerData =", NULL };
    for (int mi = 0; markers[mi]; mi++) {
        const char *idx = strstr(html, markers[mi]);
        if (!idx) continue;
        const char *start = strchr(idx, '{');
        if (!start) continue;
        int depth = 0, in_str = 0, esc = 0;
        for (const char *p = start; *p; p++) {
            char c = *p;
            if (in_str) {
                if (esc) esc = 0;
                else if (c == '\\') esc = 1;
                else if (c == '"') in_str = 0;
                continue;
            }
            if (c == '"') in_str = 1;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    size_t len = (size_t)(p - start + 1);
                    char *out = malloc(len + 1);
                    if (!out) return NULL;
                    memcpy(out, start, len);
                    out[len] = 0;
                    return out;
                }
            }
        }
    }
    return NULL;
}

/* 从页面/配置 JSON 里取字符串键值（带 JSON 转义解码：\u002b 等，直接取原文会被判 canary 无效） */
static int ms_json_field(const char *json, const char *key, char *out, size_t outn) {
    out[0] = 0;
    if (!json) return -1;
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != ':') { p += strlen(pat); continue; }
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != '"') { p += strlen(pat); continue; }
        q++;
        const char *e = q;
        while (*e) {
            if (*e == '\\') { e += 2; continue; }
            if (*e == '"') break;
            e++;
        }
        if (!*e) return -1;
        size_t n = (size_t)(e - q);
        char *raw = malloc(n + 1);
        if (!raw) return -1;
        memcpy(raw, q, n);
        raw[n] = 0;
        int rc = json_unescape(raw, out, outn);
        free(raw);
        return rc < 0 ? -1 : 0;
    }
    return -1;
}

/* 数值键（可带或不带引号），如 "scid":123 或 "scid":"123" */
static void ms_json_numfield(const char *json, const char *key, char *out, size_t n) {
    out[0] = 0;
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (*p != ':') return;
    p++;
    while (*p == ' ') p++;
    size_t o = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && o + 1 < n) out[o++] = *p++;
    } else {
        while (*p >= '0' && *p <= '9' && o + 1 < n) out[o++] = *p++;
    }
    out[o] = 0;
}

static const char *ft_name(ms_session *s) { return s->sFTName[0] ? s->sFTName : "PPFT"; }

static void parse_proofs(ms_session *s, const char *html) {
    static char objs[16][2048];
    int n = json_extract_objects(html, "arrUserProofs", &objs[0][0], 2048, 16);
    if (n <= 0)
        n = json_extract_objects(html, "OtcLoginEligibleProofs", &objs[0][0], 2048, 16);
    for (int i = 0; i < n; i++) {
        if (parse_json_int(objs[i], "type", -1) != 1) continue;
        char data[1024] = "", disp[256] = "";
        parse_json_str(objs[i], "data", data, sizeof data);
        parse_json_str(objs[i], "display", disp, sizeof disp);
        if (data[0]) {
            char un[1024];
            html_unescape(data, un, sizeof un);
            snprintf(s->epidEmail, sizeof s->epidEmail, "%s", un);
            snprintf(s->partialEmail, sizeof s->partialEmail, "%s", disp);
        }
    }
}

static int sess_parse_page(ms_session *s, const char *html) {
    log_print("[MSLOGIN] parse begin len=%zu", strlen(html));
    if (getenv("GETCID_DUMP")) {
        /* 排查用：把每一步页面都留档，MSLOGIN_DUMP=1 时启用 */
        static int n = 0;
        char tag[32];
        snprintf(tag, sizeof tag, "step%d", n++);
        dump_html(tag, html);
    }
    char *raw = extract_config_json(html);
    log_print("[MSLOGIN] parse config len=%zu", raw ? strlen(raw) : 0);
    char v[16384];
    if (raw) {
        if (ms_json_field(raw, "urlPost", v, sizeof v) == 0 && v[0])
            snprintf(s->urlPost, sizeof s->urlPost, "%s", v);
        if (ms_json_field(raw, "urlGetCredentialType", v, sizeof v) == 0 && v[0])
            snprintf(s->urlCredType, sizeof s->urlCredType, "%s", v);
        if (ms_json_field(raw, "urlGoToAADError", v, sizeof v) == 0 && v[0])
            snprintf(s->urlGoToAAD, sizeof s->urlGoToAAD, "%s", v);
        if (ms_json_field(raw, "sFT", v, sizeof v) == 0 && v[0]) {
            snprintf(s->sFT, sizeof s->sFT, "%s", v);
        } else if (ms_json_field(raw, "sFTTag", v, sizeof v) == 0 && v[0]) {
            /* sFTTag 形如 <input name="PPFT" ... value="...">，取 value 属性 */
            const char *vp = strstr(v, "value=\"");
            if (vp) {
                char rawv[16384];
                vp += 7;
                size_t o = 0;
                while (*vp && *vp != '"' && o + 1 < sizeof rawv) rawv[o++] = *vp++;
                rawv[o] = 0;
                char un[16384];
                html_unescape(rawv, un, sizeof un);
                snprintf(s->sFT, sizeof s->sFT, "%s", un);
            }
        }
        if (ms_json_field(raw, "sUnauthSessionID", v, sizeof v) == 0 && v[0])
            snprintf(s->uaid, sizeof s->uaid, "%s", v);
        if (ms_json_field(raw, "sCtx", v, sizeof v) == 0 && v[0])
            snprintf(s->sCtx, sizeof s->sCtx, "%s", v);
        /* KMSI 页的 canary 必须原样回传，空值会被判无效（拿到短命授权 ~24h 就死） */
        if (ms_json_field(raw, "sCanary", v, sizeof v) == 0 && v[0])
            snprintf(s->sCanary, sizeof s->sCanary, "%s", v);
        else if (ms_json_field(html, "apiCanary", v, sizeof v) == 0 && v[0])
            snprintf(s->sCanary, sizeof s->sCanary, "%s", v);
        if (ms_json_field(raw, "sRequestCountry", v, sizeof v) == 0 && v[0])
            snprintf(s->country, sizeof s->country, "%s", v);
        if (ms_json_field(raw, "sPageId", v, sizeof v) == 0 && v[0])
            snprintf(s->pageID, sizeof s->pageID, "%s", v);
        if (ms_json_field(raw, "sSiteId", v, sizeof v) == 0 && v[0])
            snprintf(s->siteID, sizeof s->siteID, "%s", v);
        if (ms_json_field(raw, "sClientId", v, sizeof v) == 0 && v[0])
            snprintf(s->siteClient, sizeof s->siteClient, "%s", v);
        free(raw);
    }
    if (!s->sFT[0]) {
        /* 兜底：<input name="PPFT" ... value="..."> */
        const char *ip = strstr(html, "name=\"PPFT\"");
        if (ip) {
            const char *vp = strstr(ip, "value=\"");
            if (vp) {
                vp += 7;
                char rawv[16384];
                size_t o = 0;
                while (*vp && *vp != '"' && o + 1 < sizeof rawv) rawv[o++] = *vp++;
                rawv[o] = 0;
                char un[16384];
                html_unescape(rawv, un, sizeof un);
                snprintf(s->sFT, sizeof s->sFT, "%s", un);
            }
        }
    }
    if (ms_json_field(html, "sFTName", v, sizeof v) == 0 && v[0])
        snprintf(s->sFTName, sizeof s->sFTName, "%s", v);
    /* sRawQueryString：i5030 页面 post.srf 的规范查询串（username/client_id/uaid/contextid/opid/bk）。
       从「提交密码失败后的 route=C530_BA 页面」解析到的 urlPost 会被污染，拿它当提交地址必被拒。 */
    if (ms_json_field(html, "sRawQueryString", v, sizeof v) == 0 && v[0])
        snprintf(s->rawQuery, sizeof s->rawQuery, "%s", v);
    log_print("[MSLOGIN] parse fields ok page=%s urlPost=%d sFT=%d",
              s->pageID, s->urlPost[0] ? 1 : 0, s->sFT[0] ? 1 : 0);
    parse_proofs(s, html);
    log_print("[MSLOGIN] parse proofs ok");
    return s->urlPost[0] || s->sFT[0] || s->pageID[0];
}

static const char *classify_page(const char *html) {
    /* 顺序与 Go 版一致 */
    if (str_icontains(html, "kmsiinterrupt") || strstr(html, "保持登录状态") ||
        str_icontains(html, "stay signed in")) return "kmsi";
    if (strstr(html, "MfaProofs") && strstr(html, "ProofSection")) return "mfa";
    if (strstr(html, "i5600") || strstr(html, "i5321")) return "mfa";
    if (str_icontains(html, "touaccrualinterruptpage")) return "tou";
    if (strstr(html, "\"sPageId\":\"i5245\"")) return "pwd";
    /* 微软验证器（TOTP）页：只认「输入验证器代码」这一页，别把带 authenticator 字样的 MFA 选项页误判 */
    if (strstr(html, "i5990") || str_icontains(html, "enter code from your authenticator app") ||
        strstr(html, "输入验证器应用中的代码") || str_icontains(html, "authenticator verification code"))
        return "totp";
    if (strstr(html, "OtcLoginEligibleProofs") || strstr(html, "\"sPageId\":\"i5030\"") ||
        strstr(html, "\"sPageId\":\"i5600\"")) return "otc";
    if (str_icontains(html, "account.live.com/abuse")) return "locked";
    if (strstr(html, "Proofs") && strstr(html, "SendOtt")) return "wlx";
    return "";
}

static void page_error_code(const char *html, char *out, size_t n) {
    out[0] = 0;
    if (ms_json_field(html, "sErrorCode", out, n) != 0)
        ms_json_field(html, "sErrCode", out, n);
}

/* 出错时把微软返回的页面留一份，省得下次只能对着 sErrorCode 猜 */
static void dump_html(const char *tag, const char *html) {
    if (!html) return;
    char p[160];
    snprintf(p, sizeof p, "%s/mslogin-%s.html", G_DATA_DIR[0] ? G_DATA_DIR : ".", tag);
    FILE *f = fopen(p, "wb");
    if (!f) return;
    fwrite(html, 1, strlen(html), f);
    fclose(f);
    log_print("[MSLOGIN] 页面已存 %s（%zu 字节）", p, strlen(html));
}

/* ---------- 中转页（fmHF 自动提交） ---------- */

/* 找 <form ... action="..."> */
static int find_form_action(const char *html, char *out, size_t n) {
    const char *p = html;
    while ((p = strstr(p, "<form")) != NULL) {
        const char *tagend = strchr(p, '>');
        if (!tagend) break;
        const char *ap = strstr(p, "action=\"");
        if (ap && ap < tagend) {
            ap += 8;
            size_t o = 0;
            while (*ap && *ap != '"' && o + 1 < n) out[o++] = *ap++;
            out[o] = 0;
            return 0;
        }
        p = tagend;
    }
    return -1;
}

/* 收集隐藏 input（name 在 value 前，语义与 Go reHidden 一致） */
static void collect_hidden_inputs(const char *html, sbuf *form) {
    const char *p = html;
    while ((p = strstr(p, "<input")) != NULL) {
        const char *tagend = strchr(p, '>');
        if (!tagend) break;
        const char *np = strstr(p, "name=\"");
        if (np && np < tagend) {
            np += 6;
            char name[256] = "", val[8192] = "";
            size_t o = 0;
            while (*np && *np != '"' && o + 1 < sizeof name) name[o++] = *np++;
            const char *vp = strstr(np, "value=\"");
            if (vp && vp < tagend) {
                vp += 7;
                o = 0;
                while (*vp && *vp != '"' && o + 1 < sizeof val) val[o++] = *vp++;
            }
            if (name[0]) {
                char un[256], uv[8192];
                html_unescape(name, un, sizeof un);
                html_unescape(val, uv, sizeof uv);
                sb_form_add(form, un, uv);
            }
        }
        p = tagend;
    }
}

/* autoForm：识别 JS 自动提交中转页（identity/confirm 等），提交隐藏字段。
   返回 malloc 页面/"CODE:..."；NULL = 不适用或失败。 */
static char *sess_auto_form(ms_session *s, const char *html) {
    if (!strstr(html, "fmHF") && !strstr(html, "identity/confirm")) return NULL;
    char action[2048];
    if (find_form_action(html, action, sizeof action) != 0) return NULL;
    char un[2048];
    html_unescape(action, un, sizeof un);
    sbuf form;
    sb_init(&form);
    collect_hidden_inputs(html, &form);
    ms_resp r;
    int rc = ms_request(s, "POST", un, form.p, form.len, "application/x-www-form-urlencoded",
                        NULL, s->urlPost[0] ? s->urlPost : NULL, NULL, NULL, &r);
    sb_free(&form);
    if (rc != 0) { SETERR(s, "中转页提交失败"); return NULL; }
    char code[2048];
    if (r.location && code_from_str(r.location, code, sizeof code) == 0) {
        ms_resp_free(&r);
        char *out = malloc(strlen(code) + 8);
        sprintf(out, "CODE:%s", code);
        return out;
    }
    if (r.status >= 300 && r.status < 400) {
        char *loc = r.location ? strdup(r.location) : NULL;
        char *body = r.body;
        r.body = NULL;         /* 接管所有权，否则 ms_resp_free 会把它释放掉 */
        ms_resp_free(&r);
        if (!loc || !*loc) return body ? body : strdup("");
        char c2[2048];
        if (code_from_str(loc, c2, sizeof c2) == 0) {
            free(loc); free(body);
            char *out = malloc(strlen(c2) + 8);
            sprintf(out, "CODE:%s", c2);
            return out;
        }
        char next[2048];
        abs_url(s->urlPost[0] ? s->urlPost : un, loc, next, sizeof next);
        free(loc);
        char *h = ms_get_html(s, next, s->urlPost[0] ? s->urlPost : un, 6);
        free(body);
        return h;
    }
    char *body = r.body;
    r.body = NULL;             /* 接管所有权，否则 ms_resp_free 会把它释放掉 */
    ms_resp_free(&r);
    return body ? body : strdup("");
}

/* continueInterstitial：fmHF 链最多跟 5 跳 */
static char *sess_continue_interstitial(ms_session *s, const char *html_in) {
    char *html = strdup(html_in);
    for (int hop = 0; hop < 5 && html; hop++) {
        if (!strstr(html, "fmHF")) return html;
        char *next = sess_auto_form(s, html);
        if (!next) return html;
        free(html);
        html = next;
    }
    return html;
}

/* ---------- 换 token ---------- */

/* exchangeAndSave：授权码 + PKCE 换 token 并落盘；三连兜底 aad+slash / aad+noslash / msa */
static int sess_exchange_save(ms_session *s, const char *code) {
    static const struct { const char *name, *url, *redir; int msa; } tries[] = {
        { "aad+slash",   TOKEN_URL,     MS_REDIRECT_URI,                      0 },
        { "aad+noslash", TOKEN_URL,     "https://visualsupport.microsoft.com", 0 },
        { "msa",         MSL_TOKEN_MSA, MS_REDIRECT_URI,                      1 },
    };
    char err[512] = "";
    for (size_t i = 0; i < sizeof tries / sizeof tries[0]; i++) {
        sbuf form;
        sb_init(&form);
        sb_form_add(&form, "client_id", SPA_CLIENT_ID);
        sb_form_add(&form, "grant_type", "authorization_code");
        sb_form_add(&form, "code", code);
        sb_form_add(&form, "redirect_uri", tries[i].redir);
        sb_form_add(&form, "code_verifier", s->verifier);
        if (!tries[i].msa)
            sb_form_add(&form, "scope", "openid profile offline_access");
        ms_resp r;
        int rc = ms_request(s, "POST", tries[i].url, form.p, form.len,
                            "application/x-www-form-urlencoded", NULL,
                            "https://visualsupport.microsoft.com/",
                            "https://visualsupport.microsoft.com", NULL, &r);
        sb_free(&form);
        if (rc != 0) { snprintf(err, sizeof err, "网络请求失败（EXCHANGE %s）", tries[i].name); continue; }
        log_print("[MSLOGIN] EXCHANGE %s status=%d code_len=%zu", tries[i].name, r.status, strlen(code));
        if (r.status == 200 && r.body) {
            char acct[128] = "";
            int arc = tm_apply_tokens(&s->owner->tm, r.body, acct, sizeof acct);
            ms_resp_free(&r);
            if (arc == 0) {
                s->owner->tm.hdr_variant = 0;   /* 密码登录签的是 SPA token：换票要带 Origin */
                log_print("[MSLOGIN] token 已保存 account=%s", acct);
                return 0;
            }
            snprintf(err, sizeof err, "token 响应缺少 access_token/id_token 或没有 puid");
            continue;
        }
        snprintf(err, sizeof err, "换取 token 失败 HTTP %d: %.200s", r.status,
                 r.body ? r.body : "");
        ms_resp_free(&r);
    }
    SETERR(s, "%s", err[0] ? err : "换取 token 失败");
    return -1;
}

/* ---------- KMSI / TOU / passkey ---------- */

/* submitKMSI：LoginOptions=3 才是「是」（选否拿到 ~24h 短命授权）；canary 优先页面真值 */
static int sess_submit_kmsi(ms_session *s) {
    char referer[512];
    snprintf(referer, sizeof referer, "%s", s->urlPost[0] ? s->urlPost : "https://login.live.com/");
    int last_rc = -1;
    for (int t = 0; t < 2; t++) {
        const char *canary = (t == 0 && s->sCanary[0]) ? s->sCanary : "";
        const char *ctx = (t == 0 && s->sCanary[0]) ? s->sCtx : "";
        sbuf form;
        sb_init(&form);
        sb_form_add(&form, ft_name(s), s->sFT);
        sb_form_add(&form, "canary", canary);
        sb_form_add(&form, "LoginOptions", "3");
        sb_form_add(&form, "type", "28");
        sb_form_add(&form, "hpgrequestid", "");
        sb_form_add(&form, "ctx", ctx);
        log_print("[MSLOGIN] KMSI url=%.80s canary=%.16s ctx=%.12s", referer, canary, ctx);
        ms_resp r;
        int rc = ms_request(s, "POST", s->urlPost, form.p, form.len,
                            "application/x-www-form-urlencoded", NULL, referer, NULL, NULL, &r);
        sb_free(&form);
        if (rc != 0) continue;
        char code[2048];
        if (r.location && code_from_str(r.location, code, sizeof code) == 0) {
            ms_resp_free(&r);
            return sess_exchange_save(s, code);
        }
        char html_err[64] = "";
        if (r.body) page_error_code(r.body, html_err, sizeof html_err);
        ms_resp_free(&r);
        if (html_err[0]) { SETERR(s, "确认登录状态失败（%s）", html_err); continue; }
        SETERR(s, "确认「保持登录状态」后未拿到授权码");
    }
    return last_rc;
}

/* handleTOU：服务协议确认页 POST urlRU + canary（必须 sCanary，用 apiCanary 会 errcode=1078） */
static int sess_handle_tou(ms_session *s, const char *html) {
    char ru[1024] = "", canary[2048] = "";
    ms_json_field(html, "urlRU", ru, sizeof ru);
    ms_json_field(html, "sCanary", canary, sizeof canary);
    if (!ru[0] || !canary[0]) {
        SETERR(s, "服务协议页缺少 urlRU/sCanary，无法自动确认");
        return -1;
    }
    sbuf form;
    sb_init(&form);
    sb_form_add(&form, "canary", canary);
    ms_resp r;
    int rc = ms_request(s, "POST", ru, form.p, form.len,
                        "application/x-www-form-urlencoded", NULL,
                        "https://account.live.com/", NULL, NULL, &r);
    sb_free(&form);
    if (rc != 0) { SETERR(s, "服务协议确认请求失败"); return -1; }
    char code[2048];
    if (r.location && code_from_str(r.location, code, sizeof code) == 0) {
        ms_resp_free(&r);
        return sess_exchange_save(s, code);
    }
    char *loc = r.location ? strdup(r.location) : NULL;
    ms_resp_free(&r);
    if (!loc || !*loc) { SETERR(s, "确认服务协议没有跳转"); free(loc); return -1; }
    if (code_from_str(loc, code, sizeof code) == 0) { free(loc); return sess_exchange_save(s, code); }
    char next[2048];
    abs_url(ru, loc, next, sizeof next);
    free(loc);
    char *h = ms_get_html(s, next, ru, 8);
    if (!h) return -1;
    if (is_code_html(h)) {
        int rc2 = sess_exchange_save(s, h + 5);
        free(h);
        return rc2;
    }
    int fr = sess_finish_page(s, h);
    free(h);
    return fr;
}

/* skipPasskey：通行密钥引导页上报一次 WebAuthn 失败即可跳过 */
static char *sess_skip_passkey(ms_session *s, const char *html) {
    char canary[2048] = "", uaid[128] = "", ru[1024] = "";
    ms_json_field(html, "sCanary", canary, sizeof canary);
    ms_json_field(html, "sUnauthSessionID", uaid, sizeof uaid);
    if (!uaid[0]) snprintf(uaid, sizeof uaid, "%s", s->uaid);
    ms_json_field(html, "urlRU", ru, sizeof ru);
    if (!ru[0]) snprintf(ru, sizeof ru, "%s", s->authURL);
    char eru[512], eru2[2048];
    url_escape(uaid, eru, sizeof eru);
    url_escape(ru, eru2, sizeof eru2);
    char enroll[3072];
    snprintf(enroll, sizeof enroll,
        "https://account.live.com/interrupt/passkey/enroll?uaid=%s&ru=%s", eru, eru2);
    sbuf form;
    sb_init(&form);
    sb_form_add(&form, "canary", canary);
    sb_form_add(&form, "authenticator", "");
    sb_form_add(&form, "transports", "");
    sb_form_add(&form, "aaguid", "");
    sb_form_add(&form, "credentialDeviceType", "");
    sb_form_add(&form, "credentialBackedUp", "");
    sb_form_add(&form, "attestationParseError", "");
    sb_form_add(&form, "error_code", "NotAllowedError");
    sb_form_add(&form, "suberror_code", "");
    sb_form_add(&form, "error_message",
        "The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.");
    sb_form_add(&form, "mediation", "");
    sb_form_add(&form, "clientDataJson", "");
    sb_form_add(&form, "attestationObject", "");
    sb_form_add(&form, "credentialId", "");
    sb_form_add(&form, "clientExtensionResults", "");
    sb_form_add(&form, "i19", "");
    ms_resp r;
    int rc = ms_request(s, "POST", enroll, form.p, form.len,
                        "application/x-www-form-urlencoded", NULL,
                        "https://account.live.com/", NULL, NULL, &r);
    sb_free(&form);
    if (rc != 0) { SETERR(s, "跳过通行密钥请求失败"); return NULL; }
    char code[2048];
    if (r.location && code_from_str(r.location, code, sizeof code) == 0) {
        ms_resp_free(&r);
        char *out = malloc(strlen(code) + 8);
        sprintf(out, "CODE:%s", code);
        return out;
    }
    char *loc = r.location ? strdup(r.location) : NULL;
    char *body = r.body;
    r.body = NULL;             /* 接管所有权，否则 ms_resp_free 会把它释放掉 */
    ms_resp_free(&r);
    if (!loc || !*loc) { SETERR(s, "跳过通行密钥失败（响应 %.200s）", body ? body : ""); free(body); return NULL; }
    if (code_from_str(loc, code, sizeof code) == 0) {
        free(loc); free(body);
        char *out = malloc(strlen(code) + 8);
        sprintf(out, "CODE:%s", code);
        return out;
    }
    char next[2048];
    abs_url(enroll, loc, next, sizeof next);
    free(loc); free(body);
    return ms_get_html(s, next, enroll, 8);
}

/* finishPage：条款/通行密钥/保持登录等授权尾部页面，直到拿到 code */
static int sess_finish_page(ms_session *s, const char *html_in) {
    char *html = strdup(html_in);
    int ret = -1;
    for (int i = 0; i < 5 && html; i++) {
        if (is_code_html(html)) {
            ret = sess_exchange_save(s, html + 5);
            free(html);
            return ret;
        }
        if (strstr(html, "account.live.com/interrupt/passkey") ||
            strstr(html, "Setting up your passkey") ||
            strstr(html, "设置你的通行密钥") ||
            strstr(html, "login.microsoft.com/consumers/fido/create")) {
            char *next = sess_skip_passkey(s, html);
            free(html);
            if (!next) return -1;
            html = next;
            continue;
        }
        const char *kind = classify_page(html);
        if (strcmp(kind, "kmsi") == 0) {
            if (!sess_parse_page(s, html)) { SETERR(s, "保持登录页解析失败"); free(html); return -1; }
            ret = sess_submit_kmsi(s);
            free(html);
            return ret;
        }
        if (strcmp(kind, "tou") == 0) {
            ret = sess_handle_tou(s, html);
            free(html);
            return ret;
        }
        if (strcmp(kind, "pwd") == 0 && s->password[0]) {
            ret = sess_resume_password(s, html);
            free(html);
            return ret;
        }
        if (strcmp(kind, "locked") == 0) {
            SETERR(s, "账号已被锁定，请稍后再试");
            free(html);
            return -1;
        }
        if (strstr(html, "fmHF")) {
            char *next = sess_continue_interstitial(s, html);
            free(html);
            html = next;
            continue;
        }
        break;
    }
    SETERR(s, "授权尾部页面无法识别（pageId=%s）", s->pageID);
    free(html);
    return -1;
}

/* ---------- account.live.com WLX（不常用位置验证） ---------- */

static void parse_wlx(ms_session *s, const char *html) {
    char v[4096];
    s->wlxMode = 1;
    if (ms_json_field(html, "apiCanary", v, sizeof v) == 0 && v[0]) {
        snprintf(s->wlxCanary, sizeof s->wlxCanary, "%s", v);
        if (!s->wlxCanaryOrig[0])
            snprintf(s->wlxCanaryOrig, sizeof s->wlxCanaryOrig, "%s", s->wlxCanary);
    }
    if (ms_json_field(html, "tcxt", v, sizeof v) == 0 && v[0])
        snprintf(s->wlxTcxt, sizeof s->wlxTcxt, "%s", v);
    if (ms_json_field(html, "eipt", v, sizeof v) == 0 && v[0])
        snprintf(s->wlxEipt, sizeof s->wlxEipt, "%s", v);
    if (ms_json_field(html, "uaid", v, sizeof v) == 0 && v[0])
        snprintf(s->wlxUAID, sizeof s->wlxUAID, "%s", v);
    ms_json_numfield(html, "scid", s->wlxScid, sizeof s->wlxScid);
    ms_json_numfield(html, "hpgid", s->wlxHpgid, sizeof s->wlxHpgid);
    if (!s->urlRef[0]) {
        /* "return":{"url":"..."} —— 定向找，避免命中别的 url 字段 */
        const char *rp = strstr(html, "\"return\"");
        if (rp) {
            const char *up = strstr(rp, "\"url\"");
            if (up && up - rp < 64)
                ms_json_field(up, "url", s->urlRef, sizeof s->urlRef);
        }
    }

    /* rawProofList 是被再次转义的 JSON 字符串，取 Email 渠道的 epid（SendOtt 必须带） */
    if (ms_json_field(html, "rawProofList", v, sizeof v) == 0 && v[0]) {
        static char objs[8][1024];
        int n = 0;
        const char *p = strchr(v, '[');
        while (p && n < 8) {
            p = strchr(p, '{');
            if (!p) break;
            int depth = 0, in_str = 0;
            const char *start = p;
            while (*p) {
                if (*p == '"' && (p == start || p[-1] != '\\')) in_str = !in_str;
                if (!in_str) {
                    if (*p == '{') depth++;
                    if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
                }
                p++;
            }
            size_t len = (size_t)(p - start);
            if (len >= 1024) len = 1023;
            memcpy(objs[n], start, len);
            objs[n][len] = 0;
            n++;
        }
        for (int i = 0; i < n; i++) {
            char chan[64] = "", epid[1024] = "", name[256] = "";
            parse_json_str(objs[i], "channel", chan, sizeof chan);
            parse_json_str(objs[i], "epid", epid, sizeof epid);
            parse_json_str(objs[i], "name", name, sizeof name);
            if (str_icontains(chan, "email") && epid[0]) {                snprintf(s->wlxEpid, sizeof s->wlxEpid, "%s", epid);
                snprintf(s->wlxPartial, sizeof s->wlxPartial, "%s", name);
                break;
            }
        }
    }
    if (!s->wlxScid[0]) snprintf(s->wlxScid, sizeof s->wlxScid, "100166");
    if (!s->wlxHpgid[0]) snprintf(s->wlxHpgid, sizeof s->wlxHpgid, "200355");
}

static int wlx_post(ms_session *s, const char *url, const char *body, const char *canary,
                    const char *hpgid, char **resp_out) {
    sbuf hdr;
    sb_init(&hdr);
    sb_fmt(&hdr, "canary: %s\r\n", canary);
    sb_fmt(&hdr, "uaid: %s\r\n", s->wlxUAID);
    sb_fmt(&hdr, "scid: %s\r\n", s->wlxScid);
    sb_fmt(&hdr, "hpgid: %s\r\n", hpgid && *hpgid ? hpgid : s->wlxHpgid);
    sb_append(&hdr, "uiflvr: 1001\r\n");
    sb_append(&hdr, "wlPreferIpt: 1\r\n");
    sb_append(&hdr, "x-ms-apiTransport: xhr\r\n");
    sb_append(&hdr, "x-ms-apiVersion: 2\r\n");
    sb_append(&hdr, "Sec-Fetch-Site: same-origin\r\n");
    sb_append(&hdr, "Sec-Fetch-Mode: cors\r\n");
    sb_append(&hdr, "Sec-Fetch-Dest: empty\r\n");
    if (s->wlxTcxt[0]) sb_fmt(&hdr, "tcxt: %s\r\n", s->wlxTcxt);
    if (s->wlxEipt[0]) sb_fmt(&hdr, "eipt: %s\r\n", s->wlxEipt);
    ms_resp r;
    int rc = ms_request(s, "POST", url, body, strlen(body), "application/json",
                        "application/json", "https://account.live.com/",
                        "https://account.live.com", hdr.p, &r);
    sb_free(&hdr);
    if (rc != 0) { SETERR(s, "WLX 请求失败（%.120s）", url); return -1; }
    log_print("[MSLOGIN] WLX-POST %.80s status=%d resp=%.120s", url, r.status,
              r.body ? r.body : "");
    *resp_out = r.body ? r.body : strdup("");
    free(r.location);
    return 0;
}

/* sendWLXCode：account.live.com SendOtt 发验证码 */
static int send_wlx_code(ms_session *s) {
    if (!s->wlxCanary[0]) { SETERR(s, "验证页里没找到 apiCanary，可能是页面结构变了"); return -1; }
    if (!s->wlxEpid[0]) { SETERR(s, "验证页里没找到邮箱的 epid，无法发送验证码"); return -1; }
    sbuf body;
    sb_init(&body);
    sb_append(&body, "{\"token\":\"\",\"purpose\":\"UnfamiliarLocationHard\",\"epid\":");
    sb_json_str(&body, s->wlxEpid);
    sb_append(&body, ",\"autoVerification\":false,\"autoVerificationFailed\":false,\"confirmProof\":");
    sb_json_str(&body, s->username);
    sb_append(&body, ",\"uiflvr\":\"1001\",\"uaid\":");
    sb_json_str(&body, s->wlxUAID);
    sb_fmt(&body, ",\"scid\":%s,\"hpgid\":200368}", s->wlxScid);
    char *resp = NULL;
    int rc = wlx_post(s, "https://account.live.com/API/Proofs/SendOtt", body.p,
                      s->wlxCanary, s->wlxHpgid, &resp);
    sb_free(&body);
    if (rc != 0) return -1;
    char newcanary[4096] = "", emsg[512] = "";
    ms_json_field(resp, "apiCanary", newcanary, sizeof newcanary);
    parse_json_str(resp, "message", emsg, sizeof emsg);
    free(resp);
    if (!newcanary[0]) {
        SETERR(s, "微软拒绝发送验证码: %s", emsg[0] ? emsg : "响应异常");
        return -1;
    }
    snprintf(s->wlxCanary, sizeof s->wlxCanary, "%s", newcanary);
    s->codeSent = 1;
    return 0;
}

static int verify_wlx_once(ms_session *s, const char *code, const char *canary,
                           char *out_canary, size_t on, char *out_ecode, size_t en,
                           char *out_emsg, size_t mn) {
    sbuf body;
    sb_init(&body);
    sb_append(&body, "{\"code\":");
    sb_json_str(&body, code);
    sb_append(&body, ",\"action\":\"IptVerify\",\"purpose\":\"UnfamiliarLocationHard\",\"epid\":");
    sb_json_str(&body, s->wlxEpid);
    sb_append(&body, ",\"confirmProof\":");
    sb_json_str(&body, s->username);
    sb_append(&body, ",\"uiflvr\":\"1001\",\"uaid\":");
    sb_json_str(&body, s->wlxUAID);
    sb_fmt(&body, ",\"scid\":%s,\"hpgid\":200374}", s->wlxScid);
    char *resp = NULL;
    int rc = wlx_post(s, "https://account.live.com/API/Proofs/VerifyCode", body.p,
                      canary, "200374", &resp);
    sb_free(&body);
    if (rc != 0) return -1;
    ms_json_field(resp, "apiCanary", out_canary, on);
    parse_json_str(resp, "code", out_ecode, en);
    parse_json_str(resp, "message", out_emsg, mn);
    free(resp);
    return 0;
}

/* verifyWLX：提交不常用位置验证码；成功后同一 cookie 会话重跑授权流程 */
static int verify_wlx(ms_session *s, const char *code) {
    log_print("[MSLOGIN] WLX-VERIFY attempt=%d mail=%s", s->verifyFails + 1, s->username);
    char newcanary[4096] = "", ecode[64] = "", emsg[512] = "";
    if (verify_wlx_once(s, code, s->wlxCanary, newcanary, sizeof newcanary,
                        ecode, sizeof ecode, emsg, sizeof emsg) != 0) return -1;
    if (!newcanary[0] && !strcmp(ecode, "500") && s->wlxCanaryOrig[0] &&
        strcmp(s->wlxCanaryOrig, s->wlxCanary)) {
        /* VerifyCode 对新 canary 回 500：换发码前验证页的原始 canary 再试一次 */
        log_print("[MSLOGIN] WLX-VERIFY-500 retry with orig canary");
        if (verify_wlx_once(s, code, s->wlxCanaryOrig, newcanary, sizeof newcanary,
                            ecode, sizeof ecode, emsg, sizeof emsg) != 0) return -1;
    }
    if (!newcanary[0]) {
        s->verifyFails++;
        if (s->verifyFails >= 2)
            SETERR(s, "微软拒绝校验（%s）。%s 已连续失败 %d 次：微软很可能已把本次校验临时锁死，"
                   "请停止尝试和重发，等 30-60 分钟后重新开始一轮登录（填邮箱发一次码 → 等邮件真正到达 → 只填这一次）。",
                   ecode[0] ? ecode : "?",
                   emsg[0] ? emsg : "请确认填的是最新一封邮件里的验证码（邮箱收微软邮件常有几分钟延迟）",
                   s->verifyFails);
        else
            SETERR(s, "微软拒绝校验（%s）。%s", ecode[0] ? ecode : "?",
                   emsg[0] ? emsg : "请确认填的是最新一封邮件里的验证码");
        return -1;
    }
    snprintf(s->wlxCanary, sizeof s->wlxCanary, "%s", newcanary);
    s->wlxMode = 0;
    s->codeSent = 0;
    /* 验证已通过：同一 cookie 会话继续授权流程（走 MSA 端点，AAD 端点会回 AADSTS90100） */
    char preverr[512];
    snprintf(preverr, sizeof preverr, "%s", s->errbuf);
    if (ms_continue_after_wlx(s) != 0) {
        /* 兜底：MSA 端点走不通再试一次完整链路（保留原错误便于对账） */
        int rc = sess_start_login(s);
        if (rc == 0) return 0;
        if (rc == 1) { SETERR(s, "验证已通过，但微软又要求一次验证码，请重试"); return -1; }
        if (!strstr(s->errbuf, "网络请求失败"))
            SETERR(s, "%.200s（兜底完整链路也失败：%.200s）", preverr, s->errbuf);
        return -1;
    }
    return 0;
}

/* continueAfterWLX：验证通过后用现有会话直接向 MSA 端点要授权码 */
static int ms_continue_after_wlx(ms_session *s) {
    if (!s->verifier[0]) { SETERR(s, "内部错误：缺少 PKCE verifier"); return -1; }
    char euri[256];
    url_escape(MS_REDIRECT_URI, euri, sizeof euri);
    char u[1024];
    snprintf(u, sizeof u,
        "%s?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query"
        "&scope=openid%%20profile%%20offline_access&code_challenge=%s&code_challenge_method=S256&prompt=none",
        MS_AUTHORIZE_MSA, SPA_CLIENT_ID, euri, s->challenge);
    char *html = ms_get_html(s, u, "https://visualsupport.microsoft.com/", 8);
    for (int hop = 0; hop < 4 && html; hop++) {
        if (is_code_html(html)) {
            int rc = sess_exchange_save(s, html + 5);
            free(html);
            return rc;
        }
        if (strstr(html, "login_required") || strstr(html, "interaction_required")) {
            SETERR(s, "验证已通过，但登录会话没有建立，请重试");
            free(html);
            return -1;
        }
        if (strstr(html, "fmHF") && !sess_parse_page(s, html)) {
            char *h2 = sess_continue_interstitial(s, html);
            free(html);
            html = h2;
            continue;
        }
        if (!sess_parse_page(s, html)) {
            SETERR(s, "验证通过后页面无法识别");
            free(html);
            return -1;
        }
        const char *kind = classify_page(html);
        if (strcmp(kind, "kmsi") == 0) {
            int rc = sess_submit_kmsi(s);
            free(html);
            return rc;
        }
        if (strcmp(kind, "wlx") == 0) {
            parse_wlx(s, html);
            s->emailAsked = 1;
            s->codeSent = 0;
            s->wlxMode = 1;
            free(html);
            SETERR(s, "验证已通过，但微软要求再验证一次，请在网页上重新填邮箱发码");
            return -1;
        }
        /* 回到密码页：再提交一次密码 */
        int rc = sess_submit_password(s, s->password, NULL);
        free(html);
        if (rc < 0) return -1;
        if (rc == 1) { SETERR(s, "验证已通过，但微软还要求验证码（%s）", s->partialEmail); return -1; }
        if (rc == 0) return 0;
        SETERR(s, "验证通过后登录流程未完成");
        return -1;
    }
    SETERR(s, "验证通过后仍停留在中转页");
    free(html);
    return -1;
}

/* ---------- 发码 / 验码 ---------- */

/* sendMFAMail：密码之后的验证页（i5600）发码。
   三个坑：purpose 必须 eOTT_OneTimePassword；必须带 UIMode=11 且不能带 lcid；
   页面刚渲染就发码会 203（等 2 秒再发，203 再重试一次）。 */
static int send_mfa_mail(ms_session *s) {
    if (!s->epidEmail[0]) { SETERR(s, "没有解析到邮箱验证方式"); return -1; }
    char esid[128], ecl[128];
    url_escape(s->siteID, esid, sizeof esid);
    url_escape(s->siteClient[0] ? s->siteClient : "000000004163F622", ecl, sizeof ecl);
    char u[512];
    snprintf(u, sizeof u, "%s?id=%s&client_id=%s", MS_OTC_LOGIN, esid, ecl);
    snprintf(s->otcOrigFT, sizeof s->otcOrigFT, "%s", s->sFT);
    sbuf form;
    sb_init(&form);
    sb_form_add(&form, "login", s->username);
    sb_form_add(&form, "flowtoken", s->sFT);
    sb_form_add(&form, "purpose", "eOTT_OneTimePassword");
    sb_form_add(&form, "channel", "Email");
    sb_form_add(&form, "ChallengeViewSupported", "1");
    sb_form_add(&form, "uaid", s->uaid);
    if (s->pwdSubmitted) {
        sb_form_add(&form, "AltEmailE", s->epidEmail);
        sb_form_add(&form, "UIMode", "11");
        sleep(2);
    }
    /* ProofConfirmation 只认完整邮箱；没有人工填的就不带，别把掩码塞进去（会 204） */
    if (s->fullEmail[0]) sb_form_add(&form, "ProofConfirmation", s->fullEmail);
    log_print("[MSLOGIN] OTC-SEND-CODE pageId=%s pwdSubmitted=%d proof=%s sFT=%.12s",
              s->pageID, s->pwdSubmitted, s->fullEmail[0] ? s->fullEmail : "(无)", s->sFT);
    int state = 0;
    for (int attempt = 1; attempt <= 2; attempt++) {
        if (attempt == 2) { log_print("[MSLOGIN] OTC-SEND-RETRY attempt=2"); sleep(3); }
        ms_resp r;
        if (ms_request(s, "POST", u, form.p, form.len, "application/x-www-form-urlencoded",
                       "application/json, text/plain, */*", s->urlPost[0] ? s->urlPost : NULL,
                       NULL, NULL, &r) != 0) { sb_free(&form); SETERR(s, "发码网络请求失败"); return -1; }
        char code[2048];
        if (r.location && code_from_str(r.location, code, sizeof code) == 0) {
            ms_resp_free(&r);
            sb_free(&form);
            return sess_exchange_save(s, code);
        }
        state = r.body ? parse_json_int(r.body, "State", 0) : 0;
        log_print("[MSLOGIN] OTC-SEND-RESULT attempt=%d state=%d", attempt, state);
        ms_resp_free(&r);
        if (state != 203) break;
    }
    sb_free(&form);
    if (state != 201) {
        if (state == 206) { SETERR(s, "微软限制了验证码发送频率（短时间内发太多了），请 10 分钟后再手动发一次"); return -1; }
        SETERR(s, "发送验证码失败（State=%d）", state);
        return -1;
    }
    /* FlowToken 只用于判断，不回写 sFT：提交验证码必须用 MFA 页原始 sFT */
    s->codeSent = 1;
    return 0;
}

/* otc_send_try：按一组字段拼 GetOneTimeCode 请求并解析 State。
   返回 0 = 请求已发出（*state_out 为响应 State，newft 为返回的 FlowToken，可能为空串）。 */
static int otc_send_try(ms_session *s, const char *u, const char *purpose,
                        const char *lcid, const char *referer, const char *proof,
                        int withUIMode, int withCanary, int *state_out,
                        char *newft, size_t nf, char *body_out, size_t bn) {
    sbuf form;
    sb_init(&form);
    sb_form_add(&form, "login", s->username);
    sb_form_add(&form, "flowtoken", s->sFT);
    sb_form_add(&form, "purpose", purpose);
    sb_form_add(&form, "channel", "Email");
    sb_form_add(&form, "ChallengeViewSupported", "1");
    sb_form_add(&form, "uaid", s->uaid);
    sb_form_add(&form, "AltEmailE", s->epidEmail);
    if (lcid && lcid[0]) sb_form_add(&form, "lcid", lcid);
    if (withUIMode) sb_form_add(&form, "UIMode", "11");
    if (withCanary) sb_form_add(&form, "canaryFlowToken", s->sFT);
    sb_form_add(&form, "ProofConfirmation", proof);
    if (newft && nf) newft[0] = 0;
    if (body_out && bn) body_out[0] = 0;
    ms_resp r;
    int ret = ms_request(s, "POST", u, form.p, form.len, "application/x-www-form-urlencoded",
                         "application/json, text/plain, */*", referer, NULL, NULL, &r);
    sb_free(&form);
    if (ret != 0) return -1;
    if (body_out && bn && r.body) {
        size_t n = strlen(r.body);
        if (n >= bn) n = bn - 1;
        memcpy(body_out, r.body, n);
        body_out[n] = 0;
    }
    *state_out = r.body ? parse_json_int(r.body, "State", 0) : 0;
    if (newft && nf && r.body) ms_json_field(r.body, "FlowToken", newft, nf);
    ms_resp_free(&r);
    return 0;
}

/* sendOTCNow：i5030 免密码一次性验证码发码。
   实测坑位（2026-11-20 现场日志）：
     1) ProofConfirmation 必须是**人工填的完整邮箱**，传页面掩码（bk*****@outlook.com）
        服务端一律判「输入错误」= State 204；
     2) purpose 这一页要用 eOTT_OtcLogin（实测 201；eOTT_OneTimePassword 反而回 203）；
     3) 必须带 UIMode=11，少了会被当成请求不完整。 */
static int send_otc_now(ms_session *s) {
    if (!s->epidEmail[0]) { SETERR(s, "这个账号的登录页里没有可用的邮箱验证方式"); return -1; }
    /* 提交验证码的 PPFT 默认用「发码前页面」的原始 sFT：GetOneTimeCode 返回的 FlowToken
       只属于发码会话。万一原始 sFT 被拒，sess_submit_email_code 会用 otcNewFT 再试一次。 */
    snprintf(s->otcOrigFT, sizeof s->otcOrigFT, "%s", s->sFT);
    s->otcFTTried = 0;
    s->otcNewFT[0] = 0;
    char ecl[128];
    url_escape(s->siteClient[0] ? s->siteClient : "000000004163F622", ecl, sizeof ecl);
    char u[512];
    snprintf(u, sizeof u, "%s?id=%s&client_id=%s", MS_OTC_LOGIN, s->siteID, ecl);
    const char *proof = s->fullEmail[0] ? s->fullEmail : s->partialEmail;
    const char *lcid = s->otcLcid[0] ? s->otcLcid : "2052";
    const char *referer = s->otcReferer[0] ? s->otcReferer : "https://login.live.com/";
    log_print("[MSLOGIN] OTC-SEND-CODE pageId=%s lcid=%s proof=%s 掩码=%s",
              s->pageID, lcid, s->fullEmail[0] ? s->fullEmail : "(缺完整邮箱，只能试掩码)", s->partialEmail);

    /* 字段组合按「实测最可信 → 兜底」顺序试：201 就停，206 是限流也立刻停。
       实测日志（2026-11-20 15:34:39）：i5030 免密码页上 eOTT_OneTimePassword → 203，
       eOTT_OtcLogin → 201，所以这一页把 OtcLogin 放第一个。 */
    struct { const char *purpose; const char *lcid; int uimode; int canary; } tries[3] = {
        { "eOTT_OtcLogin",        lcid, 1, 0 },
        { "eOTT_OneTimePassword", lcid, 1, 0 },
        { "eOTT_OneTimePassword", "",   1, 1 },
    };
    int state = 0;
    char body[512];
    for (int i = 0; i < 3; i++) {
        if (i) { log_print("[MSLOGIN] OTC-SEND-RETRY try=%d purpose=%s", i + 1, tries[i].purpose); sleep(2); }
        if (otc_send_try(s, u, tries[i].purpose, tries[i].lcid, referer, proof,
                         tries[i].uimode, tries[i].canary, &state,
                         s->otcNewFT, sizeof s->otcNewFT, body, sizeof body) != 0) {
            SETERR(s, "发码网络请求失败");
            return -1;
        }
        log_print("[MSLOGIN] OTC-SEND try=%d purpose=%s state=%d body=%.160s",
                  i + 1, tries[i].purpose, state, body);
        if (state == 201 || state == 206) break;
    }
    if (state != 201) {
        if (state == 206) { SETERR(s, "微软限制了验证码发送频率（短时间请求太多次），请 10 分钟后再手动发一次"); return -1; }
        if (state == 204) {
            SETERR(s, "发送一次性验证码失败（State=204 输入错误）：页面上的收件邮箱是掩码 %s，"
                      "微软要求填**完整**邮箱地址，请核对后再点一次提交", s->partialEmail);
            return -1;
        }
        SETERR(s, "发送一次性验证码失败（State=%d）", state);
        return -1;
    }
    log_print("[MSLOGIN] OTC-SEND-OK newFlowToken=%d 字符", (int)strlen(s->otcNewFT));
    s->codeSent = 1;
    s->otcMode = 1;
    return 0;
}

/* sendCodeMail：整个程序里唯一真的发码的地方（必须人工触发） */
static int send_code_mail(ms_session *s) {
    if (s->wlxMode) return send_wlx_code(s);
    if (s->otcMode) return send_otc_now(s);
    return send_mfa_mail(s);
}

/* resumePassword：验码通过后微软要求回到密码步骤时补交缓存密码 */
static int sess_resume_password(ms_session *s, const char *html) {
    s->pwdResumes++;
    if (s->pwdResumes > 3) { SETERR(s, "微软反复要求输入密码，登录流程死循环"); return -1; }
    if (!sess_parse_page(s, html)) { SETERR(s, "密码页解析失败"); return -1; }
    log_print("[MSLOGIN] RESUME-PWD page=%s urlPost=%.80s", s->pageID, s->urlPost);
    int rc = sess_submit_password(s, s->password, NULL);
    if (rc < 0) return -1;
    if (rc == 0) return 0;
    if (rc == 1) { SETERR(s, "验证码已通过、密码也通过，但微软又要求一次邮箱验证码，请重试一次"); return -1; }
    SETERR(s, "验证码已通过，但密码步骤没有走完");
    return -1;
}

/* submitEmailCode：提交 6 位验证码（PPFT 用 MFA 页原始 sFT；表单 type=18） */
static int sess_submit_email_code(ms_session *s, const char *code_in) {
    if (!s->codeSent) { SETERR(s, "尚未发送验证码"); return -1; }
    char code[64];
    size_t o = 0;
    for (const char *p = code_in; *p && o + 1 < sizeof code; p++)
        if (*p != ' ') code[o++] = *p;
    code[o] = 0;
    if (s->wlxMode) return verify_wlx(s, code);
    const char *ppft = s->otcOrigFT[0] ? s->otcOrigFT : s->sFT;
    /* 提交地址：i5030 用页面 sRawQueryString 重建规范 post.srf 查询串。
       「先提交密码失败」解析到的 urlPost 会带 route=C530_BA，拿它提交验证码必被无视。 */
    char up[1200];
    if (s->otcMode && s->rawQuery[0])
        snprintf(up, sizeof up, "https://login.live.com/ppsecure/post.srf?%s", s->rawQuery);
    else
        snprintf(up, sizeof up, "%s", s->urlPost);
    sbuf form;
    sb_init(&form);
    if (s->otcMode) {
        /* i5030「一次性验证码登录」：字段集照真实浏览器（type=27）。
           用 MFA 的 type=18/AddTD 那套会被 post.srf 当成无效表单，直接返回原页。 */
        sb_form_add(&form, "SentProofIDE", s->epidEmail);
        sb_form_add(&form, "ProofConfirmation", s->fullEmail[0] ? s->fullEmail : s->username);
        sb_form_add(&form, "ProofType", "1");
        sb_form_add(&form, "otc", code);
        sb_form_add(&form, "ps", "3");
        sb_form_add(&form, ft_name(s), ppft);
        sb_form_add(&form, "type", "27");
        sb_form_add(&form, "login", s->username);
        sb_form_add(&form, "loginfmt", s->username);
        sb_form_add(&form, "LoginOptions", "3");
        sb_form_add(&form, "canary", "");
        sb_form_add(&form, "ctx", "");
        sb_form_add(&form, "hpgrequestid", "");
        sb_form_add(&form, "NewUser", "1");
        sb_form_add(&form, "PPSX", "Pa");
        sb_form_add(&form, "FoundMSAs", "");
        sb_form_add(&form, "fspost", "0");
        sb_form_add(&form, "i21", "0");
        sb_form_add(&form, "CookieDisclosure", "0");
        sb_form_add(&form, "IsFidoSupported", "1");
        sb_form_add(&form, "isSignupPost", "0");
        sb_form_add(&form, "isRecoveryAttemptPost", "0");
        sb_form_add(&form, "i13", "0");
        sb_form_add(&form, "lrt", "");
        sb_form_add(&form, "lrtPartition", "");
        sb_form_add(&form, "hisRegion", "");
        sb_form_add(&form, "hisScaleUnit", "");
        sb_form_add(&form, "cpr", "0");
        sb_form_add(&form, "psRNGCDefaultType", "");
        sb_form_add(&form, "psRNGCEntropy", "");
        sb_form_add(&form, "psRNGCSLK", "");
    } else {
        sb_form_add(&form, "AddTD", "true");
        sb_form_add(&form, "SentProofIDE", s->epidEmail);
        sb_form_add(&form, "GeneralVerify", "false");
        sb_form_add(&form, ft_name(s), ppft);
        sb_form_add(&form, "canary", "");
        sb_form_add(&form, "sacxt", "0");
        sb_form_add(&form, "hpgrequestid", "");
        sb_form_add(&form, "hideSmsInMfaProofs", "false");
        sb_form_add(&form, "type", "18");
        sb_form_add(&form, "login", s->username);
        sb_form_add(&form, "infoPageShown", "0");
        sb_form_add(&form, "ProofConfirmation", s->username);
        sb_form_add(&form, "otc", code);
    }
    log_print("[MSLOGIN] OTC-VERIFY url=%.110s page=%s ftype=%s ppft=%.10s epid=%.14s",
              up, s->pageID, s->otcMode ? "27" : "18", ppft, s->epidEmail);
    ms_resp r;
    if (ms_request(s, "POST", up, form.p, form.len,
                   "application/x-www-form-urlencoded", NULL,
                   up, NULL, NULL, &r) != 0) {
        sb_free(&form);
        SETERR(s, "验证码提交网络请求失败");
        return -1;
    }
    sb_free(&form);
    char code2[2048];
    char *loc = r.location ? strdup(r.location) : NULL;
    char *html = r.body;
    r.body = NULL;             /* 接管所有权，否则 ms_resp_free 会把它释放掉 */
    int st = r.status;
    ms_resp_free(&r);
    log_print("[MSLOGIN] OTC-VERIFY resp status=%d loc=%.120s", st, loc ? loc : "");
    if (loc && code_from_str(loc, code2, sizeof code2) == 0) {
        free(loc); free(html);
        return sess_exchange_save(s, code2);
    }
    /* 3xx 跟随（提交成功通常会跳向服务条款页 / 保持登录页） */
    char *cur_loc = loc;
    for (int hop = 0; hop < 4; hop++) {
        if (st < 300 || st >= 400 || !cur_loc || !*cur_loc) break;
        if (code_from_str(cur_loc, code2, sizeof code2) == 0) {
            free(cur_loc); free(html);
            return sess_exchange_save(s, code2);
        }
        char next[2048];
        abs_url(up, cur_loc, next, sizeof next);
        free(cur_loc);
        cur_loc = NULL;
        char *h2 = ms_get_html(s, next, up, 6);
        if (!h2) { free(html); return -1; }
        free(html);
        html = h2;
        st = 200;
    }
    free(cur_loc);
    if (!html) { SETERR(s, "验证码提交后无响应页面"); return -1; }
    char ec[64] = "";
    page_error_code(html, ec, sizeof ec);
    if (ec[0]) {
        /* 原始 sFT 被当成无效会话时，微软会回「验证码不正确」。此时换用
           GetOneTimeCode 返回的 FlowToken 再提交一次（只试一次）。 */
        if (s->otcMode && !s->otcFTTried && s->otcNewFT[0]) {
            s->otcFTTried = 1;
            snprintf(s->otcOrigFT, sizeof s->otcOrigFT, "%s", s->otcNewFT);
            log_print("[MSLOGIN] OTC-VERIFY-RETRY ec=%s 换用发码返回的 FlowToken 重试 PPFT", ec);
            free(html);
            return sess_submit_email_code(s, code_in);
        }
        char msg[256];
        if (strcmp(ec, "8004348F") == 0)          /* 微软的「验证码不正确」 */
            snprintf(msg, sizeof msg, "验证码不正确（8004348F，可能不是最新一封邮件里的码）");
        else if (strcmp(ec, "80048877") == 0)
            snprintf(msg, sizeof msg, "这个验证码已过期，请重新发一次");
        else
            snprintf(msg, sizeof msg, "验证码校验失败（%s）", ec);
        /* 失败页会带着新的 bk/sFT 重渲染：重新解析，用户再填一次才能对上 */
        s->otcOrigFT[0] = 0;
        sess_parse_page(s, html);
        SETERR(s, "%s", msg);
        free(html);
        return -1;
    }
    /* 验码通过后微软常把流程交回「输入密码」页（干净、无错误码），直接补交密码继续 */
    if (strcmp(classify_page(html), "pwd") == 0) {
        int rc = sess_resume_password(s, html);
        free(html);
        return rc;
    }
    int fr = sess_finish_page(s, html);
    free(html);
    if (fr != 0 && strstr(s->errbuf, "无法识别"))
        SETERR(s, "验证码不正确或已过期");
    return fr;
}

/* handleVerifyInput：带 @ = 发一封码；否则 = 提交验证码 */
static int sess_handle_verify_input(ms_session *s, const char *input, int *sent) {
    char v[256];
    snprintf(v, sizeof v, "%s", input);
    char *e = v + strlen(v);
    while (e > v && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
    char *b = v;
    while (*b == ' ' || *b == '\t') b++;
    if (!*b) { SETERR(s, "请输入接收验证码的邮箱，或 6 位验证码"); return -1; }
    if (strchr(b, '@')) {
        if (!s->emailAsked && !s->codeSent) {
            SETERR(s, "当前没有等验证码的登录，请先点「登录」提交账号密码");
            return -1;
        }
        /* 人工填的完整邮箱要落进会话：微软的 ProofConfirmation 字段只认完整地址，
           用页面掩码（bk*****@outlook.com）回 State=204「输入错误」。 */
        snprintf(s->fullEmail, sizeof s->fullEmail, "%s", b);
        if (send_code_mail(s) != 0) return -1;
        s->emailAsked = 0;
        snprintf(s->emailSent, sizeof s->emailSent, "%s", b);
        char m[256];
        mask_email(b, m, sizeof m);
        log_print("[MSLOGIN] HUMAN-SEND mail=%s mode=wlx:%d otc:%d", m, s->wlxMode, s->otcMode);
        *sent = 1;
        return 0;
    }
    *sent = 0;
    return sess_submit_email_code(s, b);
}

/* ---------- 密码提交 ---------- */

/* submitPasswordHTML：提交密码表单；返回 0 完成 / 1 需要验证码 / -1 失败；
   html_out（可 NULL）返回响应页 malloc HTML。 */
static int sess_submit_password(ms_session *s, const char *password, char **html_out) {
    if (html_out) *html_out = NULL;
    if (!s->urlPost[0]) { SETERR(s, "缺少密码提交地址"); return -1; }
    sbuf form;
    sb_init(&form);
    sb_form_add(&form, "ps", "2");
    sb_form_add(&form, "psRNGCDefaultType", "");
    sb_form_add(&form, "psRNGCEntropy", "");
    sb_form_add(&form, "psRNGCSLK", "");
    sb_form_add(&form, "canary", "");
    sb_form_add(&form, "ctx", "");
    sb_form_add(&form, "hpgrequestid", "");
    sb_form_add(&form, ft_name(s), s->sFT);
    sb_form_add(&form, "PPSX", "Passpor");
    sb_form_add(&form, "NewUser", "1");
    sb_form_add(&form, "FoundMSAs", "");
    sb_form_add(&form, "fspost", "0");
    sb_form_add(&form, "i21", "0");
    sb_form_add(&form, "CookieDisclosure", "0");
    sb_form_add(&form, "IsFidoSupported", "1");
    sb_form_add(&form, "isSignupPost", "0");
    sb_form_add(&form, "isRecoveryAttemptPost", "0");
    sb_form_add(&form, "i13", "0");
    sb_form_add(&form, "login", s->username);
    sb_form_add(&form, "loginfmt", s->username);
    sb_form_add(&form, "type", "11");
    sb_form_add(&form, "LoginOptions", "3");
    sb_form_add(&form, "lrt", "");
    sb_form_add(&form, "lrtPartition", "");
    sb_form_add(&form, "hisRegion", "");
    sb_form_add(&form, "hisScaleUnit", "");
    sb_form_add(&form, "cpr", "0");
    sb_form_add(&form, "passwd", password);
    s->pwdSubmitted = 1;
    log_print("[MSLOGIN] PWD-POST url=%.80s page=%s sFT=%.12s", s->urlPost, s->pageID, s->sFT);
    ms_resp r;
    if (ms_request(s, "POST", s->urlPost, form.p, form.len,
                   "application/x-www-form-urlencoded", NULL,
                   "https://login.microsoftonline.com/", NULL, NULL, &r) != 0) {
        sb_free(&form);
        SETERR(s, "密码提交网络请求失败");
        return -1;
    }
    sb_free(&form);
    char code[2048];
    char *loc = r.location ? strdup(r.location) : NULL;
    char *html = r.body;
    r.body = NULL;             /* 接管所有权，否则 ms_resp_free 会把它释放掉 */
    int st = r.status;
    ms_resp_free(&r);
    log_print("[MSLOGIN] PWD-LOC %.180s", loc ? loc : "(无)");
    if (loc && code_from_str(loc, code, sizeof code) == 0) {
        free(loc); free(html);
        return sess_exchange_save(s, code) == 0 ? 0 : -1;
    }
    /* 3xx 跟随（Location 带 code 直接换 token） */
    char *cur_loc = loc;
    for (int hop = 0; hop < 4; hop++) {
        if (st < 300 || st >= 400 || !cur_loc || !*cur_loc) break;
        log_print("[MSLOGIN] PWD-REDIR hop=%d loc=%.180s", hop, cur_loc);
        if (code_from_str(cur_loc, code, sizeof code) == 0) {
            free(cur_loc); free(html);
            return sess_exchange_save(s, code) == 0 ? 0 : -1;
        }
        char next[2048];
        abs_url(s->urlPost, cur_loc, next, sizeof next);
        free(cur_loc);
        cur_loc = NULL;
        ms_resp r2;
        if (ms_request(s, "GET", next, NULL, 0, NULL, NULL, s->urlPost, NULL, NULL, &r2) != 0) {
            free(html);
            SETERR(s, "密码提交后跳转网络请求失败");
            return -1;
        }
        cur_loc = r2.location ? strdup(r2.location) : NULL;
        free(html);
        html = r2.body;
        r2.body = NULL;        /* 接管所有权 */
        st = r2.status;
        ms_resp_free(&r2);
    }
    free(cur_loc);
    if (!html) { SETERR(s, "密码提交后无响应页面"); return -1; }
    log_print("[MSLOGIN] PWD-STAGE1 st=%d len=%zu", st, strlen(html));
    /* 中转页自动提交后再判断 */
    for (int i = 0; i < 3; i++) {
        char *h2 = sess_auto_form(s, html);
        if (!h2) break;
        log_print("[MSLOGIN] PWD-STAGE2 hop=%d len=%zu", i, strlen(h2));
        if (is_code_html(h2)) {
            int rc = sess_exchange_save(s, h2 + 5);
            free(h2); free(html);
            return rc == 0 ? 0 : -1;
        }
        free(html);
        html = h2;
    }
    const char *kind = classify_page(html);
    log_print("[MSLOGIN] PWD-RESULT kind=%s pageId=%s", kind, s->pageID);
    int ret = -1;
    if (strcmp(kind, "kmsi") == 0) {
        sess_parse_page(s, html);
        ret = sess_submit_kmsi(s) == 0 ? 0 : -1;
    } else if (strcmp(kind, "mfa") == 0) {
        sess_parse_page(s, html);
        if (!s->epidEmail[0])
            SETERR(s, "微软要求验证，但页面里没有邮箱验证方式");
        else
            ret = 1;   /* 掩码邮箱由调用方从 partialEmail 取 */
    } else if (strcmp(kind, "pwd") == 0) {
        /* i5030 上提交密码后微软把流程交回真正的密码页（i5245）——在这页再提交一次 */
        if (s->pwdResumes >= 2) {
            SETERR(s, "微软反复要求输入密码，登录流程死循环");
        } else {
            s->pwdResumes++;
            if (!sess_parse_page(s, html)) {
                SETERR(s, "密码页解析失败");
            } else {
                log_print("[MSLOGIN] PWD-VIEW-RESUBMIT page=%s urlPost=%.80s", s->pageID, s->urlPost);
                ret = sess_submit_password(s, password, html_out);
                free(html);
                return ret;
            }
        }
    } else if (strcmp(kind, "tou") == 0) {
        ret = sess_handle_tou(s, html);
    } else if (strcmp(kind, "totp") == 0) {
        /* 微软验证器（TOTP）页：网页流程本版不实现输入动态码。
           2FA 账号请改「设备码」登录 —— 密码/2FA 都在浏览器里完成，客户端只轮询 token。 */
        dump_html("totp", html);
        SETERR(s, "该账号要求 Authenticator（6 位动态码）验证，网页流程不支持；"
                  "请把这个实例的登录方式改成「设备码」，在浏览器里完成一次即可");
    } else if (strcmp(kind, "locked") == 0) {
        SETERR(s, "账号已被锁定，请稍后再试");
    } else if (strcmp(kind, "wlx") == 0) {
        /* account.live.com 的「验证你的账户」页：只解析参数，发码等人工点 */
        parse_wlx(s, html);
        s->emailAsked = 1;
        if (s->wlxPartial[0])
            snprintf(s->partialEmail, sizeof s->partialEmail, "%s", s->wlxPartial);
        else
            mask_email(s->username, s->partialEmail, sizeof s->partialEmail);
        ret = 1;
    } else {
        char ec[64] = "";
        page_error_code(html, ec, sizeof ec);
        dump_html(ec[0] ? ec : "post-password", html);
        if (page_cookie_mismatch(html)) {
            purge_cookie_jar(s);
            SETERR(s, "登录会话 cookie 已过期（微软 contextID 不匹配），已清掉旧 cookie 存档，"
                      "下一轮会重新冷登录并走邮箱验证码");
        } else {
        /* 账号受限（长期未用/异地）时，微软会在「验证身份」页上照样带 sErrorCode=80046709，
           但页面里是邮箱验证入口 —— 这不是密码错，要走人工发码流程，别再报「密码不正确」。
           判据用页面里真实的发码入口（SendOtt / OtcLoginEligibleProofs），纯密码错页没有这些。 */
        int verify_form = strstr(html, "SendOtt") != NULL
                          || strstr(html, "OtcLoginEligibleProofs") != NULL;
        if (verify_form) {
            log_print("[MSLOGIN] PWD->VERIFY-FALLBACK 页面有邮箱验证入口（%s），转人工发码", ec);
            ret = sess_send_otc(s, html);      /* 1 = 等人工填收件邮箱；-1 已 SETERR */
            if (ret < 0 && !s->errbuf[0])
                SETERR(s, "账号需要邮箱验证，但这个页面解析不出验证入口");
        } else if (ec[0]) {
            SETERR(s, "微软拒绝登录（%s），可能是密码错误或需要额外验证", ec);
        } else {
            SETERR(s, "密码提交后页面无法识别（pageId=%s）", s->pageID);
        }
        }
    }
    if (html_out) *html_out = html;
    else free(html);
    return ret;
}

/* ---------- i5030 一次性验证码视图 ---------- */

/* sendOTC：只解析页面、不发码；返回 1 需要人工填收件邮箱 */
static int sess_send_otc(ms_session *s, const char *html) {
    if (!sess_parse_page(s, html)) { SETERR(s, "一次性验证码页解析失败"); return -1; }
    log_print("[MSLOGIN] OTC-PREP page=%s urlPost=%.80s sFT=%.12s epid=%.16s",
              s->pageID, s->urlPost, s->sFT, s->epidEmail);
    if (!s->epidEmail[0]) { SETERR(s, "这个账号的登录页里没有可用的邮箱验证方式"); return -1; }
    s->otcMode = 1;
    s->emailAsked = 1;
    snprintf(s->otcLcid, sizeof s->otcLcid, "1033");
    char v[64];
    if (ms_json_field(html, "iRequestLCID", v, sizeof v) == 0 && v[0])
        snprintf(s->otcLcid, sizeof s->otcLcid, "%s", v);
    snprintf(s->otcReferer, sizeof s->otcReferer, "%s",
             s->urlPost[0] ? s->urlPost : "https://login.live.com/");
    if (!s->partialEmail[0]) mask_email(s->username, s->partialEmail, sizeof s->partialEmail);
    return 1;
}

/* ---------- 主流程 ---------- */

/* startPasswordLogin；返回 0 完成 / 1 需要验证码（掩码在 s->partialEmail）/ -1 失败 */
static int sess_start_login(ms_session *s) {
    const char *password = s->password;
    pkce_pair(s);
    char euri[256];
    url_escape(MS_REDIRECT_URI, euri, sizeof euri);
    char authorize[1024];
    snprintf(authorize, sizeof authorize,
        "%s?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query"
        "&scope=openid%%20profile%%20offline_access&code_challenge=%s&code_challenge_method=S256"
        "&prompt=select_account&sso_reload=True",
        MS_AUTHORIZE_URL, SPA_CLIENT_ID, euri, s->challenge);
    snprintf(s->authURL, sizeof s->authURL, "%s", authorize);

    char *html = ms_get_html(s, authorize, "https://visualsupport.microsoft.com/", 6);
    if (!html) return -1;
    log_print("[MSLOGIN] authorize GET ok len=%zu", strlen(html));
    if (is_code_html(html)) {
        int rc = sess_exchange_save(s, html + 5);
        free(html);
        return rc;
    }
    if (!sess_parse_page(s, html)) {
        SETERR(s, "无法解析微软登录页（页面结构可能变化）");
        free(html);
        return -1;
    }

    /* 第二步：GetCredentialType，拿 FlowToken（只有 AAD 页面有这一步） */
    if (s->urlCredType[0]) {
        sbuf body;
        sb_init(&body);
        sb_append(&body, "{\"username\":");
        sb_json_str(&body, s->username);
        sb_append(&body, ",\"isOtherIdpSupported\":true,\"checkPhones\":false,"
                         "\"isRemoteNGCSupported\":true,\"isCookieBannerShown\":false,"
                         "\"isFidoSupported\":true,\"originalRequest\":");
        sb_json_str(&body, s->sCtx);
        sb_append(&body, ",\"country\":");
        sb_json_str(&body, s->country);
        sb_append(&body, ",\"forceotclogin\":false,\"isExternalFederationDisallowed\":false,"
                         "\"isRemoteConnectSupported\":false,\"federationFlags\":0,"
                         "\"isSignup\":false,\"flowToken\":");
        sb_json_str(&body, s->sFT);
        sb_append(&body, ",\"isAccessPassSupported\":true,\"isQrCodePinSupported\":true}");
        char reqid[40];
        guid36(reqid, sizeof reqid);
        char reqhdr[64];
        snprintf(reqhdr, sizeof reqhdr, "client-request-id: %s\r\n", reqid);
        ms_resp r;
        if (ms_request(s, "POST", s->urlCredType, body.p, body.len, "application/json",
                       "application/json", authorize, NULL, reqhdr, &r) == 0 && r.body) {
            char ft[16384] = "";
            if (ms_json_field(r.body, "FlowToken", ft, sizeof ft) == 0 && ft[0])
                snprintf(s->sFT, sizeof s->sFT, "%s", ft);
        }
        ms_resp_free(&r);
        sb_free(&body);
    }

    /* 第三步：GET 密码页（AAD 页面才有；MSA 端点的 authorize 页本身就是密码页） */
    if (s->urlGoToAAD[0]) {
        char euser[512];
        url_escape(s->username, euser, sizeof euser);
        char go[2048];
        snprintf(go, sizeof go, "%s&jsh=&jshp=&username=%s&login_hint=%s",
                 s->urlGoToAAD, euser, euser);
        free(html);
        html = ms_get_html(s, go, "https://login.microsoftonline.com/", 6);
        if (!html) return -1;
        if (is_code_html(html)) {
            int rc = sess_exchange_save(s, html + 5);
            free(html);
            return rc;
        }
    }
    if (!sess_parse_page(s, html)) {
        /* 可能是「继续」中转页（身份验证后常见）：自动提交后再判断 */
        if (strstr(html, "fmHF")) {
            char *h2 = sess_continue_interstitial(s, html);
            free(html);
            if (!h2) return -1;
            if (is_code_html(h2)) {
                int rc = sess_exchange_save(s, h2 + 5);
                free(h2);
                return rc;
            }
            html = h2;
            const char *kind = classify_page(html);
            if (strcmp(kind, "kmsi") == 0) {
                sess_parse_page(s, html);
                free(html);
                return sess_submit_kmsi(s);
            }
            if (strcmp(kind, "wlx") == 0) {
                parse_wlx(s, html);
                s->emailAsked = 1;
                if (s->wlxPartial[0])
                    snprintf(s->partialEmail, sizeof s->partialEmail, "%s", s->wlxPartial);
                else
                    mask_email(s->username, s->partialEmail, sizeof s->partialEmail);
                free(html);
                return 1;
            }
        }
    }
    if (!sess_parse_page(s, html)) {
        SETERR(s, "无法解析密码输入页（页面结构可能变化）");
        free(html);
        return -1;
    }

    /* 微软对长期未用的账号默认给「一次性验证码」视图（i5030）。
       照 QCID 做法「先密码、再邮箱码」，按优先级试三条路：
       ① urlLogin 切到密码视图 ② 在 i5030 页直接提交密码 ③ 微软打回 i5245 再提交一次。
       三条都走不通才退回免密码一次性验证码，并在日志里写明「没用密码」。 */
    if (strcmp(classify_page(html), "otc") == 0) {
        char urlLogin[1024] = "";
        ms_json_field(html, "urlLogin", urlLogin, sizeof urlLogin);
        if (urlLogin[0]) {
            char *h2 = ms_get_html(s, urlLogin, "https://login.live.com/", 6);
            if (h2) {
                if (is_code_html(h2)) {
                    int rc = sess_exchange_save(s, h2 + 5);
                    free(h2); free(html);
                    return rc;
                }
                if (page_cookie_mismatch(h2)) {
                    /* 微软把 urlLogin 顶回「contextID 对不上 cookie」的错误页。别整轮作废：
                       当前这页 i5030 里就有邮箱验证入口，直接在这页发免密码验证码。
                       （不改 cookie 存档 —— 本次流程的 cookie 是这页自己的上下文，清掉反而对不上） */
                    free(h2);
                    log_print("[MSLOGIN] urlLogin 被顶回错误页，改用当前 i5030 页直接发一次性验证码");
                    int rc_otc = sess_send_otc(s, html);
                    free(html);
                    return rc_otc;
                }
                if (sess_parse_page(s, h2)) {
                    free(html);
                    html = h2;
                    log_print("[MSLOGIN] OTC->LOGIN-VIEW ok pageId=%s kind=%s", s->pageID, classify_page(html));
                } else {
                    free(h2);
                }
            }
        }
    }
    /* 只有页面里真有密码输入框才试密码。微软给「Get a code to sign in」视图（i5030）时
       页面根本没有密码框，硬发 password 字段只会被无视（返回同一页 + 80041012），
       而且会把 urlPost 污染成 route=C530_BA，导致后面提交验证码必被拒。 */
    int has_pwd_field = strstr(html, "type=\"password\"") != NULL ||
                        strstr(html, "i0118") != NULL;
    if (strcmp(classify_page(html), "otc") == 0 && password[0] && has_pwd_field) {
        /* ② 在 i5030 这页直接提交密码，看微软给什么页（打回 i5245 时
           submit_password 内部会自动补交一次） */
        int rc = sess_submit_password(s, password, NULL);
        if (rc == 0) { free(html); return 0; }
        if (rc == 1) { free(html); return 1; }
        log_print("[MSLOGIN] OTC-PWD-FAIL %s", s->errbuf);
    }
    if (strcmp(classify_page(html), "otc") == 0) {
        log_print("[MSLOGIN] OTC-FALLBACK 密码视图不可用，退回免密码一次性验证码");
        int rc = sess_send_otc(s, html);
        free(html);
        return rc;   /* 1 = 等人工；-1 失败 */
    }
    int rc = sess_submit_password(s, password, NULL);
    free(html);
    return rc;
}

/* ---------- 配置文件记忆（rememberCred） ---------- */

/* 在 instances[]（或单实例）里定位包含该 client_name 的对象区间 */
static int find_instance_span(const char *data, const char *cname,
                              const char **sout, const char **eout) {
    const char *arr = strstr(data, "\"instances\"");
    const char *p;
    if (arr) {
        p = strchr(arr, '[');
        if (!p) return -1;
        p++;
    } else {
        p = strchr(data, '{');
        if (!p) return -1;
    }
    char esc[192];
    json_escape(cname, esc, sizeof esc);
    char pat1[256], pat2[256];
    snprintf(pat1, sizeof pat1, "\"client_name\": \"%s\"", esc);
    snprintf(pat2, sizeof pat2, "\"client_name\":\"%s\"", esc);
    while (*p) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ',') p++;
        if (*p == ']' || *p == 0) return -1;
        if (*p != '{') return -1;
        int depth = 0, in_str = 0;
        const char *os = p;
        while (*p) {
            if (in_str) { if (*p == '\\') p++; else if (*p == '"') in_str = 0; }
            else {
                if (*p == '"') in_str = 1;
                else if (*p == '{') depth++;
                else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
            }
            p++;
        }
        if (!arr) { *sout = os; *eout = p; return 0; }
        /* 检查该对象是否目标实例（对象内无嵌套，直接在区间内找） */
        const char *hit1 = strstr(os, pat1);
        const char *hit2 = strstr(os, pat2);
        if ((hit1 && hit1 < p) || (hit2 && hit2 < p)) { *sout = os; *eout = p; return 0; }
    }
    return -1;
}

/* 在对象文本里替换一个键的值；键不存在或格式不符时原样返回 */
static char *span_replace(char *span, const char *key, const char *val, int *done) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    char *hit = strstr(span, pat);
    if (!hit) return span;
    char *q = hit + strlen(pat);
    while (*q == ' ') q++;
    if (*q != ':') return span;
    q++;
    while (*q == ' ') q++;
    if (*q != '"') return span;
    char *vq = q + 1;
    char *vend = vq;
    while (*vend && *vend != '"') { if (*vend == '\\' && vend[1]) vend++; vend++; }
    if (!*vend) return span;
    char esc[512];
    json_escape(val, esc, sizeof esc);
    size_t pre = (size_t)(vq - span), post = strlen(vend);
    char *nc = malloc(pre + strlen(esc) + post + 1);
    if (!nc) return span;
    memcpy(nc, span, pre);
    memcpy(nc + pre, esc, strlen(esc));
    memcpy(nc + pre + strlen(esc), vend, post + 1);
    free(span);
    *done = 1;
    return nc;
}

/* 登录成功/进入等人工后把账号密码记进实例配置（内存 + 配置文件），自动重登要用 */
static void remember_cred(app_state *a, const char *account, const char *password) {
    int acc_chg = strcmp(a->cfg.account, account) != 0;
    int pwd_chg = strcmp(a->cfg.password, password) != 0;
    if (acc_chg) snprintf(a->cfg.account, sizeof a->cfg.account, "%s", account);
    if (pwd_chg) snprintf(a->cfg.password, sizeof a->cfg.password, "%s", password);
    if ((!acc_chg && !pwd_chg) || !MSL_CFG_PATH[0]) return;

    FILE *f = fopen(MSL_CFG_PATH, "r");
    if (!f) return;
    char data[32768];
    size_t dn = fread(data, 1, sizeof data - 1, f);
    fclose(f);
    data[dn] = 0;

    const char *s, *e;
    if (find_instance_span(data, a->cfg.client_name, &s, &e) != 0) {
        log_print("[MSLOGIN] 配置里找不到实例 %s，账号密码只记在内存", a->cfg.client_name);
        return;
    }
    char *span = malloc((size_t)(e - s) + 1);
    if (!span) return;
    memcpy(span, s, (size_t)(e - s));
    span[(size_t)(e - s)] = 0;
    int c1 = 0, c2 = 0;
    span = span_replace(span, "account", account, &c1);
    span = span_replace(span, "password", password, &c2);
    if (!c1 && !c2) { free(span); return; }
    size_t pre = (size_t)(s - data), post = strlen(e);
    char *out = malloc(pre + strlen(span) + post + 1);
    if (!out) { free(span); return; }
    memcpy(out, data, pre);
    memcpy(out + pre, span, strlen(span));
    memcpy(out + pre + strlen(span), e, post + 1);
    free(span);
    char tmpf[300];
    snprintf(tmpf, sizeof tmpf, "%s.tmp", MSL_CFG_PATH);
    f = fopen(tmpf, "w");
    if (!f) { free(out); return; }
    fputs(out, f);
    fclose(f);
    rename(tmpf, MSL_CFG_PATH);
    free(out);
    log_print("[MSLOGIN] 已把账号密码记入配置（自动重登用）");
}

/* ---------- 对外接口 ---------- */

static void sess_drop(app_state *a) {
    pthread_mutex_lock(&SESS_MU);
    for (int i = 0; i < MAX_INST; i++) {
        if (SESS[i] && SESS[i]->owner == a) { free(SESS[i]); SESS[i] = NULL; }
    }
    pthread_mutex_unlock(&SESS_MU);
}

static void cookie_path_for(const char *account, char *out, size_t n) {
    char safe[128];
    size_t o = 0;
    for (const char *p = account; *p && o + 1 < sizeof safe; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) safe[o++] = c;
        else safe[o++] = '_';
    }
    safe[o] = 0;
    /* cookie 存档放数据目录（重启后还在）：微软凭 ESTSAUTHPERSISTENT 认「已知设备」，
       密码登录大概率免邮箱验证码。 */
    if (!G_DATA_DIR[0]) snprintf(G_DATA_DIR, sizeof G_DATA_DIR, ".");
    int w = snprintf(out, n, "%s/.mscookies_%s.dat", G_DATA_DIR, safe);
    if (w > 0 && (size_t)w < n) return;
    snprintf(out, n, ".mscookies_%s.dat", safe);
}

static int jar_cookie_count(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    char line[4096];
    while (fgets(line, sizeof line, f))
        if (line[0] != '#' && line[0] != '\n' && line[0] != 0) n++;
    fclose(f);
    return n;
}

/* 微软拿「contextID 对不上 cookie」顶回来：说明回放的 cookie 存档已经和这次登录会话
   不是一个了（存档里留着上一轮的 ContextID）。这种局面重试也没用，先扔存档再冷登录。 */
static int page_cookie_mismatch(const char *html) {
    if (!html) return 0;
    return strstr(html, "did not have a matching cookie") != NULL
           || strstr(html, "0x800478DA") != NULL
           || str_icontains(html, "contextID");
}

static void purge_cookie_jar(ms_session *s) {
    if (!s || !s->jar[0]) return;
    if (unlink(s->jar) == 0)
        log_print("[MSLOGIN] 旧 cookie 存档已作废（%s），下一轮走冷登录", s->jar);
    else
        log_print("[MSLOGIN] 清理 cookie 存档失败：%s", strerror(errno));
}

int ms_pwd_login(app_state *a, const char *account_in, const char *password_in, int auto_login,
                 int *need_code, char *masked, size_t mn,
                 char *msg, size_t msgn, char *errbuf, size_t en, int *transient) {
    if (need_code) *need_code = 0;
    if (transient) *transient = 0;
    if (masked) masked[0] = 0;
    if (msg) msg[0] = 0;
    if (errbuf) errbuf[0] = 0;

    char account[128] = "", password[128] = "";
    snprintf(account, sizeof account, "%s", account_in ? account_in : "");
    snprintf(password, sizeof password, "%s", password_in ? password_in : "");
    char *t = account;
    while (*t == ' ' || *t == '\t') t++;
    memmove(account, t, strlen(t) + 1);
    if (!account[0]) snprintf(account, sizeof account, "%s", a->cfg.account);
    if (!password[0]) snprintf(password, sizeof password, "%s", a->cfg.password);
    if (!account[0] || !password[0]) {
        snprintf(errbuf, en, "账号和密码不能为空");
        return -1;
    }

    pthread_mutex_lock(&LOGIN_MU);
    /* 自动重登绝不打断正在等人工的会话（人工填一半的邮箱/验证码会被作废，
       每打断一次就多一次冷登录，把账号往风控里推） */
    pthread_mutex_lock(&SESS_MU);
    ms_session *old = NULL;
    for (int i = 0; i < MAX_INST; i++)
        if (SESS[i] && SESS[i]->owner == a) old = SESS[i];
    int pending = old && (old->emailAsked || old->codeSent) && (time(NULL) - old->created) < 20 * 60;
    pthread_mutex_unlock(&SESS_MU);
    if (pending && auto_login) {
        pthread_mutex_unlock(&LOGIN_MU);
        snprintf(errbuf, en, "已有登录正在等待人工验证（网页待应答），自动重登不中断它");
        return -1;
    }

    ms_session *s = calloc(1, sizeof *s);
    if (!s) { pthread_mutex_unlock(&LOGIN_MU); snprintf(errbuf, en, "内存不足"); return -1; }
    s->owner = a;
    s->created = time(NULL);
    snprintf(s->username, sizeof s->username, "%s", account);
    snprintf(s->password, sizeof s->password, "%s", password);
    cookie_path_for(account, s->jar, sizeof s->jar);
    sess_drop(a);
    pthread_mutex_lock(&SESS_MU);
    for (int i = 0; i < MAX_INST; i++) if (!SESS[i]) { SESS[i] = s; break; }
    pthread_mutex_unlock(&SESS_MU);

    /* 回放上次登录保存的会话 cookie：微软见自己签发的 ESTSAUTHPERSISTENT 判定已知设备，
       密码通过后通常直接放行（无人值守的关键） */
    int nc = jar_cookie_count(s->jar);
    if (nc > 0)
        log_print("[登录:%s] 已回放上次登录保存的 %d 条会话 cookie（已知设备，大概率免邮箱验证）",
                  a->cfg.client_name, nc);
    else
        log_print("[登录:%s] 没有可用的登录 cookie 存档，走冷登录（可能触发邮箱验证）",
                  a->cfg.client_name);

    int rc = sess_start_login(s);
    if (rc < 0) {
        char ecpy[512];
        snprintf(ecpy, sizeof ecpy, "%s", s->errbuf);
        sess_drop(a);   /* 会话在 SESS 表里，sess_drop 已释放 */
        pthread_mutex_unlock(&LOGIN_MU);
        log_err("[登录:%s] 密码登录失败: %s", a->cfg.client_name, ecpy);
        snprintf(errbuf, en, "%s", ecpy);
        if (transient) {
            /* 只认明确网络特征，宁可把不确定的当永久失败（多等一轮），
               也不要对着微软狂敲密码 */
            if (strstr(ecpy, "网络请求失败") || strstr(ecpy, "curl 执行失败") ||
                strstr(ecpy, "未找到系统 curl") || strstr(ecpy, "请求失败"))
                *transient = 1;
        }
        return -1;
    }
    if (rc == 1) {
        /* 密码已通过（或免密码入口），等人工填收件邮箱 —— 这里只置「等人工」标记，
           绝不发码；发码必须由人在网页上填了收件邮箱后触发，一次只发一封 */
        s->emailAsked = 1;
        s->emailSent[0] = 0;
        char m[256];
        snprintf(m, sizeof m, "%s", s->partialEmail[0] ? s->partialEmail : account);
        if (masked) snprintf(masked, mn, "%s", m);
        if (msg)
            snprintf(msg, msgn, "%s",
                     s->otcMode ? "微软只给了免密码的一次性邮箱验证码入口（未使用密码）：请填完整收件邮箱（形如 xx@outlook.com），不要填页面上的掩码"
                                : "密码已通过，微软要求邮箱验证码：请填完整收件邮箱（形如 xx@outlook.com），不要填页面上的掩码");
        /* 密码已被微软接受，立刻存下来（万一验证码环节超时，重开网页直接点登录即可）；
           busy=true 由 broken + dead_reason 表达 */
        remember_cred(a, account, password);
        pthread_mutex_lock(&a->tm.mu);
        a->tm.broken = 1;
        snprintf(a->tm.dead_reason, sizeof a->tm.dead_reason,
                 "等人工在网页填收件邮箱并提交验证码（%s）", m);
        pthread_mutex_unlock(&a->tm.mu);
        log_print("[登录:%s] %s（掩码 %s）", a->cfg.client_name, msg ? msg : "", m);
        pthread_mutex_unlock(&LOGIN_MU);
        if (need_code) *need_code = 1;
        return 1;
    }
    /* 登录成功：curl 的 -c 已把会话 cookie 持续存进 jar（下次重登免验证） */
    int ck1 = jar_cookie_count(s->jar);
    remember_cred(a, account, password);
    sess_drop(a);   /* 会话在 SESS 表里，sess_drop 已释放 */
    pthread_mutex_unlock(&LOGIN_MU);
    if (ck1 > 0)
        log_print("[登录:%s] 密码登录成功（无需验证码），会话 cookie 已存档（%d 条）",
                  a->cfg.client_name, ck1);
    else
        log_print("[登录:%s] 密码登录成功（无需验证码），但会话 cookie 存档为空（下次只能冷登录，会再撞验证码）",
                  a->cfg.client_name);
    return 0;
}

int ms_verify(app_state *a, const char *input, int *sent, char *msg, size_t msgn,
              char *errbuf, size_t en) {
    if (msg) msg[0] = 0;
    if (errbuf) errbuf[0] = 0;
    *sent = 0;
    pthread_mutex_lock(&LOGIN_MU);
    pthread_mutex_lock(&SESS_MU);
    ms_session *s = NULL;
    for (int i = 0; i < MAX_INST; i++)
        if (SESS[i] && SESS[i]->owner == a) s = SESS[i];
    pthread_mutex_unlock(&SESS_MU);
    if (!s) {
        pthread_mutex_unlock(&LOGIN_MU);
        snprintf(errbuf, en, "没有进行中的登录，请先输入账号密码");
        return -1;
    }
    int sret = sess_handle_verify_input(s, input, sent);
    if (sret != 0) {
        pthread_mutex_unlock(&LOGIN_MU);
        snprintf(errbuf, en, "%s", s->errbuf);
        log_err("[登录:%s] 验证环节失败: %s", a->cfg.client_name, s->errbuf);
        return -1;
    }
    if (*sent) {
        if (msg)
            snprintf(msg, msgn, "已按指定邮箱发送验证码（%s），等邮件到达后填 6 位码", s->emailSent);
        log_print("[登录:%s] 已按人工指定的邮箱发送验证码，等待输入 6 位码", a->cfg.client_name);
        pthread_mutex_unlock(&LOGIN_MU);
        return 0;
    }
    /* 邮箱验证通过 = token 已落盘（tm_apply_tokens 已清 broken）；cookie 由 curl -c 逐步写盘，
       这里必须核实条数——jar 为空就是没存档，下次只能冷登录、必再撞验证码 */
    int ck_n = jar_cookie_count(s->jar);
    sess_drop(a);
    pthread_mutex_unlock(&LOGIN_MU);
    if (ck_n > 0)
        log_print("[登录:%s] 邮箱验证通过，token 已保存，会话 cookie 已存档（%d 条）",
                  a->cfg.client_name, ck_n);
    else
        log_print("[登录:%s] 邮箱验证通过，token 已保存，但会话 cookie 存档为空（下次只能冷登录，会再撞验证码）",
                  a->cfg.client_name);
    return 0;
}

int ms_has_pending(app_state *a) {
    pthread_mutex_lock(&SESS_MU);
    int found = 0;
    for (int i = 0; i < MAX_INST; i++)
        if (SESS[i] && SESS[i]->owner == a) found = 1;
    pthread_mutex_unlock(&SESS_MU);
    return found;
}

/* ---------- 自动重登（relogin.go 移植） ---------- */

typedef struct {
    app_state *a;
    char cfg_path[256];
} rl_ctx;
static rl_ctx RL[MAX_INST];

/* 读最新配置文件拿该实例的 account/password（网页改配置只写文件） */
static void rl_reload_cred(rl_ctx *ctx, char *account, size_t an, char *password, size_t pn) {
    account[0] = password[0] = 0;
    FILE *f = fopen(ctx->cfg_path, "r");
    if (!f) return;
    char data[32768];
    size_t dn = fread(data, 1, sizeof data - 1, f);
    fclose(f);
    data[dn] = 0;
    static char objs[MAX_INST][2048];
    int nobj = json_extract_objects(data, "instances", &objs[0][0], 2048, MAX_INST);
    for (int i = 0; i < nobj; i++) {
        char cname[128] = "";
        parse_json_str(objs[i], "client_name", cname, sizeof cname);
        if (strcmp(cname, ctx->a->cfg.client_name) != 0) continue;
        parse_json_str(objs[i], "account", account, an);
        parse_json_str(objs[i], "password", password, pn);
        return;
    }
    /* 单实例：顶层就是配置 */
    if (nobj == 0) {
        parse_json_str(data, "account", account, an);
        parse_json_str(data, "password", password, pn);
    }
}

static int iso_age_sec(const char *iso) {
    if (!iso || !*iso) return 0;
    struct tm t;
    memset(&t, 0, sizeof t);
    if (sscanf(iso, "%d-%d-%dT%d:%d:%d", &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec) != 6) return 0;
    t.tm_year -= 1900;
    t.tm_mon -= 1;
    long ts = (long)timegm(&t);
    return ts > 0 ? (int)(time(NULL) - ts) : 0;
}

static void *relogin_thread(void *arg) {
    rl_ctx *ctx = arg;
    app_state *a = ctx->a;
    int fails_auth = 0, fails_net = 0, pend_logs = 0;
    time_t next_try = 0;
    for (;;) {
        sleep(20);
        if (g_stop) break;
        if (strcmp(a->cfg.mode, "account") != 0) continue;
        /* 设备码模式不走网页登录（浏览器里由人完成密码/2FA） */
        if (strcmp(a->cfg.login, "device") == 0) continue;

        char account[128], password[128];
        rl_reload_cred(ctx, account, sizeof account, password, sizeof password);
        if (!account[0] || !password[0]) continue;

        pthread_mutex_lock(&a->tm.mu);
        int has_tok = a->tm.tok.refresh_token[0] || a->tm.tok.id_token[0];
        char obtained[64];
        snprintf(obtained, sizeof obtained, "%s", a->tm.tok.obtained_at);
        int broken = a->tm.broken;
        pthread_mutex_unlock(&a->tm.mu);
        if (!has_tok) continue;   /* 从未登录过：交给人工，不自动登 */

        int age = iso_age_sec(obtained);
        int due = broken || (age >= MSL_RELOGIN_AT);
        if (!due) continue;

        /* 上一次自动登录停在「等人工」：绝不重发验证码（老实现超时后丢会话重登，
           几分钟一封，微软随后把验证码通道限流），等人工或超时放弃 */
        pthread_mutex_lock(&SESS_MU);
        ms_session *pend = NULL;
        for (int i = 0; i < MAX_INST; i++)
            if (SESS[i] && SESS[i]->owner == a) pend = SESS[i];
        int pend_alive = pend && (pend->emailAsked || pend->codeSent);
        time_t pend_age = pend ? (time(NULL) - pend->created) : 0;
        pthread_mutex_unlock(&SESS_MU);
        if (pend_alive) {
            if (pend_age < MSL_PENDING_WAIT) {
                if (++pend_logs % 15 == 1)
                    log_print("[自动登录:%s] 停在等人工（已等 %ld 秒）：请在网页上填收件邮箱 / 6 位验证码，不会自动发码",
                              a->cfg.client_name, (long)pend_age);
                continue;
            }
            log_print("[自动登录:%s] 人工一直没有处理（超过 %d 分钟），本次已放弃；不会自动重发验证码",
                      a->cfg.client_name, MSL_PENDING_WAIT / 60);
            pthread_mutex_lock(&LOGIN_MU);   /* 与网页 verify 互斥，防止释放正在使用的会话 */
            sess_drop(a);
            pthread_mutex_unlock(&LOGIN_MU);
            fails_auth++;
            long d = MSL_RETRY_AUTH;
            for (int i = 1; i < fails_auth && d < MSL_RETRY_AUTH_MAX; i++) d *= 2;
            if (d > MSL_RETRY_AUTH_MAX) d = MSL_RETRY_AUTH_MAX;
            next_try = time(NULL) + d;
            continue;
        }
        if (time(NULL) < next_try) continue;

        log_print("[自动登录:%s] 开始（%s）", a->cfg.client_name,
                  broken ? "授权已被判失效" : "授权已用 23 小时");
        int need = 0, transient = 0;
        char masked[256] = "", msg[512] = "", err[512] = "";
        int rc = ms_pwd_login(a, account, password, 1, &need, masked, sizeof masked,
                              msg, sizeof msg, err, sizeof err, &transient);
        if (rc == 0) {
            fails_auth = fails_net = 0;
            next_try = 0;
            log_print("[自动登录:%s] 成功，已换新授权，连接恢复", a->cfg.client_name);
        } else if (rc == 1) {
            fails_auth = fails_net = 0;
            next_try = 0;
            log_err("[自动登录:%s] 微软要求邮箱验证码（%s），已停止发码并暂停取号，等人工在网页上处理：%s",
                    a->cfg.client_name, masked, msg);
        } else {
            long d;
            if (transient) {
                fails_net++;
                d = MSL_RETRY_NET;
                for (int i = 1; i < fails_net && d < MSL_RETRY_NET_MAX; i++) d *= 2;
                if (d > MSL_RETRY_NET_MAX) d = MSL_RETRY_NET_MAX;
                log_print("[自动登录:%s] 网络/DNS 暂时不通，%ld 秒后重试（%s）", a->cfg.client_name, d, err);
            } else {
                fails_auth++;
                d = MSL_RETRY_AUTH;
                for (int i = 1; i < fails_auth && d < MSL_RETRY_AUTH_MAX; i++) d *= 2;
                if (d > MSL_RETRY_AUTH_MAX) d = MSL_RETRY_AUTH_MAX;
                log_err("[自动登录:%s] 失败：%s；%ld 分钟后再试", a->cfg.client_name, err, d / 60);
            }
            next_try = time(NULL) + d;
        }
    }
    return NULL;
}

void ms_start_relogin(app_state *apps, int ninst, const char *cfg_path) {
    if (cfg_path && *cfg_path) snprintf(MSL_CFG_PATH, sizeof MSL_CFG_PATH, "%s", cfg_path);
    for (int i = 0; i < ninst && i < MAX_INST; i++) {
        RL[i].a = &apps[i];
        snprintf(RL[i].cfg_path, sizeof RL[i].cfg_path, "%s", MSL_CFG_PATH);
        pthread_t th;
        thread_spawn(&th, relogin_thread, &RL[i]);
        pthread_detach(th);
    }
}
