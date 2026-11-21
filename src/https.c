/* https.c - HTTPS 客户端（libcurl 实现）
   API 与 Windows 版一致：https_post / https_post_inner / https_curl_path */
#include "https.h"
#include <curl/curl.h>

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct {
        char *buf;
        size_t cap;
        size_t len;
    } *acc = userdata;
    size_t n = size * nmemb;
    if (acc->buf && acc->cap > 1) {
        size_t room = acc->cap - 1 - acc->len;
        if (n > room) n = room;
        if (n) {
            memcpy(acc->buf + acc->len, ptr, n);
            acc->len += n;
            acc->buf[acc->len] = 0;
        }
    } else {
        acc->len += n; /* 只统计字节数 */
    }
    acc->len += 0;
    (void)size;
    return size * nmemb;
}

static int https_do(const char *method, const char *url, const char *headers,
                    const char *body, size_t bodyn,
                    char *resp, size_t respn, int *status_out) {
    static int inited = 0;
    CURL *h;
    struct curl_slist *hdrs = NULL;
    long status = 0;
    int rc = -1;
    struct {
        char *buf;
        size_t cap;
        size_t len;
    } acc;

    if (resp && respn) resp[0] = 0;
    if (status_out) *status_out = 0;
    if (!url || !*url) return -1;
    if (!inited) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        inited = 1;
    }

    h = curl_easy_init();
    if (!h) return -1;

    acc.buf = resp;
    acc.cap = resp ? respn : 0;
    acc.len = 0;

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 40L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &acc);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "identity");
    /* UI 语言固定 zh-CN，与 Windows 版一致 */
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "identity");
    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body ? body : "");
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)bodyn);
    }

    /* headers: "K: V\r\n..." 逐行转成 curl_slist（Authorization 里带 1.5KB 的 id_token） */
    if (headers && *headers) {
        char line[8192];
        const char *p = headers;
        while (*p) {
            size_t l = strcspn(p, "\r\n");
            if (l) {
                if (l >= sizeof line) l = sizeof line - 1;
                memcpy(line, p, l);
                line[l] = 0;
                if (strncasecmp(line, "Content-Length", 14) != 0 ||
                    strncasecmp(line, "Expect", 6) != 0) {
                    hdrs = curl_slist_append(hdrs, line);
                }
            }
            p += strcspn(p, "\r\n");
            while (*p == '\r' || *p == '\n') p++;
        }
        if (hdrs) curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    }

    CURLcode cr = curl_easy_perform(h);
    if (cr != CURLE_OK) {
        log_err("[https] %s %s 失败: %s", method, url, curl_easy_strerror(cr));
    } else {
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
    }
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);

    if (cr != CURLE_OK) return -1;
    if (status_out) *status_out = (int)status;
    if (resp && respn) {
        if (acc.len >= respn) acc.len = respn - 1;
        resp[acc.len] = 0;
    }

    {
        /* 别把每秒一条的请求刷进日志：
           - validateIID 的 200 由调用方的「成功 CID」体现
           - token 端点的 400 在设备码轮询里是正常状态，真失败由 tm_refresh/dev_poll 记明细 */
        int quiet = 0;
        if (status >= 200 && status < 300 && strstr(url, "productActivation/validateIID")) quiet = 1;
        if (status == 400 && strstr(url, "oauth2/v2.0/token")) quiet = 1;
        if (!quiet)
            log_print("[https] %s %s -> HTTP %d (%zu 字节)", method, url, (int)status, acc.len);
    }
    rc = 0;
    return rc;
}

const char *https_curl_path(void) { return platform_curl_path(); }

int https_post(const char *url, const char *headers, const char *body, size_t bodyn,
               char *resp, size_t respn, int *status_out) {
    return https_do("POST", url, headers, body, bodyn, resp, respn, status_out);
}

int https_post_inner(const char *url, const char *headers, const char *body, size_t bodyn,
                     char *resp, size_t respn, int *status_out) {
    return https_do("POST", url, headers, body, bodyn, resp, respn, status_out);
}

/* http_post 兼容入口（common.h） */
int http_post(const char *url, const char *ctype, const char *body,
              const char *extra_headers, char *resp, size_t respn, int *status) {
    char hdrs[3072];
    snprintf(hdrs, sizeof hdrs, "Content-Type: %s\r\n%s", ctype,
             extra_headers ? extra_headers : "");
    return https_post(url, hdrs, body, strlen(body), resp, respn, status);
}
