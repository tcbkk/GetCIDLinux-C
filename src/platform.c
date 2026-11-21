/* platform.c - POSIX 兼容层：线程 / 随机数 / SHA-256 / 时间 / 路径 / curl 探测 */
#include "common.h"

/* ---------- 线程 ---------- */

typedef struct {
    void *(*fn)(void *);
    void *arg;
} th_pack;

static void *th_entry(void *p) {
    th_pack *tp = (th_pack *)p;
    void *(*fn)(void *) = tp->fn;
    void *arg = tp->arg;
    free(tp);
    fn(arg);
    return NULL;
}

int thread_spawn(pthread_t *th, void *(*fn)(void *), void *arg) {
    th_pack *tp = malloc(sizeof *tp);
    pthread_t t;
    if (!tp) return -1;
    tp->fn = fn;
    tp->arg = arg;
    if (pthread_create(&t, NULL, th_entry, tp) != 0) {
        free(tp);
        return -1;
    }
    if (th) *th = t;
    else pthread_detach(t);
    return 0;
}

int pthread_join_portable(pthread_t t) {
    if (!t) return -1;
    pthread_join(t, NULL);
    return 0;
}

/* ---------- 时间 ---------- */

long long platform_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

long long platform_uptime_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void platform_monotonic_ts(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

/* ---------- 随机数 ---------- */

int platform_random_bytes(void *buf, size_t n) {
    if (!n) return 0;
    return RAND_bytes((unsigned char *)buf, (int)n) == 1 ? 0 : -1;
}

/* ---------- SHA-256（OpenSSL EVP） ---------- */

void br_sha256_init(br_sha256_context *ctx) {
    ctx->ctx = EVP_MD_CTX_new();
    if (ctx->ctx) EVP_DigestInit_ex(ctx->ctx, EVP_sha256(), NULL);
}

void br_sha256_update(br_sha256_context *ctx, const void *data, size_t len) {
    if (!ctx->ctx || !len) return;
    EVP_DigestUpdate(ctx->ctx, data, len);
}

void br_sha256_out(br_sha256_context *ctx, void *out) {
    unsigned int n = 0;
    if (ctx->ctx) {
        EVP_DigestFinal_ex(ctx->ctx, (unsigned char *)out, &n);
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

/* ---------- 目录 / 路径 ---------- */

int platform_mkdir(const char *path) {
    if (!path || !*path) return -1;
    if (mkdir(path, 0755) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

void platform_path_join(char *out, size_t n, const char *dir, const char *name) {
    if (!dir || !*dir) {
        snprintf(out, n, "%s", name ? name : "");
        return;
    }
    char last = dir[strlen(dir) - 1];
    if (last == '/' ) snprintf(out, n, "%s%s", dir, name ? name : "");
    else snprintf(out, n, "%s/%s", dir, name ? name : "");
}

const char *platform_exe_dir(void) {
    static char dir[MAX_PATH] = "";
    if (dir[0]) return dir;
    char buf[MAX_PATH];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) {
        snprintf(dir, sizeof dir, ".");
        return dir;
    }
    buf[n] = 0;
    char *slash = strrchr(buf, '/');
    if (slash) *slash = 0;
    else snprintf(buf, sizeof buf, ".");
    snprintf(dir, sizeof dir, "%s", buf);
    return dir;
}

/* ---------- 系统 curl ---------- */

static int is_exec_file(const char *p) {
    struct stat st;
    return (stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, X_OK) == 0);
}

const char *platform_curl_path(void) {
    static char found[320] = "";
    static int tried = 0;
    if (tried) return found[0] ? found : NULL;
    tried = 1;

    const char *cands[] = { "/usr/bin/curl", "/usr/local/bin/curl", "/bin/curl", NULL };
    for (int i = 0; cands[i]; i++) {
        if (is_exec_file(cands[i])) {
            snprintf(found, sizeof found, "%s", cands[i]);
            return found;
        }
    }
    /* PATH 里找一遍 */
    char *path = getenv("PATH");
    if (path) {
        char *dup = strdup(path);
        if (dup) {
            char cand[320];
            char *save = NULL;
            for (char *p = strtok_r(dup, ":", &save); p; p = strtok_r(NULL, ":", &save)) {
                snprintf(cand, sizeof cand, "%s/curl", p);
                if (is_exec_file(cand)) {
                    snprintf(found, sizeof found, "%s", cand);
                    break;
                }
            }
            free(dup);
        }
    }
    return found[0] ? found : NULL;
}

/* 复制文件（GUI 改名时搬 token 用）：成功返回 0 */
int platform_copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb"), *out;
    char buf[8192];
    size_t n;
    int rc = 0;
    if (!in) return -1;
    out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { rc = -1; break; }
    }
    fclose(in);
    if (fclose(out) != 0) rc = -1;
    return rc;
}
