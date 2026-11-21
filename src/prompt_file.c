/* prompt_file.c - 文件通道的人工验证提示器（Linux 无头版） */
#include "prompt_file.h"

static void one_line(const char *in, char *out, size_t n) {
    size_t o = 0;
    if (!in) {
        if (n) out[0] = 0;
        return;
    }
    for (const char *p = in; *p && o + 1 < n; p++) {
        char c = *p;
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
        out[o++] = c;
    }
    out[o] = 0;
}

static void req_path(char *out, size_t n, const char *dir, const char *name) {
    platform_path_join(out, n, dir, name);
}

static void trim(char *s) {
    size_t l;
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    l = strlen(s);
    while (l && (s[l - 1] == ' ' || s[l - 1] == '\t')) s[--l] = 0;
}

int prompt_device_code(const char *dir, const char *url, const char *code, int expires_s) {
    char p[400], name[64];
    FILE *f;
    if (!dir) return -1;
    platform_mkdir(dir);
    snprintf(name, sizeof name, "request.txt");
    req_path(p, sizeof p, dir, name);
    f = fopen(p, "w");
    if (!f) return -1;
    fprintf(f, "ID=%s\n", code && *code ? code : "device");
    fprintf(f, "TYPE=device\n");
    fprintf(f, "TITLE=%s\n", "设备码登录");
    fprintf(f, "URL=%s\n", url ? url : "");
    fprintf(f, "CODE=%s\n", code ? code : "");
    fprintf(f, "MESSAGE=请打开 %s ，输入代码 %s（%d 秒内有效）：登录后自动继续。\n",
            url && *url ? url : "https://microsoft.com/devicelogin",
            code ? code : "", expires_s > 0 ? expires_s : 900);
    fprintf(f, "TIMEOUT=%d\n", expires_s > 0 ? expires_s : 900);
    fclose(f);
    log_print("[提示] 设备码已写入 %s（%s 代码 %s）", p, url ? url : "", code ? code : "");
    return 0;
}

void prompt_device_clear(const char *dir) {
    char p[400];
    if (!dir) return;
    req_path(p, sizeof p, dir, "request.txt");
    unlink(p);
}

int prompt_clear_stale_device(const char *dir) {
    char p[400], ap[400], type[64] = "";
    char line[1024];
    FILE *f;
    if (!dir) return 0;
    req_path(p, sizeof p, dir, "request.txt");
    f = fopen(p, "r");
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (strncmp(line, "TYPE=", 5) == 0) {
            snprintf(type, sizeof type, "%s", line + 5);
            trim(type);
            break;
        }
    }
    fclose(f);
    if (strcasecmp(type, "device") != 0) return 0;
    unlink(p);
    req_path(ap, sizeof ap, dir, "answer.txt");
    unlink(ap);
    log_print("[提示] 登录方式已不是设备码，清掉残留的设备码提示");
    return 1;
}

char *prompt_ask(const char *dir, const char *title, const char *message, int timeout_s) {
    char p[400], ap[400];
    char id[40];
    char line[1024];
    FILE *f;
    long deadline;
    unsigned char rnd[16];

    if (!dir) return NULL;
    if (timeout_s <= 0) timeout_s = 900;
    platform_mkdir(dir);

    req_path(p, sizeof p, dir, "request.txt");
    req_path(ap, sizeof ap, dir, "answer.txt");
    unlink(ap); /* 上一轮残留的答案 */

    if (platform_random_bytes(rnd, sizeof rnd) != 0) {
        snprintf(id, sizeof id, "%ld", (long)time(NULL));
    } else {
        for (int i = 0; i < 16; i++) sprintf(id + i * 2, "%02x", rnd[i]);
    }

    f = fopen(p, "w");
    if (!f) {
        log_err("[提示] 写 request.txt 失败: %s", strerror(errno));
        return NULL;
    }
    fputs("ID=", f);          fputs(id, f);   fputc('\n', f);
    fputs("TYPE=ask\n", f);
    one_line(title, line, sizeof line);
    fprintf(f, "TITLE=%s\n", line);
    one_line(message, line, sizeof line);
    fprintf(f, "MESSAGE=%s\n", line);
    fprintf(f, "TIMEOUT=%d\n", timeout_s);
    fclose(f);

    log_print("[需要人工验证] %s —— 请求已写入 %s，等待 %s（最多 %d 秒）", title, p, ap, timeout_s);

    deadline = (long)time(NULL) + timeout_s;
    while ((long)time(NULL) < deadline) {
        sleep(1);
        f = fopen(ap, "r");
        if (!f) continue;
        {
            char got_id[64] = "", value[512] = "", bare[512] = "";
            while (fgets(line, sizeof line, f)) {
                char *eq, *k, *v;
                size_t l = strlen(line);
                while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
                if (!line[0]) continue;
                eq = strchr(line, '=');
                if (!eq) {
                    if (!bare[0]) {
                        trim(line);
                        if (line[0]) snprintf(bare, sizeof bare, "%s", line);
                    }
                    continue;
                }
                *eq = 0;
                k = line;
                v = eq + 1;
                trim(k);
                trim(v);
                if (strcasecmp(k, "ID") == 0) {
                    snprintf(got_id, sizeof got_id, "%s", v);
                } else if (strcasecmp(k, "VALUE") == 0) {
                    snprintf(value, sizeof value, "%s", v);
                }
            }
            fclose(f);
            if (got_id[0] && strcasecmp(got_id, id) != 0) {
                /* 上一轮的答案，忽略 */
                unlink(ap);
                continue;
            }
            if (!value[0] && bare[0]) snprintf(value, sizeof value, "%s", bare);
            if (!value[0]) continue;
            unlink(ap);
            unlink(p);
            log_print("[提示] 收到答案（%d 字符）", (int)strlen(value));
            {
                char *out = strdup(value);
                return out;
            }
        }
    }

    log_print("[需要人工验证] %s 等待超时（%d 秒），按取消处理", title, timeout_s);
    unlink(p);
    return NULL;
}
