/* util.c - 时间/JSON 小工具 */
#include "common.h"

/* Windows：线程栈由 CreateThread 决定（默认 1MB），thread_spawn 在 platform.c */

long long now_ms(void) { return platform_now_ms(); }

void iso_now(char *buf, size_t n, int plus_seconds) {
    time_t t = time(NULL) + plus_seconds;
    struct tm g;
    gmtime_r(&t, &g);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &g);
}

/* ---- 最小 JSON 工具 ---- */

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int json_unescape(const char *in, char *out, size_t outn) {
    size_t o = 0;
    for (const char *p = in; *p; p++) {
        if (*p != '\\') {
            if (o + 1 >= outn) return -1;
            out[o++] = *p;
            continue;
        }
        p++;
        if (o + 1 >= outn) return -1;
        switch (*p) {
        case 'n': out[o++] = '\n'; break;
        case 't': out[o++] = '\t'; break;
        case 'r': out[o++] = '\r'; break;
        case 'b': out[o++] = '\b'; break;
        case 'f': out[o++] = '\f'; break;
        case 'u': {
            int v = 0;
            for (int i = 1; i <= 4; i++) {
                int h = hexval(p[i]);
                if (h < 0) return -1;
                v = v * 16 + h;
            }
            p += 4;
            /* 只处理 BMP；多字节 UTF-8 */
            if (v < 0x80) out[o++] = (char)v;
            else if (v < 0x800) {
                out[o++] = (char)(0xC0 | (v >> 6));
                out[o++] = (char)(0x80 | (v & 0x3F));
            } else {
                out[o++] = (char)(0xE0 | (v >> 12));
                out[o++] = (char)(0x80 | ((v >> 6) & 0x3F));
                out[o++] = (char)(0x80 | (v & 0x3F));
            }
            break;
        }
        default: out[o++] = *p; break;
        }
    }
    out[o] = 0;
    return (int)o;
}

char *json_escape(const char *s, char *out, size_t outn) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && o + 7 < outn; p++) {
        if (*p == '"' || *p == '\\') { out[o++] = '\\'; out[o++] = *p; }
        else if (*p == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (*p == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (*p == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (*p < 0x20) o += snprintf(out + o, outn - o, "\\u%04x", *p);
        else out[o++] = *p;
    }
    out[o] = 0;
    return out;
}

/* 在 JSON 里取顶层（或嵌套任意层）字符串键的值。够用即可，不做完整解析器。 */
int parse_json_str(const char *json, const char *key, char *out, size_t outn) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        /* ★ 必须是「键」而不是恰好同名的字符串值：例如 {"mode":"account"}
           里的值 "account" 会被旧的 strstr 命中，导致真的 "account" 键读不到。
           判据：引号串后面（跳过空白）必须是 ':'。 */
        const char *q = p + strlen(pat);
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        p += strlen(pat);
        if (*q != ':') continue;
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != '"') return -1;      /* 只支持字符串值 */
        q++;
        const char *e = q;
        while (*e) {
            if (*e == '\\') e += 2;
            else if (*e == '"') break;
            else e++;
        }
        if (!*e) return -1;
        char raw[8192];
        size_t n = (size_t)(e - q);
        if (n >= sizeof raw) n = sizeof raw - 1;
        memcpy(raw, q, n);
        raw[n] = 0;
        return json_unescape(raw, out, outn) < 0 ? -1 : 0;
    }
    return -1;
}

/* 从 JSON 对象文本里取数值键 */
int parse_json_int(const char *json, const char *key, int defval) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        p += strlen(pat);
        if (*q != ':') continue;   /* 同 parse_json_str：值不算键 */
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        return atoi(q);
    }
    return defval;
}

/* 在 JSON 文本中找 "key":[ ... ]，逐个顶层对象截取出来（忽略字符串内括号）。
   objs 指向 objsize×max 的二维缓冲。返回对象个数（0 = 没有该键或空数组）。 */
int json_extract_objects(const char *data, const char *key,
                         char *objs, size_t objsize, int max) {
    char needle[80];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *k = strstr(data, needle);
    if (!k) return 0;
    const char *p = strchr(k, '[');
    if (!p) return 0;
    p++;
    int n = 0;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ',') p++;
        if (*p == ']' || *p == 0) break;
        if (*p != '{') break;
        int depth = 0, in_str = 0;
        const char *start = p;
        while (*p) {
            if (*p == '"' && (p == start || *(p - 1) != '\\')) in_str = !in_str;
            if (!in_str) {
                if (*p == '{') depth++;
                if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
            }
            p++;
        }
        size_t len = (size_t)(p - start);
        if (len >= objsize) len = objsize - 1;
        memcpy(objs + (size_t)n * objsize, start, len);
        objs[(size_t)n * objsize + len] = 0;
        n++;
    }
    return n;
}
