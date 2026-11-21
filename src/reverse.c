/* reverse.c - IID 逆向（移植自 Go 版 reverse.go / CIDPlugin ReverseIID.cs） */
#include "common.h"
#include "reverse.h"
#include "productdata.h"
#include <bearssl.h>

static const uint32_t SIG[16] = {
    3562981483u, 2228812016u, 791298423u, 4094923645u,
    3865479707u, 3147109794u, 1739627790u, 2536190595u,
    3453615689u, 4007427452u, 3742500784u, 3946515431u,
    3751329110u, 3483772925u, 3258352733u, 1463448568u
};

static uint32_t le32(const unsigned char *b, int off) {
    return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}

static uint32_t rol(uint32_t v, int s) { return s ? (v << s) | (v >> (32 - s)) : v; }
static uint32_t ror(uint32_t v, int s) { return s ? (v >> s) | (v << (32 - s)) : v; }

/* 分 9 组去掉每组末位校验数字 */
static void reverse_get_full_iid(const char *iid, char *out, size_t outn) {
    size_t n = strlen(iid);
    out[0] = 0;
    if (n < 9) return;
    size_t chunk = n / 9;
    size_t o = 0;
    for (int i = 0; i < 9; i++) {
        const char *part = iid + (size_t)i * chunk;
        size_t take = chunk - 1;
        for (size_t j = 0; j < take && o + 1 < outn; j++) out[o++] = part[j];
    }
    out[o] = 0;
}

/* 十进制字符串 → size 字节小端大整数（大数按 10 进制逐位乘加） */
static void reverse_original_id(const char *s, unsigned char *out, int size) {
    memset(out, 0, (size_t)size);
    for (const char *p = s; *p; p++) {
        int digit = *p - '0';
        if (digit < 0 || digit > 9) continue;
        unsigned carry = (unsigned)digit;
        for (int i = 0; i < size; i++) {
            unsigned v = (unsigned)out[i] * 10 + carry;
            out[i] = (unsigned char)(v & 0xFF);
            carry = v >> 8;
        }
    }
}

/* 标准 SHA1 压缩，输入字按 LE 读出后按 BE 解释（与 C# 原版一致） */
static void cal_sha1(uint32_t state[5], const uint32_t a2[16]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((a2[i] << 24) & 0xFF000000u) | ((a2[i] << 8) & 0xFF0000u) |
               ((a2[i] >> 8) & 0xFF00u) | ((a2[i] >> 24) & 0xFFu);
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int k = 0; k < 80; k++) {
        uint32_t f, kk;
        if (k < 20) { f = (b & c) | (~b & d); kk = 1518500249u; }
        else if (k < 40) { f = b ^ c ^ d; kk = 1859775393u; }
        else if (k < 60) { f = (b & c) | (b & d) | (c & d); kk = 2400959708u; }
        else { f = b ^ c ^ d; kk = 3395469782u; }
        uint32_t tmp = rol(a, 5) + f + e + kk + w[k];
        e = d; d = c; c = ror(b, 2); b = a; a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

/* C# do-while 等价：out[n] = (src[n]>>3) | ((src[n+1]&7)<<5)，out[22] = src[22]>>3 */
static void reverse_cal_bytes(const unsigned char *src, unsigned char *out) {
    for (int n = 0; n < 22; n++)
        out[n] = (unsigned char)((src[n] >> 3) | ((src[n + 1] & 7) << 5));
    out[22] = (unsigned char)(src[22] >> 3);
}

static void reverse_convert(const unsigned char *result, const unsigned char *data,
                            uint32_t sig_byte, unsigned char *out, int result_len) {
    unsigned char buf[92];
    memset(buf, 0, sizeof buf);
    buf[0] = 121;
    buf[88] = 1;
    /* 与 Go/C# 一致：只拷 num 字节（45 位分支 num=9，54 位分支 num=11）。
       之前写死 22 会越界读 data 并污染 SHA1 输入，导致 gid/pid 计算全错 */
    memcpy(buf + 1, data, (size_t)result_len);
    int num = result_len;
    buf[88] += (unsigned char)num;
    uint32_t state[5] = { 1732584193u, 4023233417u, 2562383102u, 271733878u, 3285377520u };
    for (int i = 0; i < 5; i++) {
        buf[64 + i * 4 + 0] = (unsigned char)state[i];
        buf[64 + i * 4 + 1] = (unsigned char)(state[i] >> 8);
        buf[64 + i * 4 + 2] = (unsigned char)(state[i] >> 16);
        buf[64 + i * 4 + 3] = (unsigned char)(state[i] >> 24);
    }
    buf[88] += 4;
    unsigned char sb[4] = {
        (unsigned char)sig_byte, (unsigned char)(sig_byte >> 8),
        (unsigned char)(sig_byte >> 16), (unsigned char)(sig_byte >> 24)
    };
    memcpy(buf + 1 + num, sb, 4);
    unsigned b = buf[88] * 8;
    buf[1 + num + 4] = 128;
    int num3 = 64 - (buf[88] & 0x3F);
    buf[1 + num + 4 + num3 - 1] = (unsigned char)b;
    buf[88] += (unsigned char)num3;

    uint32_t a[23];
    for (int i = 0; i < 23; i++) a[i] = le32(buf, i * 4);
    cal_sha1(state, a);
    for (int i = 0; i < 5; i++) {
        uint32_t v = state[i];
        state[i] = ((v << 24) & 0xFF000000u) | ((v << 8) & 0xFF0000u) |
                   ((v >> 8) & 0xFF00u) | ((v >> 24) & 0xFFu);
    }
    int num4 = (int)((8 * num + 31) >> 5 << 2);
    unsigned num5 = (unsigned)((8 * num + 31) >> 5 << 5) - (unsigned)(8 * num);
    state[2] >>= num5;
    unsigned char state_bytes[20];
    for (int i = 0; i < 5; i++) {
        state_bytes[i * 4 + 0] = (unsigned char)state[i];
        state_bytes[i * 4 + 1] = (unsigned char)(state[i] >> 8);
        state_bytes[i * 4 + 2] = (unsigned char)(state[i] >> 16);
        state_bytes[i * 4 + 3] = (unsigned char)(state[i] >> 24);
    }
    for (int i = 0; i < num; i++) {
        unsigned char x = (i < num4) ? state_bytes[i] : 0;
        out[i] = (unsigned char)(result[i] ^ x);
    }
}

static int sum_digits(int v) {
    int s = 0;
    while (v > 0) { s += v % 10; v /= 10; }
    return s;
}

static const char *find_range(const product_range *tbl, int len, int gid, long key_address) {
    for (int i = 0; i < len; i++)
        if (tbl[i].gid == gid && key_address >= tbl[i].start && key_address <= tbl[i].end)
            return tbl[i].name;
    return NULL;
}

static void pad_left(char *s, int width) {
    int n = (int)strlen(s);
    if (n >= width) return;
    memmove(s + (width - n), s, (size_t)n + 1);
    memset(s, '0', (size_t)(width - n));
}

void reverse_key_data(const char *iid, char *name, size_t name_n,
                      char *pid, size_t pid_n, int *group_id, int *key_address) {
    char full[128];
    reverse_get_full_iid(iid, full, sizeof full);
    name[0] = pid[0] = 0;
    *group_id = 0;
    *key_address = 0;
    size_t flen = strlen(full);

    if (flen == 45) {
        unsigned char arr[18];
        reverse_original_id(full, arr, 18);
        unsigned char a[9], b[9], dest[9];
        memcpy(a, arr, 9);
        memcpy(b, arr + 9, 9);
        for (int i = 15; i >= 0; i--) {
            reverse_convert(b, a, SIG[i], dest, 9);
            memcpy(b, a, 9);
            memcpy(a, dest, 9);
        }
        uint32_t num2 = le32(dest, 0);
        uint32_t num3 = le32(dest, 4);
        int gid = (int)((num3 >> 17) & 0x3FF);
        uint32_t num4 = num3 & 0x7F;
        uint32_t num5 = num2 & 0xFFFFFF00u;
        uint32_t num6 = (num4 << 23) | (num5 >> 9);
        unsigned ka = (num6 / 1000000) * 1000000 + num6 % 1000000;
        char key_str[16];
        snprintf(key_str, sizeof key_str, "%09u", ka);
        const char *t3 = key_str;   /* 前 3 位 */
        int num = 0;
        for (const char *p = key_str + 3; *p; p++) num = num * 10 + (*p - '0');
        int inp = num * 10 - sum_digits(num) % 7 + 7;
        char t4[16];
        snprintf(t4, sizeof t4, "%d", 1000 * ((gid >> 1) % 100));
        pad_left(t4, 5);
        snprintf(pid, pid_n, "22222-%.3s-%d-%s", t3, inp, t4);
        *group_id = gid;
        *key_address = (int)ka;

        int in_vista = 0;
        for (int g = 142; g <= 166; g += 2) if (gid == g) { in_vista = 1; break; }
        const char *n = NULL;
        if (in_vista) {
            n = find_range(t2005_Vista, t2005_Vista_len, gid, (long)ka);
            snprintf(name, name_n, "%s", n ? n : "Vista");
        } else if (gid > 212 || gid < 140) {
            if (gid > 98 || gid < 20) {
                snprintf(name, name_n, "Unknown");
            } else {
                n = find_range(t2005_Office2010, t2005_Office2010_len, gid, (long)ka);
                snprintf(name, name_n, "%s", n ? n : "Office2010");
            }
        } else {
            n = find_range(t2005_Win7, t2005_Win7_len, gid, (long)ka);
            snprintf(name, name_n, "%s", n ? n : "Windows 7");
        }
        return;
    }

    if (flen == 54) {
        unsigned char res[24];
        reverse_original_id(full, res, 24);
        unsigned char buf[23];
        reverse_cal_bytes(res, buf);
        unsigned char a[11], b[11], dest[11];
        memcpy(a, buf, 11);
        memcpy(b, buf + 11, 11);
        for (int i = 15; i >= 0; i--) {
            reverse_convert(b, a, SIG[i], dest, 11);
            memcpy(b, a, 11);
            memcpy(a, dest, 11);
        }
        unsigned char h[22];
        memcpy(h, a, 11);
        memcpy(h + 11, b, 11);
        unsigned char gb[4] = {
            (unsigned char)(((h[6] & 1) << 7) | ((h[5] & 0xFE) >> 1)),
            (unsigned char)((h[6] & 0xFE) >> 1),
            (unsigned char)((h[7] & 0x1E) >> 1),
            0
        };
        int gid = (int)le32(gb, 0);
        unsigned char ka4[4];
        int m = 7, n = 0;
        for (int i = 0; i < 3; i++) {
            ka4[n] = (unsigned char)((h[m] >> 5) | ((h[m + 1] & 0x1F) << 3));
            n++; m++;
        }
        ka4[3] = (unsigned char)(((h[10] >> 5) & 7) | ((h[11] & 7) << 3));
        int ka = (int)le32(ka4, 0);
        char g[16];
        snprintf(g, sizeof g, "%d", gid);
        pad_left(g, 5);
        const char *t7 = g;          /* 前 5 位 */
        const char *t8 = strlen(g) > 5 ? g + 5 : "";
        char ks[16];
        snprintf(ks, sizeof ks, "%d", ka);
        char t10[16] = "", t11[16] = "";
        size_t ksl = strlen(ks);
        if (ksl >= 5) {
            snprintf(t10, sizeof t10, "%s", ks + ksl - 5);
            if (ksl > 5) {
                size_t l = ksl - 5;
                if (l >= sizeof t11) l = sizeof t11 - 1;
                memcpy(t11, ks, l);
                t11[l] = 0;
            }
        } else {
            snprintf(t10, sizeof t10, "%s", ks);
            pad_left(t10, 5);
        }
        char t12[16];
        snprintf(t12, sizeof t12, "%s%s", t8, t11);
        if (strlen(t12) < 5) {
            char zeros[8];
            memset(zeros, '0', 5 - strlen(t12));
            zeros[5 - strlen(t12)] = 0;
            char tmp[16];
            snprintf(tmp, sizeof tmp, "%s%s%s", t8, zeros, t11);
            snprintf(t12, sizeof t12, "%s", tmp);
        } else if (strlen(t12) > 5) {
            memmove(t12, t12 + strlen(t12) - 5, 6);
        }
        const char *nm = "Unknown";
        const product_range *tbls[] = { t2009_Office, t2009_Win8, t2009_Win10,
                                        t2009_VS2015, t2009_SQL2016 };
        const int lens[] = { t2009_Office_len, t2009_Win8_len, t2009_Win10_len,
                             t2009_VS2015_len, t2009_SQL2016_len };
        for (int ti = 0; ti < 5 && !strcmp(nm, "Unknown"); ti++) {
            for (int i = 0; i < lens[ti]; i++) {
                if (tbls[ti][i].gid == gid) { nm = tbls[ti][i].name; break; }
            }
        }
        const char *suffix = strstr(nm, "OEM") ? "AAOEM" : "AA000";
        snprintf(name, name_n, "%s", nm);
        snprintf(pid, pid_n, "%.5s-%.5s-%.5s-%s", t7, t12, t10, suffix);
        *group_id = gid;
        *key_address = ka;
    }
}
