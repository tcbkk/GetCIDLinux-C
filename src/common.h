/* common.h - Linux 版共用定义（GetCIDLinux）
   与 Windows 版（GetCID-C）同一套 API，内部换成 POSIX / OpenSSL / libcurl。 */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include <openssl/evp.h>

/* Winsock 命名兼容（router-c 遗留代码） */
#ifndef SOCKET_DEFINED
#define SOCKET_DEFINED 1
typedef int SOCKET;
#endif
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#define AES_KEY "lkirwf897+33#bbtrm8814z5qq=998j6"
#define AES_IV  "851952hheeyy77#c"
#define TOKEN_URL  "https://login.microsoftonline.com/common/oauth2/v2.0/token"
#define VALIDATE_URL "https://visualsupport.microsoft.com/api/productActivation/validateIID"
#define SPA_CLIENT_ID "2b217cec-607d-4eb6-887e-c928520a14f6"

/* MSVC 遗留名字 */
#define _strdup strdup
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif
#define localtime_s(tm, t) localtime_r((t), (tm))

/* 数据目录（配置、cookie 存档、token、临时文件都放这里） */
extern char G_CFG_DIR[320];
extern char G_DATA_DIR[320];

/* ---------------- 线程 ---------------- */
typedef pthread_t thr_t;
int thread_spawn(pthread_t *th, void *(*fn)(void *), void *arg);

/* ---------------- 时间 ---------------- */
long long platform_now_ms(void);                 /* 墙钟毫秒 */
long long platform_uptime_ms(void);              /* 单调毫秒，用于超时 */
void platform_monotonic_ts(struct timespec *ts); /* 单调时间（CLOCK_MONOTONIC） */

/* 系统 curl（网页登录流程用），找不到返回 NULL */
const char *platform_curl_path(void);

/* 真随机（RAND_bytes） */
int platform_random_bytes(void *buf, size_t n);

/* SHA-256（PKCE / DPoP 用），对应 BearSSL 的 br_sha256_* */
typedef struct {
    EVP_MD_CTX *ctx;
} br_sha256_context;
void br_sha256_init(br_sha256_context *ctx);
void br_sha256_update(br_sha256_context *ctx, const void *data, size_t len);
void br_sha256_out(br_sha256_context *ctx, void *out);

/* 目录/路径小工具 */
int  platform_mkdir(const char *path);   /* 已存在也算成功 */
int  platform_copy_file(const char *src, const char *dst);
void platform_path_join(char *out, size_t n, const char *dir, const char *name);
const char *platform_exe_dir(void);      /* exe 所在目录（绝对路径） */

/* ---------------- router-c 公共定义 ---------------- */

typedef struct {
    char server[256];
    char client_name[128];
    char mode[16];       /* account | remote */
    char token_file[256];
    char account[128];
    char password[128];
    int  lang;
    char log_file[256];
    char http[64];
    char login[16];      /* password = 账号密码/邮件验证码网页流程；device = OAuth 设备码 */
    int  autostart;      /* GUI：启动程序时自动连接 */
} app_config;

typedef struct {
    char access_token[2048];
    char refresh_token[2048];
    char id_token[4096];
    char expires_at[64];
    char obtained_at[64];
    char scope[512];
    char user_id[128];
    char account[128];
} token_info;

typedef struct {
    char cid[256];
    char pid[128];
    char title[128];
} cid_result;

/* log.c */
void log_init(const char *path);
void log_print(const char *fmt, ...);
void log_err(const char *fmt, ...);
char *log_tail(int n);
void log_clear(void);
void log_set_instance_log(const char *path);   /* 线程级：同一条日志同写实例文件 */
void log_set_console(int on);                  /* 无头守护进程：同时打到 stdout（journal） */

/* aes.c：AES-256-CBC（key 固定为 AES_KEY，iv 由调用方给），返回输出字节数 */
int aes_cbc_crypt(int encrypt, const unsigned char *iv,
                  const unsigned char *in, size_t len, unsigned char *out);

/* util.c */
long long now_ms(void);
void iso_now(char *buf, size_t n, int plus_seconds);
char *json_escape(const char *s, char *out, size_t outn);
int json_unescape(const char *in, char *out, size_t outn);
int parse_json_str(const char *json, const char *key, char *out, size_t outn);
int parse_json_int(const char *json, const char *key, int defval);
int json_extract_objects(const char *data, const char *key,
                         char *objs, size_t objsize, int max);
int http_post(const char *url, const char *ctype, const char *body,
              const char *extra_headers, char *resp, size_t respn, int *status);

#endif
