/* log.c - 环形内存日志 + 文件（512KB 轮转）
   Windows 版额外支持「线程级实例日志」：worker 线程设置自己的日志文件后，
   同一条日志同时写全局日志与该实例日志（GUI 按实例显示）。 */
#include "common.h"

#define RING_MAX 400
#define LOG_MAX  (512 << 10)

static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static char *ring[RING_MAX];
static int ring_len = 0, ring_head = 0;
static char log_path[320] = "app.log";
static __thread char tls_inst_log[320];
static int log_console = 0;

void log_init(const char *path) {
    if (path && *path) snprintf(log_path, sizeof log_path, "%s", path);
}

void log_set_console(int on) { log_console = on ? 1 : 0; }

void log_set_instance_log(const char *path) {
    snprintf(tls_inst_log, sizeof tls_inst_log, "%s", (path && *path) ? path : "");
}

static void append_file(const char *path, const char *line) {
    if (!path || !*path) return;
    FILE *f = fopen(path, "r");
    long sz = 0;
    if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }
    if (sz > LOG_MAX) remove(path);
    f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", line); fclose(f); }
}

static void log_write(const char *level, const char *fmt, va_list ap) {
    char msg[2048], line[2300], ts[32];
    vsnprintf(msg, sizeof msg, fmt, ap);
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    strftime(ts, sizeof ts, "%m-%d %H:%M:%S", &tmv);
    snprintf(line, sizeof line, "[%s] %s%s", ts, level, msg);

    if (log_console) { fputs(line, stdout); fputc('\n', stdout); fflush(stdout); }

    pthread_mutex_lock(&log_mu);
    free(ring[ring_head]);
    ring[ring_head] = _strdup(line);
    ring_head = (ring_head + 1) % RING_MAX;
    if (ring_len < RING_MAX) ring_len++;
    pthread_mutex_unlock(&log_mu);

    append_file(log_path, line);
    if (tls_inst_log[0]) append_file(tls_inst_log, line);
}

void log_print(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_write("", fmt, ap);
    va_end(ap);
}

void log_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_write("[E] ", fmt, ap);
    va_end(ap);
}

void log_clear(void) {
    pthread_mutex_lock(&log_mu);
    for (int i = 0; i < RING_MAX; i++) {
        free(ring[i]);
        ring[i] = NULL;
    }
    ring_len = 0;
    ring_head = 0;
    pthread_mutex_unlock(&log_mu);
    remove(log_path);
    if (tls_inst_log[0]) remove(tls_inst_log);
}

char *log_tail(int n) {
    static char buf[32768];
    buf[0] = 0;
    pthread_mutex_lock(&log_mu);
    if (n <= 0 || n > ring_len) n = ring_len;
    size_t o = 0;
    for (int i = ring_len - n; i < ring_len; i++) {
        int idx = (ring_head - ring_len + i + RING_MAX * 2) % RING_MAX;
        if (!ring[idx]) continue;
        o += (size_t)snprintf(buf + o, sizeof buf - o, "%s\n", ring[idx]);
        if (o >= sizeof buf - 2) break;
    }
    pthread_mutex_unlock(&log_mu);
    return buf;
}
