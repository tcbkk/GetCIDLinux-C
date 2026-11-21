/* daemon.c - 无头守护进程（Linux 服务器版）
   用法：getcid --config /opt/serverclient40/appsettings.json
   兼容 C# 版 appsettings.json 的字段：Server / ClientName / Username / Password / Prompt(file|device) / LogDirectory
   需要人工验证时把请求写到 <目录>/prompt/request.txt，答案从 prompt/answer.txt 读回
   （格式与 C# 版 FileVerificationPrompt 一致，网页控制台可以直接应答）。 */
#include "app.h"
#include "msft.h"
#include "mslogin.h"
#include "devlogin.h"
#include "prompt_file.h"

static char D_DIR[320];
static char D_PROMPT[400];
static char D_LOGDIR[360];
static app_state *A;

static int read_all(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "rb");
    size_t dn;
    if (!f) return -1;
    dn = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[dn] = 0;
    return 0;
}

static void cfg_str(const char *json, const char *key, char *out, size_t n, const char *def) {
    out[0] = 0;
    parse_json_str(json, key, out, n);
    if (!out[0] && def) snprintf(out, n, "%s", def);
}

/* 问收件邮箱 → 提交；问 6 位码 → 提交。返回 0 = 登录完成 */
static int finish_code_steps(app_state *a) {
    int sent = 0, step;
    char msg[700], err[700];

    for (step = 0; step < 3; step++) {
        char *ans;
        if (!ms_has_pending(a)) return 0;
        ans = prompt_ask(D_PROMPT, "收件邮箱",
                         "微软要往这个邮箱发一次性验证码：请填完整收件邮箱（形如 xx@outlook.com），"
                         "不要填界面上的掩码。写进 prompt/answer.txt 即可（VALUE=邮箱）。", 900);
        if (!ans) return -1;
        sent = 0;
        msg[0] = err[0] = 0;
        int rc = app_submit_code(a, ans, &sent, msg, sizeof msg, err, sizeof err);
        free(ans);
        if (rc != 0) {
            log_err("[守护] 提交收件邮箱失败：%s", err[0] ? err : msg);
            return -1;
        }
        log_print("[守护] %s", msg[0] ? msg : (sent ? "验证码已发送" : "登录完成"));

        if (!sent) return 0;   /* 账号不需要验证码，直接完成 */

        ans = prompt_ask(D_PROMPT, "邮箱验证码",
                         "请填邮件里的 6 位验证码（只填数字）。写进 prompt/answer.txt 即可（VALUE=123456）。", 900);
        if (!ans) return -1;
        sent = 0;
        msg[0] = err[0] = 0;
        rc = app_submit_code(a, ans, &sent, msg, sizeof msg, err, sizeof err);
        free(ans);
        if (rc != 0) {
            log_err("[守护] 验证码被拒：%s", err[0] ? err : msg);
            continue;          /* 再问一次，允许输错重来 */
        }
        log_print("[守护] %s", msg[0] ? msg : "登录完成");
        return 0;
    }
    return -1;
}

/* 走一次完整登录：密码登录 → （需要验证码）等人工应答 */
static int login_once(app_state *a) {
    int need_code = 0;
    char masked[256], msg[700], err[700];
    int rc;
    if (ms_has_pending(a)) return finish_code_steps(a);

    msg[0] = err[0] = masked[0] = 0;
    log_print("[守护] 开始密码登录 %s", a->cfg.account);
    rc = app_login_manual(a, a->cfg.account, a->cfg.password, &need_code,
                          masked, sizeof masked, msg, sizeof msg, err, sizeof err);
    if (rc == 0 && !need_code) {
        log_print("[守护] %s", msg[0] ? msg : "登录完成，token 已保存");
        return 0;
    }
    if (rc < 0) {
        log_err("[守护] 登录失败：%s", err[0] ? err : msg);
        return -1;
    }
    /* rc==1 或 need_code：微软要邮箱验证码，不是失败，直接进人工应答 */
    log_print("[守护] %s", msg[0] ? msg : "微软要求邮箱验证码，等待人工应答");
    return finish_code_steps(a);
}

/* 返回设备码状态：0=idle 1=等浏览器 2=成功 3=出错 */
static int device_prompt_tick(app_state *a, char *last_code, size_t n) {
    int status = 0, left = -1;
    char code[64] = "", url[300] = "", msg[300] = "";

    devlogin_info(a, &status, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
    if (status == 1 && code[0]) {
        if (strcmp(code, last_code) != 0) {
            snprintf(last_code, n, "%s", code);
            prompt_device_code(D_PROMPT, url, code, left > 0 ? left : 900);
        }
    } else if (status == 2) {
        if (last_code[0]) {
            last_code[0] = 0;
            prompt_device_clear(D_PROMPT);
            log_print("[守护] 设备码登录完成，token 已保存");
        }
    } else if (status == 3) {
        if (last_code[0]) {
            last_code[0] = 0;
            prompt_device_clear(D_PROMPT);
        }
        log_err("[守护] 设备码登录失败：%s", msg[0] ? msg : "未知原因");
    }
    return status;
}

int daemon_main(int argc, char **argv) {
    char cfgpath[400] = "appsettings.json";
    char json[32768];
    char logdir[128] = "logs";
    char logp[400], ymd[32], logfile[400];
    char promptmode[32] = "file";
    struct tm tmv;
    time_t now;
    long long last_login_try = 0;
    long long login_backoff_ms = 60000;
    int login_fails = 0;
    char last_code[64] = "";
    int device_retry_at = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) snprintf(cfgpath, sizeof cfgpath, "%s", argv[++i]);
    }

    /* 相对 config 文件定位数据目录 */
    snprintf(D_DIR, sizeof D_DIR, "%s", cfgpath);
    {
        char *slash = strrchr(D_DIR, '/');
        if (slash && slash != D_DIR) *slash = 0;
        else snprintf(D_DIR, sizeof D_DIR, ".");
    }
    if (chdir(D_DIR) != 0)
        log_err("[守护] 切换目录失败 %s: %s", D_DIR, strerror(errno));
    snprintf(G_DATA_DIR, sizeof G_DATA_DIR, "%s", D_DIR);
    snprintf(G_CFG_DIR, sizeof G_CFG_DIR, "%s", D_DIR);
    snprintf(D_PROMPT, sizeof D_PROMPT, "%s/%s", D_DIR, PROMPT_DIR);
    platform_mkdir(D_PROMPT);

    if (read_all(cfgpath, json, sizeof json) != 0) {
        fprintf(stderr, "读不到配置 %s\n", cfgpath);
        return 1;
    }

    cfg_str(json, "LogDirectory", logdir, sizeof logdir, "logs");
    platform_mkdir(logdir);
    snprintf(D_LOGDIR, sizeof D_LOGDIR, "%s/%s", D_DIR, logdir);
    snprintf(logp, sizeof logp, "%s/app.log", D_LOGDIR);
    log_init(logp);
    log_set_console(1);

    memset(APPS, 0, sizeof APPS);
    NINST = 1;
    A = &APPS[0];
    A->idx = 0;
    cfg_str(json, "Server", A->cfg.server, sizeof A->cfg.server, "ws://getcid.live:8082");
    cfg_str(json, "ClientName", A->cfg.client_name, sizeof A->cfg.client_name, "serverclient01");
    cfg_str(json, "Username", A->cfg.account, sizeof A->cfg.account, "");
    cfg_str(json, "Password", A->cfg.password, sizeof A->cfg.password, "");
    cfg_str(json, "Prompt", promptmode, sizeof promptmode, "file");
    snprintf(A->cfg.mode, sizeof A->cfg.mode, "account");
    if (strcasecmp(promptmode, "device") == 0)
        snprintf(A->cfg.login, sizeof A->cfg.login, "device");
    else
        snprintf(A->cfg.login, sizeof A->cfg.login, "password");
    A->cfg.lang = 1;
    A->cfg.autostart = 1;

    snprintf(A->cfg.token_file, sizeof A->cfg.token_file, "%s/vs_tokens.json", D_DIR);
    now = time(NULL);
    localtime_r(&now, &tmv);
    strftime(ymd, sizeof ymd, "%Y%m%d", &tmv);
    snprintf(logfile, sizeof logfile, "%s/%s-%s.log", D_LOGDIR, A->cfg.client_name, ymd);
    snprintf(A->cfg.log_file, sizeof A->cfg.log_file, "%s", logfile);

    log_print("[启动] getcid 守护进程 实例=%s 服务端=%s 登录=%s 目录=%s",
              A->cfg.client_name, A->cfg.server, A->cfg.login, D_DIR);

    tm_init(&A->tm, A->cfg.token_file, A->cfg.client_name);
    if (tm_load(&A->tm) != 0)
        log_print("[token] 本机没有可用 token，需要登录一次");
    else
        log_print("[token] %s", tm_state_text(&A->tm));

    app_start(A);

    /* 若这次是以「密码 + 邮箱安全码」启动，清掉上次设备码模式留下的 pending 提示，
       否则网页控制台会一直显示一张早已作废的设备码卡片 */
    if (strcmp(A->cfg.login, "device") != 0) prompt_clear_stale_device(D_PROMPT);



    while (!g_stop) {
        sleep(2);

        if (strcmp(A->cfg.login, "device") == 0) {
            /* app_start 已经会给一次设备码；这里只负责把码写到 prompt 文件，
               码过期/出错（status 回到 idle）时再补要一次，绝不重复申请。 */
            int dst = device_prompt_tick(A, last_code, sizeof last_code);
            if (dst == 0 && !tm_healthy(&A->tm) && (int)time(NULL) >= device_retry_at) {
                if (devlogin_start(A) == 0) device_retry_at = (int)time(NULL) + 60;
            }
            continue;
        }

        if (tm_healthy(&A->tm) && !ms_has_pending(A)) continue;

        /* 需要登录：等人工的会话先应答，否则重新走一次密码登录。
           失败就指数退避（1→2→5→10→20 分钟）：微软对短时间内反复登录会甩
           「contextID 不匹配」的错误页，硬敲只会把冷却期越拖越长。 */
        {
            long long nowms = platform_uptime_ms();
            if (!ms_has_pending(A) && last_login_try && nowms - last_login_try < login_backoff_ms) continue;
            last_login_try = nowms;
            if (login_once(A) != 0) {
                last_login_try = platform_uptime_ms();
                if (login_fails < 5) login_fails++;
                login_backoff_ms = 60000LL << (login_fails - 1);
                if (login_backoff_ms > 1200000LL) login_backoff_ms = 1200000LL;
                log_print("[守护] 登录未完成，%lld 秒后再试", login_backoff_ms / 1000);
            } else {
                login_fails = 0;
                login_backoff_ms = 60000;
            }
        }
    }

    log_print("[退出] 收到停止信号，正在断开连接");
    app_stop(A);
    app_wait_stopped(A);
    log_print("[退出] 已退出");
    return 0;
}
