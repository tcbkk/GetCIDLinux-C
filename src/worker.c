/* worker.c - 每个实例的连接循环 / 消息分发 / 任务处理
   逻辑移植自 router-c 的 main.c（Linux 服务端 router），去掉 web/httpd 部分，
   增加 GUI 需要的启停控制与按实例日志。 */
#include "app.h"
#include "config.h"
#include "b64.h"
#include "proto.h"
#include "msft.h"
#include "mslogin.h"
#include "reverse.h"
#include "ws.h"
#include "devlogin.h"

/* ---------- 实例日志 ---------- */

static void inst_log(app_state *a, const char *fmt, ...) {
    char path[360];
    config_instance_log(a, path, sizeof path);
    log_set_instance_log(path);
    char msg[1800];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    log_print("[%s] %s", a->cfg.client_name, msg);
    log_set_instance_log("");
}

/* ---------- 消息组装 ---------- */

static void msg_init(client_message *m, const char *from) {
    memset(m, 0, sizeof *m);
    snprintf(m->to, sizeof m->to, "server");
    m->lang = 1;
    m->user_type = 4;
    m->show_price = 1;   /* 缺省与 ReceivedData 一致：显示价格 */
    snprintf(m->from, sizeof m->from, "%s", from);
}

static void apply_status(client_message *m, int busy) {
    snprintf(m->call_status, sizeof m->call_status, "%s", busy ? "true" : "false");
    snprintf(m->get_status, sizeof m->get_status, "%s", busy ? "true" : "false");
}

static int send_msg(app_state *a, client_message *m) {
    char plain[32768], esc_text[24576], esc_from[256], esc_outer[256];
    char esc_fromid[256], esc_groupid[256], esc_convid[256];
    char et[40960], outer[65536];
    json_escape(m->text, esc_text, sizeof esc_text);
    json_escape(m->from, esc_from, sizeof esc_from);
    json_escape(a->cfg.client_name, esc_outer, sizeof esc_outer);
    json_escape(m->from_id, esc_fromid, sizeof esc_fromid);
    json_escape(m->group_id, esc_groupid, sizeof esc_groupid);
    json_escape(m->conversation_id, esc_convid, sizeof esc_convid);
    snprintf(plain, sizeof plain,
        "{\"clientId\":\"\",\"type\":\"%s\",\"text\":\"%s\",\"iid\":\"%s\",\"cid\":\"%s\","
         "\"from\":\"%s\",\"to\":\"%s\",\"lang\":%d,\"userType\":%d,\"UserFrom\":0,"
         "\"LanguageId\":0,\"showPrice\":%d,\"fromId\":\"%s\",\"groupId\":\"%s\","
         "\"conversationId\":\"%s\",\"isTopic\":%s,\"topicId\":%lld,"
         "\"callStatus\":\"%s\",\"getStatus\":\"%s\",\"status\":false,"
         "\"startTime\":\"0001-01-01T00:00:00\",\"result\":\"%s\"}",
        m->type, esc_text, m->iid, m->cid, esc_from, m->to, m->lang,
        m->user_type, m->show_price, esc_fromid, esc_groupid, esc_convid,
        m->is_topic ? "true" : "false", m->topic_id,
        m->call_status, m->get_status, m->result);
    if (!proto_encrypt(plain, et, sizeof et)) {
        log_err("[发送] 加密失败");
        return -1;
    }
    int on = snprintf(outer, sizeof outer, "{\"text\":\"%s\",\"from\":\"%s\"}", et, esc_outer);
    return ws_send_text(&a->ws, outer, (size_t)on);
}

/* ---------- 忙闲判定 ---------- */

int app_remote_healthy(app_state *a) {
    (void)a;
    return 0;   /* Windows 版只做 account 模式 */
}

static int app_busy_now(app_state *a) {
    if (a->paused || !a->want_run) return 1;
    if (a->active > 0 || a->token_broke) return 1;
    if (tm_is_broken(&a->tm)) return 1;
    if (!tm_healthy(&a->tm)) return 1;
    return 0;
}

/* ---------- 任务处理 ---------- */

static int is_numeric(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return 0;
    return 1;
}

static void result_json(char *out, size_t n, const char *cid, const char *pid, const char *name) {
    char ec[300], ep[200], en[200];
    snprintf(out, n, "{\"cid\":\"%s\",\"pid\":\"%s\",\"productName\":\"%s\"}",
             json_escape(cid, ec, sizeof ec),
             json_escape(pid, ep, sizeof ep),
             json_escape(name, en, sizeof en));
}

static void send_success(app_state *a, client_message *m, const char *cid, const char *pid, const char *name) {
    client_message r = *m;
    snprintf(r.type, sizeof r.type, "succeed");
    result_json(r.text, sizeof r.text, cid, pid, name);
    snprintf(r.cid, sizeof r.cid, "%s", cid);
    apply_status(&r, app_busy_now(a));
    send_msg(a, &r);
}

static void send_failure(app_state *a, client_message *m, const char *cid, const char *pid, const char *name) {
    inst_log(a, "[失败] %s -> %s", m->iid, cid);
    client_message r = *m;
    snprintf(r.type, sizeof r.type, "getcid");
    result_json(r.text, sizeof r.text, cid, pid, name);
    snprintf(r.cid, sizeof r.cid, "%s", cid);
    apply_status(&r, app_busy_now(a));
    send_msg(a, &r);
}

static void send_failover(app_state *a, client_message *m, const char *reason, const char *pid, const char *name) {
    inst_log(a, "[失败上报] %s 原因: %s", m->iid, reason);
    client_message r = *m;
    snprintf(r.type, sizeof r.type, "getfailed");
    snprintf(r.result, sizeof r.result, "%s", reason);
    r.cid[0] = 0;
    result_json(r.text, sizeof r.text, "", pid, name);
    apply_status(&r, app_busy_now(a));
    send_msg(a, &r);
}

/* 本机 token 取号（GUI 的「测试取号」也走这里） */
void app_check_cid(app_state *a, const char *iid, char *cid, size_t cn,
                   char *pid, size_t pn, char *title, size_t tn) {
    if (cid && cn) cid[0] = 0;
    if (pid && pn) pid[0] = 0;
    if (title && tn) title[0] = 0;
    char it[4096], uid[128];
    if (tm_get_id_token(&a->tm, it, sizeof it, uid, sizeof uid) != 0) {
        a->token_broke = 1;
        if (cid && cn) snprintf(cid, cn, "token 不可用（需要先登录 / 刷新）");
        return;
    }
    cid_result r = fetch_cid(iid, it, uid, a->cfg.lang);
    if (!tm_healthy(&a->tm)) a->token_broke = 1;
    if (cid && cn) snprintf(cid, cn, "%s", r.cid);
    if (pid && pn) snprintf(pid, pn, "%s", r.pid);
    if (title && tn) snprintf(title, tn, "%s", r.title);
}

static void get_cid(app_state *a, const char *iid, int lang, char *cid, size_t cidn,
                    char *pid, size_t pidn, char *name, size_t namen) {
    cid[0] = pid[0] = name[0] = 0;
    char it[4096], uid[128];
    if (tm_get_id_token(&a->tm, it, sizeof it, uid, sizeof uid) != 0) {
        a->token_broke = 1;
        inst_log(a, "[token:%s] 不可用（refresh_token 缺失或已过期）", a->tm.name);
        return;
    }
    cid_result r = fetch_cid(iid, it, uid, lang);
    if (!tm_healthy(&a->tm)) a->token_broke = 1;
    snprintf(cid, cidn, "%s", r.cid);
    snprintf(pid, pidn, "%s", r.pid);
    snprintf(name, namen, "%s", r.title);
}

static int retryable_reason(const char *cid, char *reason, size_t rn) {
    if (!cid[0]) { snprintf(reason, rn, "empty"); return 1; }
    if (!strcmp(cid, "获取异常，已超时") || !strcmp(cid, "Timeout, please try again")) {
        snprintf(reason, rn, "timeout");
        return 1;
    }
    return 0;
}

static void handle_task(app_state *a, client_message *m) {
    if (!m->iid[0] || !is_numeric(m->iid)) return;
    a->task_count++;
    a->active++;

    app_set_status(a, 1);
    client_message prog = *m;
    snprintf(prog.type, sizeof prog.type, "text");
    if (m->lang == 0) snprintf(prog.text, sizeof prog.text, "\xE2\x9C\x85 IID detected,fetching...");
    else snprintf(prog.text, sizeof prog.text, "收到安装ID,正在获取...");
    apply_status(&prog, 1);
    send_msg(a, &prog);
    inst_log(a, "[任务] 开始取号");

    char cid[256] = "", pid[128] = "", name[128] = "";
    get_cid(a, m->iid, m->lang, cid, sizeof cid, pid, sizeof pid, name, sizeof name);

    char reason[32];
    if (is_numeric(cid)) {
        send_success(a, m, cid, pid, name);
        a->last_cid_ok = 1;
        snprintf(a->last_cid, sizeof a->last_cid, "%s", cid);
        snprintf(a->last_pid, sizeof a->last_pid, "%s", pid);
        snprintf(a->last_product, sizeof a->last_product, "%s", name);
        snprintf(a->last_line, sizeof a->last_line, "成功 CID %s", cid);
        inst_log(a, "[任务] 成功 CID=%s (%s)", cid, name);
    } else if (retryable_reason(cid, reason, sizeof reason)) {
        send_failover(a, m, reason, pid, name);
        a->last_cid_ok = 0;
        snprintf(a->last_line, sizeof a->last_line, "失败（%s）", reason);
    } else if (a->token_broke) {
        send_failover(a, m, "token", pid, name);
        a->last_cid_ok = 0;
        snprintf(a->last_line, sizeof a->last_line, "失败：token 失效");
    } else {
        send_failure(a, m, cid, pid, name);
        a->last_cid_ok = 0;
        snprintf(a->last_line, sizeof a->last_line, "失败：%.120s", cid);
    }

    a->active--;
    if (a->token_broke) app_set_status(a, 1);
    else if (a->active == 0) app_set_status(a, app_busy_now(a));
}

/* ---------- 队列 ---------- */

static void queue_push(app_state *a, client_message *m) {
    pthread_mutex_lock(&a->q_mu);
    if (a->q_len < (int)(sizeof a->queue / sizeof a->queue[0])) {
        a->queue[a->q_tail] = *m;
        a->q_tail = (a->q_tail + 1) % (int)(sizeof a->queue / sizeof a->queue[0]);
        a->q_len++;
        pthread_cond_signal(&a->q_cv);
    } else {
        inst_log(a, "[队列] 已满，丢弃任务 %s", m->iid);
    }
    pthread_mutex_unlock(&a->q_mu);
}

static void *worker_main(void *arg) {
    app_state *a = arg;
    log_set_instance_log(a->cfg.log_file);
    for (;;) {
        pthread_mutex_lock(&a->q_mu);
        while (a->q_len == 0 && a->want_run && !g_stop) pthread_cond_wait(&a->q_cv, &a->q_mu);
        if ((g_stop || !a->want_run) && a->q_len == 0) { pthread_mutex_unlock(&a->q_mu); break; }
        client_message m = a->queue[a->q_head];
        a->q_head = (a->q_head + 1) % (int)(sizeof a->queue / sizeof a->queue[0]);
        a->q_len--;
        pthread_mutex_unlock(&a->q_mu);
        handle_task(a, &m);
    }
    log_set_instance_log("");
    return NULL;
}

/* ---------- 状态上报 ---------- */

void app_set_status(app_state *a, int busy) {
    const char *v = busy ? "true" : "false";
    pthread_mutex_lock(&a->q_mu);
    int same = strcmp(a->last_status, v) == 0;
    if (!same) snprintf(a->last_status, sizeof a->last_status, "%s", v);
    pthread_mutex_unlock(&a->q_mu);
    if (same) return;
    app_send_status_report(a);
}

int app_send_status_report(app_state *a) {
    int busy = app_busy_now(a);
    pthread_mutex_lock(&a->q_mu);
    snprintf(a->last_status, sizeof a->last_status, "%s", busy ? "true" : "false");
    pthread_mutex_unlock(&a->q_mu);
    client_message m;
    msg_init(&m, a->cfg.client_name);
    snprintf(m.type, sizeof m.type, "getStatus");
    snprintf(m.text, sizeof m.text, "false");
    apply_status(&m, busy);
    if (!a->connected) return -1;
    return send_msg(a, &m);
}

/* ---------- 分发 ---------- */

static void dispatch(app_state *a, const client_message *m) {
    if (a->paused && (!strcmp(m->type, "getcid") || !strcmp(m->type, "batchget"))) {
        inst_log(a, "[暂停] 已停止，丢弃一条 %s 任务（%s）", m->type, m->iid);
        return;
    }
    if (!strcmp(m->type, "getcid")) {
        queue_push(a, (client_message *)m);
    } else if (!strcmp(m->type, "batchget")) {
        const char *p = m->text;
        while ((p = strchr(p, '"')) != NULL) {
            const char *kend = strchr(p + 1, '"');
            if (!kend) break;
            size_t klen = (size_t)(kend - p - 1);
            if (klen >= 6 && klen <= 64) {
                int all_digits = 1;
                for (size_t i = 0; i < klen; i++)
                    if (p[1 + i] < '0' || p[1 + i] > '9') { all_digits = 0; break; }
                if (all_digits) {
                    const char *v = kend + 1;
                    while (*v == ' ' || *v == ':') v++;
                    if (*v == '{') {
                        int depth = 0;
                        const char *vend = v;
                        int in_str = 0;
                        while (*vend) {
                            if (*vend == '"' && *(vend - 1) != '\\') in_str = !in_str;
                            if (!in_str) {
                                if (*vend == '{') depth++;
                                if (*vend == '}') { depth--; if (depth == 0) break; }
                            }
                            vend++;
                        }
                        client_message mm;
                        msg_init(&mm, m->from);
                        size_t vlen = (size_t)(vend - v + 1);
                        if (vlen >= sizeof mm.text) vlen = sizeof mm.text - 1;
                        memcpy(mm.text, v, vlen);
                        mm.text[vlen] = 0;
                        if (parse_json_str(mm.text, "iid", mm.iid, sizeof mm.iid) != 0 || !mm.iid[0]) {
                            size_t cl = klen < sizeof mm.iid - 1 ? klen : sizeof mm.iid - 1;
                            memcpy(mm.iid, p + 1, cl);
                            mm.iid[cl] = 0;
                        }
                        char f[128];
                        if (parse_json_str(mm.text, "from", f, sizeof f) != 0 || !f[0])
                            snprintf(mm.from, sizeof mm.from, "%s", m->from);
                        else snprintf(mm.from, sizeof mm.from, "%s", f);
                        mm.lang = parse_json_int(mm.text, "lang", 1);
                        queue_push(a, &mm);
                        p = vend + 1;
                        continue;
                    }
                }
            }
            p = kend + 1;
        }
    } else if (!strcmp(m->type, "status")) {
        app_set_status(a, app_busy_now(a));
    } else if (!strcmp(m->type, "restartclient")) {
        inst_log(a, "[控制] 服务器要求重启客户端");
        a->want_run = 0;
        a->connected = 0;
    }
}

/* ---------- 读线程 ---------- */

static void *reader_main(void *arg) {
    app_state *a = arg;
    log_set_instance_log(a->cfg.log_file);
    char buf[131072];
    for (;;) {
        if (g_stop || !a->want_run || !a->connected) break;
        int r = ws_read_text(&a->ws, buf, sizeof buf, 60);
        if (r == 0) {
            /* 空闲超时不是断线：只发 ping 探活 */
            inst_log(a, "[连接] 60 秒无数据帧，发 ping 探活");
            if (ws_send_ping(&a->ws) != 0) {
                inst_log(a, "[连接] ping 失败（空闲探活），断开重连");
                a->connected = 0;
                break;
            }
            continue;
        }
        if (r < 0) {
            inst_log(a, "[连接] 读取失败 rc=%d（连接关闭）", r);
            a->connected = 0;
            break;
        }
        char *s = buf;
        while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') s++;
        if (*s != '{') { inst_log(a, "[收] 非 JSON 帧，忽略: %.120s", s); continue; }
        char text[65536];
        if (parse_json_str(s, "text", text, sizeof text) != 0 || !text[0]) {
            inst_log(a, "[收] 缺 text 字段，忽略: %.160s", s);
            continue;
        }
        char plain[32768];
        if (proto_decrypt(text, plain, sizeof plain) <= 0) {
            inst_log(a, "[收] 解密失败（b64 长度=%d）", (int)strlen(text));
            continue;
        }
        client_message m;
        msg_init(&m, a->cfg.client_name);
        parse_json_str(plain, "clientId", m.client_id, sizeof m.client_id);
        parse_json_str(plain, "type", m.type, sizeof m.type);
        parse_json_str(plain, "text", m.text, sizeof m.text);
        parse_json_str(plain, "iid", m.iid, sizeof m.iid);
        parse_json_str(plain, "cid", m.cid, sizeof m.cid);
        parse_json_str(plain, "from", m.from, sizeof m.from);
        parse_json_str(plain, "to", m.to, sizeof m.to);
        parse_json_str(plain, "result", m.result, sizeof m.result);
        m.lang = parse_json_int(plain, "lang", 0);
        m.user_type = parse_json_int(plain, "userType", 0);
        /* showPrice 必须回显派单请求里的值：服务端按它决定回包显不显示价格（0=群/用户关了价格显示）。 */
        m.show_price = parse_json_int(plain, "showPrice", 1);
        parse_json_str(plain, "fromId", m.from_id, sizeof m.from_id);
        parse_json_str(plain, "groupId", m.group_id, sizeof m.group_id);
        parse_json_str(plain, "conversationId", m.conversation_id, sizeof m.conversation_id);
        m.is_topic = strstr(plain, "\"isTopic\":true") != NULL;
        m.topic_id = parse_json_int(plain, "topicId", 0);
        parse_json_str(plain, "callStatus", m.call_status, sizeof m.call_status);
        parse_json_str(plain, "getStatus", m.get_status, sizeof m.get_status);
        if (!m.type[0]) continue;
        {
            /* IID 有 81 位，全打出来太吵：只留尾号 10 位，需要全文时看实例日志的服务端原文 */
            size_t ilen = strlen(m.iid);
            inst_log(a, "[收] %s%s%.10s", m.type, ilen > 10 ? " (iid=…" : " (iid=",
                     ilen > 10 ? m.iid + ilen - 10 : m.iid);
        }
        dispatch(a, &m);
    }
    log_set_instance_log("");
    return NULL;
}

/* ---------- 连接主循环 ---------- */

static int handshake(app_state *a) {
    client_message m;
    msg_init(&m, a->cfg.client_name);
    snprintf(m.type, sizeof m.type, "getStatus");
    snprintf(m.text, sizeof m.text, "true");
    snprintf(m.call_status, sizeof m.call_status, "false");
    snprintf(m.get_status, sizeof m.get_status, "false");
    int rc = send_msg(a, &m);
    if (rc != 0) inst_log(a, "[连接] 握手发送失败 rc=%d", rc);
    return rc;
}

static void *run_thread(void *arg) {
    app_state *a = arg;
    log_set_instance_log(a->cfg.log_file);
    int backoff = 2;
    while (a->want_run && !g_stop) {
        inst_log(a, "[连接] %s", a->cfg.server);
        if (ws_connect(&a->ws, a->cfg.server) != 0) {
            inst_log(a, "[连接] 失败，%d 秒后重试", backoff);
            for (int i = 0; i < backoff && a->want_run && !g_stop; i++) sleep(1);
            backoff *= 2;
            if (backoff > 30) backoff = 30;
            continue;
        }
        backoff = 2;
        a->connected = 1;
        a->paused = 0;
        a->last_status[0] = 0;
        inst_log(a, "[连接] WS 已建立 → %s", a->cfg.server);
        inst_log(a, "[token] %s", tm_state_text(&a->tm));
        handshake(a);
        app_set_status(a, app_busy_now(a));

        pthread_t rth;
        thread_spawn(&rth, reader_main, a);

        /* 心跳：每 20 秒一条状态数据帧 + ping，1 秒粒度检查断开 */
        for (;;) {
            int alive = 1;
            for (int t = 0; t < 20; t++) {
                sleep(1);
                if (g_stop || !a->want_run || !a->connected) { alive = 0; break; }
            }
            if (!alive) break;
            int sr = app_send_status_report(a);
            int pr = ws_send_ping(&a->ws);
            if (sr != 0 || pr != 0) {
                inst_log(a, "[连接] 心跳发送失败（status=%d ping=%d），断开重连", sr, pr);
                break;
            }
        }
        a->connected = 0;
        ws_close(&a->ws);
        pthread_join(rth, NULL);
        inst_log(a, "[连接] 断开，2 秒后重连");
        if (g_stop || !a->want_run) break;
        sleep(2);
    }
    a->connected = 0;
    a->running = 0;
    a->paused = 1;
    inst_log(a, "[停止] 已停止");
    log_set_instance_log("");
    return NULL;
}

/* ---------- 启动 / 停止 ---------- */

/* 设备码登录要发 HTTPS 请求（1~2 秒），不能在 GUI 线程里跑 */
typedef struct { app_state *a; } dev_start_arg;
static void *dev_start_thread(void *p) {
    dev_start_arg *x = p;
    devlogin_start(x->a);
    free(x);
    return NULL;
}

void app_start(app_state *a) {
    if (a->running) return;
    a->want_run = 1;
    a->paused = 0;
    a->running = 1;
    a->token_broke = 0;

    inst_log(a, "[启动] → %s（%s / %s）", a->cfg.server,
             a->cfg.mode, a->cfg.login[0] ? a->cfg.login : "password");

    if (!a->token_loop_started) {
        a->token_loop_started = 1;
        pthread_t tmth;
        thread_spawn(&tmth, tm_refresh_loop, &a->tm);
    }

    /* 设备码模式：没有可用 token 就去要一个 code（有 token 就先复用，等失效再说） */
    if (strcmp(a->cfg.login, "device") == 0 && !tm_healthy(&a->tm)) {
        dev_start_arg *x = calloc(1, sizeof *x);
        if (x) {
            x->a = a;
            pthread_t dth;
            thread_spawn(&dth, dev_start_thread, x);
            pthread_detach(dth);
        }
    }

    thread_spawn(&a->work_th, worker_main, a);
    pthread_detach(a->work_th);

    thread_spawn(&a->run_th, run_thread, a);
}

void app_stop(app_state *a) {
    if (!a->want_run) return;
    a->want_run = 0;
    a->paused = 1;
    a->connected = 0;
    inst_log(a, "[停止] 收到停止指令");
    /* 停下来的实例不该再占着设备码提示条：那个码就算还能用也不再跟随该实例 */
    devlogin_reset(a);
    ws_close(&a->ws);           /* 让读线程立刻从 recv 返回 */
    pthread_cond_broadcast(&a->q_cv);
}

int app_running(app_state *a) { return a->want_run; }

void app_wait_stopped(app_state *a) {
    if (a->run_th) {
        { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 5; pthread_timedjoin_np(a->run_th, NULL, &ts); }
        a->run_th = NULL;
    }
    /* worker_main 也要等：不然改名重启后可能同时存在两个 worker 线程 */
    if (a->work_th) {
        { struct timespec ts2; clock_gettime(CLOCK_REALTIME, &ts2); ts2.tv_sec += 5; pthread_timedjoin_np(a->work_th, NULL, &ts2); }
        a->work_th = NULL;
    }
}

void worker_stop_all(void) {
    g_stop = 1;
    for (int i = 0; i < NINST; i++) {
        APPS[i].want_run = 0;
        APPS[i].connected = 0;
        ws_close(&APPS[i].ws);
        pthread_cond_broadcast(&APPS[i].q_cv);
    }
}

/* ---------- 手动登录 / 提交验证码 ---------- */

int app_login_manual(app_state *a, const char *account, const char *password,
                     int *need_code, char *masked, size_t mn,
                     char *msg, size_t msgn, char *err, size_t en) {
    int transient = 0;
    log_set_instance_log(a->cfg.log_file);
    int rc = ms_pwd_login(a, account, password, 0, need_code, masked, mn,
                          msg, msgn, err, en, &transient);
    log_set_instance_log("");
    return rc;
}

int app_submit_code(app_state *a, const char *input, int *sent, char *msg, size_t msgn,
                    char *err, size_t en) {
    log_set_instance_log(a->cfg.log_file);
    int rc = ms_verify(a, input, sent, msg, msgn, err, en);
    log_set_instance_log("");
    return rc;
}

int app_has_pending(app_state *a) { return ms_has_pending(a); }
