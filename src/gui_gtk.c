/* gui_gtk.c - GTK3 界面（Linux 版，布局与 Windows 版逐像素对齐） */
#include <gtk/gtk.h>
#include "config.h"
#include "msft.h"
#include "mslogin.h"
#include "devlogin.h"
#include "gui.h"

#define CLIENT_W 740
#define CLIENT_H 458

/* ---------------- 全局 ---------------- */

static GtkWidget *W_WIN, *W_FIXED, *W_SUMMARY, *W_STATUS;
static GtkWidget *W_STORE, *W_LIST;
static GtkWidget *W_PROMPT, *W_CODE, *W_BTN_SUBMIT;
static GtkWidget *W_BTN_DEVOPEN, *W_BTN_DEVCODE, *W_BTN_DEVACC;
static GtkWidget *W_LOGVIEW, *W_LOGTEXT, *W_LOGBUFF;
static int G_PENDING_IDX = -1;
static long long G_LOG_LAST_LEN = -1;
static gboolean G_LOG_STICK = TRUE;   /* 日志是否追底 */

/* ---------------- 小工具 ---------------- */

static void msgbox(int err, const char *title, const char *fmt, ...) {
    char buf[1400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(W_WIN),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        err ? GTK_MESSAGE_ERROR : GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", title);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", buf);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void clipboard_set(const char *text) {
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
}

static void open_path(const char *path) {
    char *argv[3];
    argv[0] = (char *)"xdg-open";
    argv[1] = (char *)path;
    argv[2] = NULL;
    g_spawn_async(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL);
}

static void set_status(const char *text) { gtk_label_set_text(GTK_LABEL(W_STATUS), text); }

static int selected_idx(void) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(W_LIST));
    GtkTreeModel *m;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &m, &it)) return -1;
    GtkTreePath *p = gtk_tree_model_get_path(m, &it);
    int row = gtk_tree_path_get_indices(p)[0];
    gtk_tree_path_free(p);
    if (row < 0 || row >= NINST) return -1;
    return row;
}

/* 单行输入框对话框 */
static int input_dialog(const char *title, const char *label, const char *def,
                        char *out, size_t outn) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title, GTK_WINDOW(W_WIN),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, "确定", GTK_RESPONSE_OK, NULL);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(d));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *lb = gtk_label_new(label);
    GtkWidget *ed = gtk_entry_new();
    gtk_label_set_line_wrap(GTK_LABEL(lb), TRUE);
    gtk_label_set_xalign(GTK_LABEL(lb), 0.0f);
    gtk_widget_set_size_request(ed, 430, -1);
    if (def && *def) gtk_entry_set_text(GTK_ENTRY(ed), def);
    gtk_box_pack_start(GTK_BOX(box), lb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), ed, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    gtk_container_add(GTK_CONTAINER(area), box);
    gtk_widget_show_all(d);
    gint rc = gtk_dialog_run(GTK_DIALOG(d));
    if (rc == GTK_RESPONSE_OK) snprintf(out, outn, "%s", gtk_entry_get_text(GTK_ENTRY(ed)));
    gtk_widget_destroy(d);
    return rc == GTK_RESPONSE_OK;
}

/* ---------------- 实例编辑对话框 ---------------- */

static int instance_dialog(app_state *a, int is_new) {
    char name[128] = "", acc[128] = "", pwd[128] = "", srv[256] = "", login[16] = "password";
    int autostart = 1;
    if (a) {
        snprintf(name, sizeof name, "%s", a->cfg.client_name);
        snprintf(acc, sizeof acc, "%s", a->cfg.account);
        snprintf(pwd, sizeof pwd, "%s", a->cfg.password);
        snprintf(srv, sizeof srv, "%s", a->cfg.server);
        snprintf(login, sizeof login, "%s", a->cfg.login[0] ? a->cfg.login : "password");
        autostart = a->cfg.autostart;
    }

    GtkWidget *d = gtk_dialog_new_with_buttons(is_new ? "新增实例" : "编辑实例",
        GTK_WINDOW(W_WIN), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_OK, NULL);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(d));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 14);

    const char *labels[4] = {
        "实例名称（服务端显示的名字，如 serverclient01）",
        "服务器（ws://ip:port）",
        "微软账号",
        "密码（只存本机，用于自动重登）"
    };
    const char *vals[4] = { name, srv, acc, pwd };
    GtkWidget *ed[4];
    for (int i = 0; i < 4; i++) {
        GtkWidget *lb = gtk_label_new(labels[i]);
        gtk_label_set_xalign(GTK_LABEL(lb), 0.0f);
        ed[i] = gtk_entry_new();
        gtk_widget_set_size_request(ed[i], 460, -1);
        if (vals[i] && *vals[i]) gtk_entry_set_text(GTK_ENTRY(ed[i]), vals[i]);
        gtk_grid_attach(GTK_GRID(grid), lb, 0, i * 2, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), ed[i], 0, i * 2 + 1, 1, 1);
    }

    GtkWidget *lb_login = gtk_label_new("登录验证方式");
    gtk_label_set_xalign(GTK_LABEL(lb_login), 0.0f);
    GtkWidget *combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "密码登录（账号密码 + 邮箱验证码）");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "设备码登录（免密码，2FA 账号也能用）");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), strcmp(login, "device") == 0 ? 1 : 0);
    GtkWidget *cb = gtk_check_button_new_with_label("程序启动时自动连接该实例");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb), autostart ? TRUE : FALSE);

    gtk_grid_attach(GTK_GRID(grid), lb_login, 0, 8, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), combo, 0, 9, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), cb, 0, 10, 1, 1);
    gtk_container_add(GTK_CONTAINER(area), grid);
    gtk_widget_show_all(d);

    if (gtk_dialog_run(GTK_DIALOG(d)) != GTK_RESPONSE_OK) {
        gtk_widget_destroy(d);
        return 0;
    }
    snprintf(name, sizeof name, "%s", gtk_entry_get_text(GTK_ENTRY(ed[0])));
    snprintf(srv, sizeof srv, "%s", gtk_entry_get_text(GTK_ENTRY(ed[1])));
    snprintf(acc, sizeof acc, "%s", gtk_entry_get_text(GTK_ENTRY(ed[2])));
    snprintf(pwd, sizeof pwd, "%s", gtk_entry_get_text(GTK_ENTRY(ed[3])));
    autostart = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb)) ? 1 : 0;
    snprintf(login, sizeof login, "%s",
             gtk_combo_box_get_active(GTK_COMBO_BOX(combo)) == 1 ? "device" : "password");
    gtk_widget_destroy(d);

    if (!name[0]) { msgbox(1, "新增实例", "实例名称不能为空"); return 0; }
    int other = config_find_by_name(name);
    if (other >= 0 && (!a || other != a->idx)) {
        msgbox(1, "新增实例", "已存在同名实例：%s", name);
        return 0;
    }

    if (is_new) {
        int idx = config_add_instance(name);
        if (idx < 0) { msgbox(1, "新增实例", "实例数量已达上限（%d）", MAX_INST); return 0; }
        a = &APPS[idx];
    }

    char o_name[128] = "", o_srv[256] = "", o_acc[128] = "", o_login[32] = "", o_tok[420] = "";
    int ident_changed = 0, was_run = 0;
    if (!is_new) {
        snprintf(o_name, sizeof o_name, "%s", a->cfg.client_name);
        snprintf(o_srv, sizeof o_srv, "%s", a->cfg.server);
        snprintf(o_acc, sizeof o_acc, "%s", a->cfg.account);
        snprintf(o_login, sizeof o_login, "%s", a->cfg.login[0] ? a->cfg.login : "password");
        snprintf(o_tok, sizeof o_tok, "%s", a->cfg.token_file);
        was_run = a->want_run;
        ident_changed = strcmp(o_name, name) || strcmp(o_srv, srv) || strcmp(o_acc, acc) ||
                        strcmp(o_login, login[0] ? login : "password");
        if (ident_changed && was_run) {
            app_stop(a);
            app_wait_stopped(a);
            usleep(100 * 1000);
        }
    }

    snprintf(a->cfg.client_name, sizeof a->cfg.client_name, "%s", name);
    snprintf(a->cfg.server, sizeof a->cfg.server, "%s", srv);
    snprintf(a->cfg.account, sizeof a->cfg.account, "%s", acc);
    snprintf(a->cfg.password, sizeof a->cfg.password, "%s", pwd);
    snprintf(a->cfg.login, sizeof a->cfg.login, "%s", login[0] ? login : "password");
    a->cfg.autostart = autostart;

    char dir[360], tok[420];
    config_instance_dir(a, dir, sizeof dir);
    platform_mkdir(dir);
    platform_path_join(tok, sizeof tok, dir, "vs_tokens.json");
    snprintf(a->cfg.token_file, sizeof a->cfg.token_file, "%s", tok);
    config_instance_log(a, a->cfg.log_file, sizeof a->cfg.log_file);

    if (ident_changed && o_tok[0] && strcmp(o_tok, a->cfg.token_file) != 0) {
        if (access(o_tok, F_OK) == 0 && access(a->cfg.token_file, F_OK) != 0)
            if (platform_copy_file(o_tok, a->cfg.token_file) != 0)
                log_print("[配置] token 复制失败：%s → %s", o_tok, a->cfg.token_file);
    }

    if (is_new) {
        tm_init(&a->tm, a->cfg.token_file, a->cfg.client_name);
        tm_load(&a->tm);
    } else if (ident_changed) {
        devlogin_reset(a);
        tm_rebind(&a->tm, a->cfg.token_file, a->cfg.client_name);
        tm_load(&a->tm);
    }
    config_save();

    if (ident_changed && was_run) app_start(a);
    return 1;
}

/* ---------------- 列表 / 摘要 ---------------- */

static const char *state_text(app_state *a, char *buf, size_t n) {
    if (!a->want_run) {
        snprintf(buf, n, "已停止");
    } else if (!a->connected) {
        snprintf(buf, n, "连接中…");
    } else if (a->active > 0) {
        snprintf(buf, n, "取号中");
    } else {
        const char *st = tm_state_text(&a->tm);
        if (!strcmp(st, "ok")) snprintf(buf, n, "空闲");
        else if (!strcmp(st, "none")) snprintf(buf, n, "未登录");
        else if (!strcmp(st, "expired")) snprintf(buf, n, "token 过期");
        else snprintf(buf, n, "需要重登");
    }
    return buf;
}

static void refresh_list(void) {
    int selected = selected_idx();
    int rows = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(W_STORE), NULL);

    while (rows > NINST) {
        GtkTreeIter it;
        if (!gtk_tree_model_iter_nth_child(GTK_TREE_MODEL(W_STORE), &it, NULL, rows - 1)) break;
        gtk_list_store_remove(W_STORE, &it);
        rows--;
    }
    while (rows < NINST) {
        GtkTreeIter it;
        gtk_list_store_append(W_STORE, &it);
        gtk_list_store_set(W_STORE, &it, 0, APPS[rows].cfg.client_name, 1, "", 2, "", 3, "", 4, "", -1);
        rows++;
    }

    for (int i = 0; i < NINST; i++) {
        app_state *a = &APPS[i];
        char acc[160] = "";
        char st[64], left[64] = "";
        GtkTreeIter it;

        tm_account_hint(&a->tm, acc, sizeof acc);
        if (!acc[0]) snprintf(acc, sizeof acc, "%s", a->cfg.account[0] ? a->cfg.account : "-");

        state_text(a, st, sizeof st);

        const char *ts = tm_state_text(&a->tm);
        if (!a->want_run) snprintf(left, sizeof left, "—");
        else if (!strcmp(ts, "none")) snprintf(left, sizeof left, "未登录");
        else if (!strcmp(ts, "rejected")) snprintf(left, sizeof left, "已失效");
        else tm_left_h(&a->tm, left, sizeof left);
        if (!left[0]) snprintf(left, sizeof left, "—");

        if (!gtk_tree_model_iter_nth_child(GTK_TREE_MODEL(W_STORE), &it, NULL, i)) continue;
        gtk_list_store_set(W_STORE, &it,
                           0, a->cfg.client_name,
                           1, acc,
                           2, st,
                           3, a->connected ? "已连接" : "未连接",
                           4, left, -1);
    }

    if (selected >= 0 && selected < NINST) {
        GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(W_LIST));
        GtkTreePath *p = gtk_tree_path_new_from_indices(selected, -1);
        gtk_tree_selection_select_path(sel, p);
        gtk_tree_path_free(p);
    }
}

static void refresh_summary(void) {
    int online = 0, busy = 0;
    for (int i = 0; i < NINST; i++) {
        if (APPS[i].connected) online++;
        if (APPS[i].active > 0) busy++;
    }
    gtk_label_set_text(GTK_LABEL(W_SUMMARY),
        g_strdup_printf("实例 %d / 在线 %d / 取号中 %d", NINST, online, busy));
}

static void set_code_panel(int idx, const char *masked, const char *hint) {
    G_PENDING_IDX = idx;
    if (idx < 0) {
        gtk_label_set_text(GTK_LABEL(W_PROMPT), "当前没有等待人工验证的实例。");
        gtk_entry_set_text(GTK_ENTRY(W_CODE), "");
        gtk_widget_set_sensitive(W_CODE, FALSE);
        gtk_widget_set_sensitive(W_BTN_SUBMIT, FALSE);
        return;
    }
    char buf[760];
    snprintf(buf, sizeof buf,
             "实例 %s 等待人工验证（掩码 %s）：先填「收件邮箱」提交，收到验证码后再填 6 位验证码提交。 %s",
             APPS[idx].cfg.client_name, masked && masked[0] ? masked : "未知",
             hint && hint[0] ? hint : "");
    gtk_label_set_text(GTK_LABEL(W_PROMPT), buf);
    gtk_entry_set_text(GTK_ENTRY(W_CODE), "");
    gtk_widget_set_sensitive(W_CODE, TRUE);
    gtk_widget_set_sensitive(W_BTN_SUBMIT, TRUE);
    gtk_widget_grab_focus(W_CODE);
}

static int find_dev_instance(void) {
    for (int i = 0; i < NINST; i++) {
        int st = 0, left = -1;
        char code[64] = "";
        devlogin_info(&APPS[i], &st, code, sizeof code, NULL, 0, &left, NULL, 0);
        if (st == 1 && code[0]) return i;
    }
    return -1;
}

static void sync_dev_buttons(int dev_idx) {
    static int last_open = -1, last_acc = -1;
    int open = dev_idx >= 0 ? 1 : 0;
    int acc = NINST > 0 ? 1 : 0;
    if (open != last_open) {
        gtk_widget_set_sensitive(W_BTN_DEVOPEN, open);
        gtk_widget_set_sensitive(W_BTN_DEVCODE, open);
        last_open = open;
    }
    if (acc != last_acc) {
        gtk_widget_set_sensitive(W_BTN_DEVACC, acc);
        last_acc = acc;
    }
}

static void refresh_dev_panel(void) {
    static char last[760] = "\x01";
    char buf[760];
    int found = find_dev_instance();
    sync_dev_buttons(found);
    if (G_PENDING_IDX >= 0) return;
    int left = -1, st = 0;
    char code[64] = "", url[256] = "", msg[256] = "";
    if (found >= 0) {
        devlogin_info(&APPS[found], &st, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
        snprintf(buf, sizeof buf,
                 "实例 %s 设备码登录待完成 · 打开 %s 输入 %s（剩 %d 分 %d 秒）· 完成后自动更新",
                 APPS[found].cfg.client_name, url[0] ? url : "https://microsoft.com/devicelogin",
                 code, left > 0 ? left / 60 : 0, left > 0 ? left % 60 : 0);
    } else {
        snprintf(buf, sizeof buf, "当前没有等待人工验证的实例。");
    }
    if (strcmp(buf, last) == 0) return;
    snprintf(last, sizeof last, "%s", buf);
    gtk_label_set_text(GTK_LABEL(W_PROMPT), buf);
}

/* ---------------- 日志显示 ---------------- */

static void read_log_tail(char *out, size_t outn, long long *out_len) {
    char path[400];
    config_app_log(path, sizeof path);
    out[0] = 0;
    *out_len = -1;
    FILE *f = fopen(path, "rb");
    if (!f) { *out_len = 0; return; }
    fseeko(f, 0, SEEK_END);
    long long sz = (long long)ftello(f);
    *out_len = sz;
    long long want = 160 * 1024;
    long long start = sz > want ? sz - want : 0;
    fseeko(f, start, SEEK_SET);
    size_t rd = fread(out, 1, outn - 1, f);
    fclose(f);
    out[rd] = 0;
}

/* 贴底：直接操作滚动条 adjustment。set_text 之后文本高度要等下一次
   布局才生效，所以除立即调用外，还要靠 adjustment 的 changed 信号补一次。 */
static void log_scroll_bottom(void) {
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(W_LOGVIEW));
    if (!adj) return;
    double bottom = gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj);
    if (bottom > 0 && gtk_adjustment_get_value(adj) < bottom - 0.5)
        gtk_adjustment_set_value(adj, bottom);
}

static gboolean log_scroll_idle(gpointer p) {
    (void)p;
    log_scroll_bottom();
    return G_SOURCE_REMOVE;
}

/* 内容变高（upper 变化）时若仍处于追底状态，就跟着滚到底 */
static void on_log_adj_changed(GtkAdjustment *adj, gpointer p) {
    (void)adj; (void)p;
    if (!G_LOG_STICK) return;
    log_scroll_bottom();
}

/* 用户滚动：离开底部就取消追底，回到底部就恢复 */
static void on_log_adj_value(GtkAdjustment *adj, gpointer p) {
    (void)p;
    double bottom = gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj);
    G_LOG_STICK = (bottom <= 0 || gtk_adjustment_get_value(adj) >= bottom - 4);
}

static void refresh_log(void) {
    static char buf[168 * 1024];
    long long len = 0;
    GtkAdjustment *adj;
    double before, upper, page;
    gboolean at_bottom;

    read_log_tail(buf, sizeof buf, &len);
    if (len == G_LOG_LAST_LEN) return;

    adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(W_LOGVIEW));
    before = adj ? gtk_adjustment_get_value(adj) : 0;
    upper = adj ? gtk_adjustment_get_upper(adj) : 0;
    page = adj ? gtk_adjustment_get_page_size(adj) : 0;
    at_bottom = G_LOG_STICK || (adj && (before + page >= upper - 4)) || G_LOG_LAST_LEN < 0;

    G_LOG_LAST_LEN = len;
    gtk_text_buffer_set_text(W_LOGBUFF, buf, -1);
    if (at_bottom) {
        G_LOG_STICK = TRUE;
        log_scroll_bottom();
        g_idle_add(log_scroll_idle, NULL);
        g_timeout_add(50, log_scroll_idle, NULL);
    }
}

/* ---------------- 后台任务 ---------------- */

typedef struct {
    int idx;
    int rc;
    int need_code;
    int sent;
    char masked[256];
    char msg[600];
    char err[600];
    char input[512];
    char cid[256], pid[128], title[128];
    char iid[128];
    char rt[2048];
} job;

static gboolean on_login_done(gpointer p) {
    job *r = (job *)p;
    app_state *a = &APPS[r->idx];
    if (r->rc == 0) {
        set_code_panel(-1, NULL, NULL);
        msgbox(0, "登录成功", "实例 %s 登录成功，token 已保存。", a->cfg.client_name);
        app_send_status_report(a);
    } else if (r->rc == 1) {
        set_code_panel(r->idx, r->masked, r->msg);
    } else {
        msgbox(1, "登录失败", "实例 %s 登录失败：%s", a->cfg.client_name, r->err);
    }
    free(r);
    refresh_list();
    return G_SOURCE_REMOVE;
}

static void *login_thread(void *p) {
    job *r = (job *)p;
    app_state *a = &APPS[r->idx];
    r->rc = app_login_manual(a, a->cfg.account, a->cfg.password, &r->need_code,
                             r->masked, sizeof r->masked, r->msg, sizeof r->msg,
                             r->err, sizeof r->err);
    g_idle_add(on_login_done, r);
    return NULL;
}

static gboolean on_verify_done(gpointer p) {
    job *r = (job *)p;
    app_state *a = &APPS[r->idx];
    if (r->rc == 0) {
        if (r->sent) {
            msgbox(0, "验证码已发送", "已提交收件邮箱并发送验证码。收到 6 位验证码后填进输入框再提交。\n%s",
                   r->msg);
            gtk_entry_set_text(GTK_ENTRY(W_CODE), "");
            gtk_widget_grab_focus(W_CODE);
        } else {
            set_code_panel(-1, NULL, NULL);
            msgbox(0, "验证通过", "实例 %s 验证通过，token 已保存。", a->cfg.client_name);
            app_send_status_report(a);
        }
    } else {
        msgbox(1, "提交失败", "提交失败：%s", r->err);
    }
    free(r);
    refresh_list();
    return G_SOURCE_REMOVE;
}

static void *verify_thread(void *p) {
    job *r = (job *)p;
    app_state *a = &APPS[r->idx];
    r->rc = app_submit_code(a, r->input, &r->sent, r->msg, sizeof r->msg,
                            r->err, sizeof r->err);
    g_idle_add(on_verify_done, r);
    return NULL;
}

static gboolean on_test_done(gpointer p) {
    job *r = (job *)p;
    if (r->cid[0] && r->cid[0] >= '0' && r->cid[0] <= '9')
        msgbox(0, "取号成功", "CID：%s\nPID：%s\n产品：%s", r->cid, r->pid, r->title);
    else
        msgbox(1, "取号失败", "取号失败：%s", r->cid[0] ? r->cid : "无返回");
    free(r);
    return G_SOURCE_REMOVE;
}

static void *test_thread(void *p) {
    job *r = (job *)p;
    app_check_cid(&APPS[r->idx], r->iid, r->cid, sizeof r->cid, r->pid, sizeof r->pid,
                  r->title, sizeof r->title);
    g_idle_add(on_test_done, r);
    return NULL;
}

static gboolean on_dev_done(gpointer p) {
    job *j = (job *)p;
    app_state *a = &APPS[j->idx];
    int st = 0, left = -1;
    char code[64] = "", url[256] = "", msg[256] = "";
    devlogin_info(a, &st, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
    if (j->rc == 0 && st == 1 && code[0]) {
        set_status("设备码已获取，请在浏览器里输入");
        refresh_list();
    } else if (j->rc != 0) {
        msgbox(1, "设备码登录失败", "设备码登录失败：%s", msg[0] ? msg : "未知原因");
        set_status("就绪");
    }
    free(j);
    return G_SOURCE_REMOVE;
}

static void *dev_thread(void *p) {
    job *j = (job *)p;
    j->rc = devlogin_start(&APPS[j->idx]);
    g_idle_add(on_dev_done, j);
    return NULL;
}

static gboolean on_key_done(gpointer p) {
    job *j = (job *)p;
    app_state *a = &APPS[j->idx];
    int st = 0, left = -1;
    char code[64] = "", url[256] = "", msg[256] = "";
    devlogin_info(a, &st, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
    if (j->rc == 0) {
        msgbox(0, "密钥登录", "实例 %s 密钥登录成功，token 已保存。", a->cfg.client_name);
        set_status("就绪");
    } else {
        msgbox(1, "密钥登录失败", "密钥登录失败：%s", msg[0] ? msg : "未知原因");
        set_status("就绪");
    }
    free(j);
    refresh_list();
    return G_SOURCE_REMOVE;
}

static void *key_thread(void *p) {
    job *j = (job *)p;
    j->rc = devlogin_key(&APPS[j->idx], j->rt);
    g_idle_add(on_key_done, j);
    return NULL;
}

static void spawn(void *(*fn)(void *), void *arg) {
    pthread_t th;
    if (pthread_create(&th, NULL, fn, arg) != 0) {
        free(arg);
        msgbox(1, "启动线程失败", "无法创建后台线程");
        return;
    }
    pthread_detach(th);
}

/* ---------------- 命令 ---------------- */

static void do_start(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    if (APPS[idx].want_run) return;
    app_start(&APPS[idx]);
    refresh_list();
}

static void do_stop(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    app_stop(&APPS[idx]);
    refresh_list();
}

static void do_login(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    app_state *a = &APPS[idx];
    char acc[128], pwd[128];
    snprintf(acc, sizeof acc, "%s", a->cfg.account);
    snprintf(pwd, sizeof pwd, "%s", a->cfg.password);
    if (!acc[0]) {
        if (!input_dialog("登录微软账号", "请输入微软账号（邮箱）：", "", acc, sizeof acc)) return;
        snprintf(a->cfg.account, sizeof a->cfg.account, "%s", acc);
    }
    if (!pwd[0]) {
        if (!input_dialog("登录微软账号", "请输入密码：", "", pwd, sizeof pwd)) return;
        snprintf(a->cfg.password, sizeof a->cfg.password, "%s", pwd);
    }
    config_save();

    job *r = g_new0(job, 1);
    r->idx = idx;
    gtk_label_set_text(GTK_LABEL(W_PROMPT), "正在登录，请稍候（微软网页流程最长约 40 秒）…");
    spawn(login_thread, r);
}

static void do_submit(void) {
    if (G_PENDING_IDX < 0) { msgbox(0, "提示", "没有等待验证的实例"); return; }
    const char *txt = gtk_entry_get_text(GTK_ENTRY(W_CODE));
    if (!txt[0]) { msgbox(0, "提示", "请先填写收件邮箱或 6 位验证码"); return; }
    job *r = g_new0(job, 1);
    r->idx = G_PENDING_IDX;
    snprintf(r->input, sizeof r->input, "%s", txt);
    gtk_label_set_text(GTK_LABEL(W_PROMPT), "正在提交，请稍候…");
    spawn(verify_thread, r);
}

static void do_test(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    char iid[128] = "";
    if (!input_dialog("测试取号", "请输入安装 ID（IID，63 位或 54 位数字）：", "", iid, sizeof iid)) return;
    if (!iid[0]) return;
    job *r = g_new0(job, 1);
    r->idx = idx;
    snprintf(r->iid, sizeof r->iid, "%s", iid);
    spawn(test_thread, r);
}

static void do_delete(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    app_state *a = &APPS[idx];
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(W_WIN),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "确定删除实例「%s」？",
        a->cfg.client_name);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d),
        "只删配置条目，实例目录（token/日志）保留。");
    gint rc = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    if (rc != GTK_RESPONSE_YES) return;

    app_stop(a);
    app_wait_stopped(a);
    config_remove_instance(idx);
    config_save();
    gui_refresh();
}

static void do_devlogin(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    app_state *a = &APPS[idx];
    snprintf(a->cfg.login, sizeof a->cfg.login, "device");
    config_save();
    if (!a->want_run) app_start(a);
    job *j = g_new0(job, 1);
    j->idx = idx;
    spawn(dev_thread, j);
    set_status("正在向微软申请设备码…");
}

static void do_keylogin(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    char rt[2048] = "";
    if (!input_dialog("密钥登录", "粘贴该账号的 refresh_token（整串，会自动去掉空白）：",
                      "", rt, sizeof rt)) return;
    if (!rt[0]) return;
    job *j = g_new0(job, 1);
    j->idx = idx;
    snprintf(j->rt, sizeof j->rt, "%s", rt);
    spawn(key_thread, j);
    set_status("正在用 refresh_token 换 token…");
}

static void do_openlink(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    int st = 0, left = -1;
    char code[64] = "", url[256] = "", msg[256] = "";
    devlogin_info(&APPS[idx], &st, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
    if (!url[0]) snprintf(url, sizeof url, "https://microsoft.com/devicelogin");
    open_path(url);
    set_status("已打开设备码登录页，输入复制到的代码即可");
}

static void do_copycode(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    int st = 0, left = -1;
    char code[64] = "", url[256] = "", msg[256] = "";
    devlogin_info(&APPS[idx], &st, code, sizeof code, url, sizeof url, &left, msg, sizeof msg);
    if (!code[0]) { msgbox(0, "提示", "当前没有进行中的设备码登录：先点「设备码登录」"); return; }
    clipboard_set(code);
    set_status("设备码已复制，粘贴到浏览器输入框即可");
}

static void do_copyacc(int idx) {
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    char acc[128] = "";
    tm_account_hint(&APPS[idx].tm, acc, sizeof acc);
    if (!acc[0]) snprintf(acc, sizeof acc, "%s", APPS[idx].cfg.account);
    if (!acc[0]) {
        msgbox(0, "提示", "实例 %s 还没填账号：在「编辑」里把微软账号（完整邮箱）填上，"
                          "浏览器登录时要用到它", APPS[idx].cfg.client_name);
        return;
    }
    clipboard_set(acc);
    char b[320];
    snprintf(b, sizeof b, "账号已复制：%s", acc);
    set_status(b);
}

/* ---------------- 右键菜单 ---------------- */

static void menu_cb(GtkMenuItem *mi, gpointer data) {
    int cmd = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(mi), "cmd"));
    int idx = selected_idx();
    switch (cmd) {
    case 1: do_start(idx); break;
    case 2: do_stop(idx); break;
    case 3: do_login(idx); break;
    case 4: do_devlogin(idx); break;
    case 5: do_keylogin(idx); break;
    case 6: if (idx >= 0) do_openlink(idx); break;
    case 7: if (idx >= 0) do_copycode(idx); break;
    case 8: do_submit(); break;
    case 9: do_test(idx); break;
    case 10:
        if (idx >= 0 && instance_dialog(&APPS[idx], 0)) gui_refresh();
        break;
    case 11: if (idx >= 0) do_copyacc(idx); break;
    case 12: {
        if (idx < 0) break;
        char dir[360];
        config_instance_dir(&APPS[idx], dir, sizeof dir);
        open_path(dir);
        break;
    }
    case 13: {
        if (idx < 0) break;
        char p[400];
        config_instance_log(&APPS[idx], p, sizeof p);
        open_path(p);
        break;
    }
    case 14: do_delete(idx); break;
    default: break;
    }
    (void)data;
}

static void add_item(GtkWidget *menu, const char *text, int cmd, int need_sel, int has_sel) {
    if (!*text) {
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
        return;
    }
    GtkWidget *mi = gtk_menu_item_new_with_label(text);
    g_object_set_data(G_OBJECT(mi), "cmd", GINT_TO_POINTER(cmd));
    g_signal_connect(mi, "activate", G_CALLBACK(menu_cb), NULL);
    if (need_sel && !has_sel) gtk_widget_set_sensitive(mi, FALSE);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
}

static gboolean on_list_button(GtkWidget *w, GdkEventButton *ev, gpointer data) {
    (void)w; (void)data;
    if (ev->type != GDK_BUTTON_PRESS || ev->button != 3) return FALSE;
    GtkTreePath *p = NULL;
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(W_LIST), (int)ev->x, (int)ev->y, &p, NULL, NULL, NULL)) {
        gtk_tree_view_set_cursor(GTK_TREE_VIEW(W_LIST), p, NULL, FALSE);
        gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(W_LIST)), p);
        gtk_tree_path_free(p);
    }
    int idx = selected_idx();
    int has = idx >= 0;
    GtkWidget *menu = gtk_menu_new();
    add_item(menu, "启动", 1, 1, has);
    add_item(menu, "停止", 2, 1, has);
    add_item(menu, "", 0, 0, has);
    add_item(menu, "密码登录 / 重新登录（账号密码 + 邮箱验证码）", 3, 1, has);
    add_item(menu, "设备码登录（免密码，可用 2FA 账号）", 4, 1, has);
    add_item(menu, "打开设备码链接", 6, 1, has);
    add_item(menu, "复制设备码", 7, 1, has);
    add_item(menu, "密钥登录（粘贴已有 refresh_token，跳过邮箱验证码）", 5, 1, has);
    add_item(menu, "提交验证码", 8, 0, has);
    add_item(menu, "测试取号", 9, 1, has);
    add_item(menu, "", 0, 0, has);
    add_item(menu, "编辑", 10, 1, has);
    add_item(menu, "复制账号", 11, 1, has);
    add_item(menu, "打开实例目录", 12, 1, has);
    add_item(menu, "打开实例日志", 13, 1, has);
    add_item(menu, "", 0, 0, has);
    add_item(menu, "删除", 14, 1, has);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent *)ev);
    return TRUE;
}

/* ---------------- 按钮回调 ---------------- */

static void on_btn_new(GtkButton *b, gpointer d) { (void)b; (void)d; if (instance_dialog(NULL, 1)) gui_refresh(); }

static void on_btn_edit(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    int idx = selected_idx();
    if (idx < 0) { msgbox(0, "提示", "请先在列表里选择一个实例"); return; }
    if (instance_dialog(&APPS[idx], 0)) gui_refresh();
}

static void on_btn_del(GtkButton *b, gpointer d) { (void)b; (void)d; do_delete(selected_idx()); }
static void on_btn_start(GtkButton *b, gpointer d) { (void)b; (void)d; do_start(selected_idx()); }
static void on_btn_stop(GtkButton *b, gpointer d) { (void)b; (void)d; do_stop(selected_idx()); }

static void on_btn_startall(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    for (int i = 0; i < NINST; i++) if (!APPS[i].want_run) app_start(&APPS[i]);
    refresh_list();
}

static void on_btn_stopall(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    for (int i = 0; i < NINST; i++) app_stop(&APPS[i]);
    refresh_list();
}

static void on_btn_login(GtkButton *b, gpointer d) { (void)b; (void)d; do_login(selected_idx()); }
static void on_btn_submit(GtkButton *b, gpointer d) { (void)b; (void)d; do_submit(); }
static void on_btn_test(GtkButton *b, gpointer d) { (void)b; (void)d; do_test(selected_idx()); }

static void on_btn_devopen(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    int dev = find_dev_instance();
    do_openlink(dev >= 0 ? dev : selected_idx());
}

static void on_btn_devcode(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    int dev = find_dev_instance();
    do_copycode(dev >= 0 ? dev : selected_idx());
}

static void on_btn_devacc(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    int dev = find_dev_instance();
    do_copyacc(dev >= 0 ? dev : selected_idx());
}

static void on_btn_clearlog(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    char p[400];
    config_app_log(p, sizeof p);
    remove(p);
    gtk_text_buffer_set_text(W_LOGBUFF, "", -1);
    G_LOG_LAST_LEN = -1;
}

static void on_btn_copylog(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(W_LOGBUFF, &s, &e);
    char *txt = gtk_text_buffer_get_text(W_LOGBUFF, &s, &e, FALSE);
    clipboard_set(txt ? txt : "");
    g_free(txt);
}

static gboolean on_row_double(GtkWidget *w, GdkEventButton *ev, gpointer d) {
    (void)w; (void)d;
    if (ev->button != 1 || ev->type != GDK_2BUTTON_PRESS) return FALSE;
    int idx = selected_idx();
    if (idx >= 0 && instance_dialog(&APPS[idx], 0)) gui_refresh();
    return TRUE;
}

/* ---------------- 每秒刷新 ---------------- */

static gboolean on_tick(gpointer d) {
    (void)d;
    refresh_list();
    refresh_dev_panel();
    refresh_summary();
    refresh_log();
    return G_SOURCE_CONTINUE;
}

static gboolean on_delete(GtkWidget *w, GdkEvent *ev, gpointer d) {
    (void)w; (void)ev; (void)d;
    worker_stop_all();
    gtk_main_quit();
    return FALSE;
}

/* ---------------- 样式与构建 ---------------- */

static void apply_css(void) {
    const char *css =
        "* { font-family: 'Noto Sans CJK SC','Noto Sans SC','Source Han Sans SC',sans-serif; font-size: 12px; }"
        "button { padding: 0 2px; min-height: 0; min-width: 0; border-radius: 3px; }"
        "entry { min-height: 0; min-width: 0; padding: 1px 4px; border-radius: 3px; }"
        "entry text { min-height: 0; }"
        "combobox, combobox button { min-height: 0; padding: 1px 4px; }"
        "checkbutton { min-height: 0; padding: 0; }"
        "checkbutton indicator { min-height: 14px; min-width: 14px; }"
        ".bold { font-weight: 700; }"
        ".mono { font-family: 'JetBrains Mono','DejaVu Sans Mono','Noto Sans Mono CJK SC',monospace; font-size: 12px; }"
        "treeview { -GtkTreeView-vertical-separator: 0; }"
        "treeview header button { padding: 0 2px; min-height: 0; min-width: 0; }"
        "scrollbar { min-width: 10px; min-height: 10px; }";
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static GtkWidget *btn(GtkWidget *fixed, const char *text, int x, int y, int w, int h,
                      GCallback cb) {
    GtkWidget *b = gtk_button_new_with_label(text);
    g_signal_connect(b, "clicked", cb, NULL);
    gtk_widget_set_size_request(b, w, h);
    gtk_fixed_put(GTK_FIXED(fixed), b, x, y);
    return b;
}

/* 启动时把窗口摆到显示器工作区正中（xfce/xfwm 下 WM 默认会放到左上角） */
static gboolean center_window_idle(gpointer p) {
    (void)p;
    GdkDisplay *disp = gtk_widget_get_display(W_WIN);
    if (!disp) return G_SOURCE_REMOVE;
    GdkWindow *gw = gtk_widget_get_window(W_WIN);
    GdkMonitor *mon = gw ? gdk_display_get_monitor_at_window(disp, gw)
                         : gdk_display_get_primary_monitor(disp);
    if (!mon) mon = gdk_display_get_monitor(disp, 0);
    if (!mon) return G_SOURCE_REMOVE;

    GdkRectangle work;
    gdk_monitor_get_workarea(mon, &work);
    if (work.width <= 1 || work.height <= 1)
        gdk_monitor_get_geometry(mon, &work);

    GtkAllocation al;
    gtk_widget_get_allocation(W_WIN, &al);
    int w = al.width > 1 ? al.width : CLIENT_W;
    int h = al.height > 1 ? al.height : CLIENT_H;
    int x = work.x + (work.width - w) / 2;
    int y = work.y + (work.height - h) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    gtk_window_move(GTK_WINDOW(W_WIN), x, y);
    return G_SOURCE_REMOVE;
}

static void build_window(void) {
    W_WIN = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(W_WIN), "GetCID-C · 多实例客户端管理器");
    gtk_window_set_resizable(GTK_WINDOW(W_WIN), FALSE);
    gtk_window_set_position(GTK_WINDOW(W_WIN), GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(W_WIN), CLIENT_W, CLIENT_H);
    g_signal_connect(W_WIN, "delete-event", G_CALLBACK(on_delete), NULL);

    W_FIXED = gtk_fixed_new();
    gtk_widget_set_size_request(W_FIXED, CLIENT_W, CLIENT_H);
    gtk_container_add(GTK_CONTAINER(W_WIN), W_FIXED);

    GtkWidget *title = gtk_label_new("GetCID-C · 多实例客户端管理器");
    gtk_widget_set_size_request(title, 380, 20);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_widget_set_name(title, "title");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "bold");
    gtk_fixed_put(GTK_FIXED(W_FIXED), title, 12, 8);

    W_SUMMARY = gtk_label_new("");
    gtk_widget_set_size_request(W_SUMMARY, 332, 20);
    gtk_label_set_xalign(GTK_LABEL(W_SUMMARY), 1.0f);
    gtk_fixed_put(GTK_FIXED(W_FIXED), W_SUMMARY, 396, 10);

    struct { const char *t; int x; GCallback cb; } btns[] = {
        { "新增实例", 12, G_CALLBACK(on_btn_new) },
        { "编辑", 87, G_CALLBACK(on_btn_edit) },
        { "删除", 162, G_CALLBACK(on_btn_del) },
        { "启动", 237, G_CALLBACK(on_btn_start) },
        { "停止", 312, G_CALLBACK(on_btn_stop) },
        { "全部启动", 387, G_CALLBACK(on_btn_startall) },
        { "全部停止", 462, G_CALLBACK(on_btn_stopall) },
        { "登录", 537, G_CALLBACK(on_btn_login) },
        { "测试取号", 612, G_CALLBACK(on_btn_test) },
    };
    for (int i = 0; i < (int)(sizeof btns / sizeof btns[0]); i++)
        btn(W_FIXED, btns[i].t, btns[i].x, 34, 70, 24, btns[i].cb);

    /* 列表：5 列 140/190/80/85/190 */
    W_STORE = gtk_list_store_new(5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                 G_TYPE_STRING, G_TYPE_STRING);
    W_LIST = gtk_tree_view_new_with_model(GTK_TREE_MODEL(W_STORE));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(W_LIST), TRUE);
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(W_LIST), GTK_TREE_VIEW_GRID_LINES_BOTH);
    const char *cols[5] = { "实例", "账号", "状态", "连接", "token 剩余" };
    int widths[5] = { 140, 190, 80, 85, 190 };
    for (int i = 0; i < 5; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(cols[i], r, "text", i, NULL);
        gtk_tree_view_column_set_sizing(c, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(c, widths[i]);
        gtk_tree_view_column_set_resizable(c, FALSE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(W_LIST), c);
    }
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(W_LIST));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    gtk_widget_set_size_request(W_LIST, 716, 118);
    g_signal_connect(W_LIST, "button-press-event", G_CALLBACK(on_list_button), NULL);
    g_signal_connect(W_LIST, "button-press-event", G_CALLBACK(on_row_double), NULL);
    GtkWidget *sc1 = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sc1),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(sc1, 716, 118);
    gtk_container_add(GTK_CONTAINER(sc1), W_LIST);
    gtk_fixed_put(GTK_FIXED(W_FIXED), sc1, 12, 64);

    /* 验证提示条（两行，40 px） */
    W_PROMPT = gtk_label_new("当前没有等待人工验证的实例。");
    gtk_label_set_line_wrap(GTK_LABEL(W_PROMPT), TRUE);
    gtk_label_set_xalign(GTK_LABEL(W_PROMPT), 0.0f);
    gtk_label_set_yalign(GTK_LABEL(W_PROMPT), 0.0f);
    gtk_widget_set_size_request(W_PROMPT, 712, 40);
    gtk_fixed_put(GTK_FIXED(W_FIXED), W_PROMPT, 14, 188);

    W_CODE = gtk_entry_new();
    gtk_widget_set_size_request(W_CODE, 240, 24);
    gtk_fixed_put(GTK_FIXED(W_FIXED), W_CODE, 14, 234);
    W_BTN_SUBMIT = btn(W_FIXED, "提交验证码 / 收件邮箱", 262, 234, 150, 24,
                       G_CALLBACK(on_btn_submit));
    W_BTN_DEVOPEN = btn(W_FIXED, "打开设备码链接", 420, 234, 100, 24,
                        G_CALLBACK(on_btn_devopen));
    W_BTN_DEVCODE = btn(W_FIXED, "复制设备码", 528, 234, 90, 24,
                        G_CALLBACK(on_btn_devcode));
    W_BTN_DEVACC = btn(W_FIXED, "复制账号", 626, 234, 80, 24,
                       G_CALLBACK(on_btn_devacc));
    gtk_widget_set_sensitive(W_CODE, FALSE);
    gtk_widget_set_sensitive(W_BTN_SUBMIT, FALSE);
    gtk_widget_set_sensitive(W_BTN_DEVOPEN, FALSE);
    gtk_widget_set_sensitive(W_BTN_DEVCODE, FALSE);

    GtkWidget *lt = gtk_label_new("运行日志（全部实例）");
    gtk_widget_set_size_request(lt, 200, 18);
    gtk_label_set_xalign(GTK_LABEL(lt), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(lt), "bold");
    gtk_fixed_put(GTK_FIXED(W_FIXED), lt, 14, 264);
    btn(W_FIXED, "清空日志", 596, 262, 60, 22, G_CALLBACK(on_btn_clearlog));
    btn(W_FIXED, "复制日志", 664, 262, 64, 22, G_CALLBACK(on_btn_copylog));

    W_LOGTEXT = gtk_text_view_new();
    W_LOGBUFF = gtk_text_view_get_buffer(GTK_TEXT_VIEW(W_LOGTEXT));
    gtk_text_view_set_editable(GTK_TEXT_VIEW(W_LOGTEXT), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(W_LOGTEXT), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(W_LOGTEXT), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(W_LOGTEXT), 4);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(W_LOGTEXT), 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(W_LOGTEXT), "mono");
    W_LOGVIEW = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(W_LOGVIEW),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(W_LOGVIEW, 716, 136);
    gtk_container_add(GTK_CONTAINER(W_LOGVIEW), W_LOGTEXT);
    gtk_fixed_put(GTK_FIXED(W_FIXED), W_LOGVIEW, 12, 286);
    {
        GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(W_LOGVIEW));
        g_signal_connect(adj, "changed", G_CALLBACK(on_log_adj_changed), NULL);
        g_signal_connect(adj, "value-changed", G_CALLBACK(on_log_adj_value), NULL);
    }

    W_STATUS = gtk_label_new("就绪");
    gtk_widget_set_size_request(W_STATUS, 712, 18);
    gtk_label_set_xalign(GTK_LABEL(W_STATUS), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(W_STATUS), PANGO_ELLIPSIZE_END);
    gtk_fixed_put(GTK_FIXED(W_FIXED), W_STATUS, 14, 428);
}

int gui_main(int argc, char **argv) {
    char logp[400];
    gtk_init(&argc, &argv);
    apply_css();

    config_app_log(logp, sizeof logp);
    log_init(logp);

    if (config_load() != 0) {
        config_add_instance(NULL);
        config_save();
    }
    log_print("[启动] GetCID-C 初始化完成，实例 %d 个，配置 %s", NINST, G_CFG_PATH);

    build_window();
    gtk_widget_show_all(W_WIN);
    gui_refresh();
    /* WM 有时会自己决定初始位置，等布局完成后补一次居中 */
    g_idle_add(center_window_idle, NULL);
    g_timeout_add(350, center_window_idle, NULL);

    ms_start_relogin(APPS, NINST, G_CFG_PATH);
    for (int i = 0; i < NINST; i++) {
        if (APPS[i].cfg.autostart) app_start(&APPS[i]);
    }
    g_timeout_add(1000, on_tick, NULL);
    gtk_main();

    worker_stop_all();
    for (int i = 0; i < NINST; i++) app_wait_stopped(&APPS[i]);
    log_print("[退出] GetCID-C 已退出");
    return 0;
}

void gui_refresh(void) {
    refresh_list();
    refresh_summary();
    refresh_log();
}
