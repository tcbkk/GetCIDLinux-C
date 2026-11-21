/* config.c - config.json 读写 + 实例目录管理
   布局（与 Rust 版一致，全部放在 exe 同目录）：
     config.json
     instances\<client_name>\vs_tokens.json
     instances\<client_name>\logs\yyyymmdd.log
     logs\app.log */
#include "config.h"
#include "msft.h"

app_state APPS[MAX_INST];
int NINST = 0;
volatile int g_stop = 0;
char G_CFG_PATH[320] = "config.json";
char G_CFG_DIR[320] = ".";
char G_DATA_DIR[320] = ".";

static char G_SERVER[256] = DEF_SERVER;

void config_init_paths(void) {
    const char *exe = platform_exe_dir();
    snprintf(G_DATA_DIR, sizeof G_DATA_DIR, "%s", exe);
    snprintf(G_CFG_DIR, sizeof G_CFG_DIR, "%s", exe);
    snprintf(G_CFG_PATH, sizeof G_CFG_PATH, "%s/config.json", exe);
    platform_mkdir(G_DATA_DIR);
    char dir[400];
    platform_path_join(dir, sizeof dir, G_DATA_DIR, "logs");
    platform_mkdir(dir);
    platform_path_join(dir, sizeof dir, G_DATA_DIR, "instances");
    platform_mkdir(dir);
}

void config_instance_dir(const app_state *a, char *out, size_t n) {
    char inst[360];
    platform_path_join(inst, sizeof inst, G_DATA_DIR, "instances");
    platform_path_join(out, n, inst, a->cfg.client_name);
}

void config_instance_log(const app_state *a, char *out, size_t n) {
    char dir[360], sub[400];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &t);
    char ymd[32];
    strftime(ymd, sizeof ymd, "%Y%m%d", &tmv);
    config_instance_dir(a, dir, sizeof dir);
    platform_path_join(sub, sizeof sub, dir, "logs");
    platform_mkdir(dir);
    platform_mkdir(sub);
    char nm[64];
    snprintf(nm, sizeof nm, "%s.log", ymd);
    platform_path_join(out, n, sub, nm);
}

void config_app_log(char *out, size_t n) {
    char dir[360];
    platform_path_join(dir, sizeof dir, G_DATA_DIR, "logs");
    platform_path_join(out, n, dir, "app.log");
}

int config_find_by_name(const char *name) {
    for (int i = 0; i < NINST; i++)
        if (strcmp(APPS[i].cfg.client_name, name) == 0) return i;
    return -1;
}

static void default_name(char *out, size_t n) {
    for (int k = 1; k <= 99; k++) {
        snprintf(out, n, "serverclient%02d", k);
        if (config_find_by_name(out) < 0) return;
    }
}

int config_add_instance(const char *name) {
    if (NINST >= MAX_INST) return -1;
    app_state *a = &APPS[NINST];
    memset(a, 0, sizeof *a);
    a->idx = NINST;
    if (name && *name) snprintf(a->cfg.client_name, sizeof a->cfg.client_name, "%s", name);
    else default_name(a->cfg.client_name, sizeof a->cfg.client_name);
    snprintf(a->cfg.server, sizeof a->cfg.server, "%s", G_SERVER);
    snprintf(a->cfg.mode, sizeof a->cfg.mode, "account");
    snprintf(a->cfg.login, sizeof a->cfg.login, "password");
    a->cfg.lang = 1;
    a->cfg.autostart = 1;
    char dir[360];
    config_instance_dir(a, dir, sizeof dir);
    platform_mkdir(dir);
    char tok[400];
    platform_path_join(tok, sizeof tok, dir, "vs_tokens.json");
    snprintf(a->cfg.token_file, sizeof a->cfg.token_file, "%s", tok);
    config_instance_log(a, a->cfg.log_file, sizeof a->cfg.log_file);
    NINST++;
    return NINST - 1;
}

void config_remove_instance(int idx) {
    if (idx < 0 || idx >= NINST) return;
    for (int i = idx; i + 1 < NINST; i++) APPS[i] = APPS[i + 1];
    NINST--;
    for (int i = 0; i < NINST; i++) APPS[i].idx = i;
}

static void fix_paths(app_state *a) {
    char dir[360];
    config_instance_dir(a, dir, sizeof dir);
    platform_mkdir(dir);
    if (!a->cfg.token_file[0]) {
        char tok[400];
        platform_path_join(tok, sizeof tok, dir, "vs_tokens.json");
        snprintf(a->cfg.token_file, sizeof a->cfg.token_file, "%s", tok);
    }
    config_instance_log(a, a->cfg.log_file, sizeof a->cfg.log_file);
}

int config_load(void) {
    NINST = 0;
    FILE *f = fopen(G_CFG_PATH, "r");
    if (!f) return -1;
    static char data[32768];
    size_t dn = fread(data, 1, sizeof data - 1, f);
    fclose(f);
    data[dn] = 0;

    parse_json_str(data, "server", G_SERVER, sizeof G_SERVER);
    if (!G_SERVER[0]) snprintf(G_SERVER, sizeof G_SERVER, "%s", DEF_SERVER);

    static char objs[MAX_INST][4096];
    int nobj = json_extract_objects(data, "instances", &objs[0][0], 4096, MAX_INST);
    for (int i = 0; i < nobj; i++) {
        app_state *a = &APPS[i];
        memset(a, 0, sizeof *a);
        a->idx = i;
        parse_json_str(objs[i], "client_name", a->cfg.client_name, sizeof a->cfg.client_name);
        parse_json_str(objs[i], "server", a->cfg.server, sizeof a->cfg.server);
        parse_json_str(objs[i], "account", a->cfg.account, sizeof a->cfg.account);
        parse_json_str(objs[i], "password", a->cfg.password, sizeof a->cfg.password);
        parse_json_str(objs[i], "mode", a->cfg.mode, sizeof a->cfg.mode);
        parse_json_str(objs[i], "login", a->cfg.login, sizeof a->cfg.login);
        a->cfg.lang = parse_json_int(objs[i], "lang", 1);
        a->cfg.autostart = parse_json_int(objs[i], "autostart", 1);
        if (!a->cfg.client_name[0]) default_name(a->cfg.client_name, sizeof a->cfg.client_name);
        if (!a->cfg.server[0]) snprintf(a->cfg.server, sizeof a->cfg.server, "%s", G_SERVER);
        if (!a->cfg.mode[0]) snprintf(a->cfg.mode, sizeof a->cfg.mode, "account");
        /* 老配置没有 login 字段：有账号密码就按网页流程，否则按设备码 */
        if (!a->cfg.login[0])
            snprintf(a->cfg.login, sizeof a->cfg.login,
                     (a->cfg.account[0] && a->cfg.password[0]) ? "password" : "device");
        fix_paths(a);
        /* 启动时就把 token 装进管理器：不然 panel 里账号/token 状态是空的，
           第一次连接会误报「refresh_token 为空」 */
        tm_init(&a->tm, a->cfg.token_file, a->cfg.client_name);
        int tokrc = tm_load(&a->tm);
        log_print("[配置] %s token 加载=%s（%d 字符）", a->cfg.client_name,
                  tokrc ? "无/失效" : "成功", (int)strlen(a->tm.tok.refresh_token));
        NINST++;
    }
    return 0;
}

int config_save(void) {
    char tmp[400];
    snprintf(tmp, sizeof tmp, "%s.tmp", G_CFG_PATH);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, "{\n  \"server\": \"%s\",\n  \"instances\": [\n", G_SERVER);
    for (int i = 0; i < NINST; i++) {
        app_state *a = &APPS[i];
        char e_name[300], e_acc[300], e_pwd[400], e_srv[600], e_login[40];
        json_escape(a->cfg.client_name, e_name, sizeof e_name);
        json_escape(a->cfg.account, e_acc, sizeof e_acc);
        json_escape(a->cfg.password, e_pwd, sizeof e_pwd);
        json_escape(a->cfg.server, e_srv, sizeof e_srv);
        json_escape(a->cfg.login[0] ? a->cfg.login : "password", e_login, sizeof e_login);
        fprintf(f,
            "    {\"client_name\":\"%s\",\"server\":\"%s\",\"account\":\"%s\","
            "\"password\":\"%s\",\"mode\":\"%s\",\"login\":\"%s\",\"lang\":%d,\"autostart\":%d}%s\n",
            e_name, e_srv, e_acc, e_pwd, a->cfg.mode, e_login, a->cfg.lang, a->cfg.autostart,
            (i + 1 < NINST) ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    if (fclose(f) != 0) { remove(tmp); return -1; }
    remove(G_CFG_PATH);
    if (rename(tmp, G_CFG_PATH) != 0) { remove(tmp); return -1; }
    return 0;
}

void config_open_console(void) {
#ifdef _DEBUG
    if (!AllocConsole()) return;
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
#endif
}
