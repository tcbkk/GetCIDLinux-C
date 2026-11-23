/* app.h - 应用状态与线程接口（Windows GUI 版） */
#ifndef APP_H
#define APP_H
#include "common.h"
#include "ws.h"
#include "msft.h"

#define MAX_INST 8

typedef struct {
    char client_id[128];
    char type[32];
    char text[8192];
    char iid[128];
    char cid[128];
    char from[128];
    char to[64];
    char result[64];
    int  lang;
    int  user_type;
    int  show_price;              /* 派单请求里的 showPrice，回包必须原样回显（0=用户关了价格显示） */
    char from_id[128];
    char group_id[128];
    char conversation_id[128];
    int  is_topic;
    long long topic_id;
    char call_status[8];
    char get_status[8];
} client_message;

typedef struct {
    app_config cfg;
    int idx;
    long long started_ms;
    volatile int connected;
    volatile int task_count;
    volatile int active;
    volatile int token_broke;
    volatile int paused;          /* 单实例停止：保持连接但上报 busy=true、不接单 */
    volatile int want_run;        /* 该实例是否应该保持连接（GUI 启动/停止） */
    volatile int last_cid_ok;     /* 上一次取号成功（列表用） */
    char last_cid[64];
    char last_pid[64];
    char last_product[128];
    char last_line[256];          /* 列表「最近状态」列 */
    char last_status[8];

    /* 任务队列 */
    client_message queue[8];
    int q_head, q_tail, q_len;
    pthread_mutex_t q_mu;
    pthread_cond_t q_cv;

    ws_conn ws;
    char client_id[128];

    token_manager tm;

    /* 线程句柄（GUI 启停用） */
    pthread_t run_th, rd_th, work_th;
    int running;
    int token_loop_started;

    /* cidtoken 远程令牌 */
    pthread_mutex_t rt_mu;
    pthread_cond_t rt_cv;
    int rt_pending;
    char rt_text[16384];
    char rt_id_token[4096];
    char rt_user_id[128];
    char rt_expires_at[64];
    long long rt_backoff_until;
    int rt_valid;

    /* 设备码登录状态（每实例一份，GUI 用它显示 code/链接） */
    pthread_mutex_t dev_mu;
    int  dev_status;        /* 0=idle 1=waiting 2=success 3=error */
    char dev_code[32];
    char dev_url[256];
    char dev_msg[256];
    long dev_deadline;      /* 设备码过期时间（unix 秒） */
    int  dev_polling;
} app_state;

/* 全局 */
extern app_state APPS[MAX_INST];
extern int NINST;
extern volatile int g_stop;
extern char G_CFG_PATH[320];

/* worker.c */
void app_set_status(app_state *a, int busy);
int  app_send_status_report(app_state *a);
int  app_remote_healthy(app_state *a);
void app_start(app_state *a);       /* 启动该实例的连接线程（幂等） */
void app_stop(app_state *a);        /* 请求停止（幂等） */
int  app_running(app_state *a);
void app_wait_stopped(app_state *a);
void worker_stop_all(void);

/* 用户操作 */
int  app_login_manual(app_state *a, const char *account, const char *password,
                      int *need_code, char *masked, size_t mn,
                      char *msg, size_t msgn, char *err, size_t en);
int  app_submit_code(app_state *a, const char *input, int *sent, char *msg, size_t msgn,
                     char *err, size_t en);
int  app_has_pending(app_state *a);
void app_check_cid(app_state *a, const char *iid, char *cid, size_t cn,
                   char *pid, size_t pn, char *title, size_t tn);
#endif
