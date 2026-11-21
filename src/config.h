/* config.h - config.json 读写 + 实例目录 */
#ifndef CONFIG_H
#define CONFIG_H
#include "app.h"

#define DEF_SERVER "ws://getcid.live:8082"

void config_init_paths(void);                  /* 初始化 G_CFG_DIR / G_DATA_DIR / G_CFG_PATH */
int  config_load(void);                        /* 读 config.json → APPS/NINST */
int  config_save(void);                        /* APPS → config.json */
int  config_add_instance(const char *name);    /* 追加实例（返回下标，-1 失败） */
void config_remove_instance(int idx);
void config_instance_dir(const app_state *a, char *out, size_t n);
void config_instance_log(const app_state *a, char *out, size_t n);   /* 今日实例日志路径 */
void config_app_log(char *out, size_t n);
int  config_find_by_name(const char *name);
void config_open_console(void);                /* 分配控制台，便于诊断（默认不调用） */
#endif
