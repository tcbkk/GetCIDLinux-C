/* prompt_file.h - 文件通道的人工验证提示器（Linux 无头版）
   与 C# 版 FileVerificationPrompt 的文件格式保持一致，网页控制台可以直接应答：
     prompt/request.txt   ID= / TYPE= / TITLE= / MESSAGE= / OPTIONn= / TIMEOUT=
     prompt/answer.txt    ID= / VALUE=（也允许只写裸答案） */
#ifndef PROMPT_FILE_H
#define PROMPT_FILE_H
#include "common.h"

#define PROMPT_DIR "prompt"

/* 返回 malloc 的答案（调用方 free）；超时/失败返回 NULL */
char *prompt_ask(const char *dir, const char *title, const char *message, int timeout_s);

/* 设备码：写 request.txt（TYPE=device, URL=/CODE=），不等待应答 */
int  prompt_device_code(const char *dir, const char *url, const char *code, int expires_s);
void prompt_device_clear(const char *dir);

/* 切换登录方式后清理上一模式残留的设备码提示：
   request.txt 里 TYPE=device 才删（含 answer.txt），返回 1 表示清掉了 */
int  prompt_clear_stale_device(const char *dir);

#endif
