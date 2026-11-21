/* ws.h - RFC6455 websocket 客户端（仅 ws:// 明文，Winsock 实现） */
#ifndef WS_H
#define WS_H
#include "common.h"

typedef struct {
    int sock;
    int connected;
    pthread_mutex_t mu;      /* 保护写帧 */
    /* 帧重组缓冲：多实例各有读线程，不能共享 static */
    unsigned char rxfrag[262144];
} ws_conn;

int ws_connect(ws_conn *w, const char *url);   /* ws://host:port[/path] */
int ws_send_text(ws_conn *w, const char *data, size_t n);
int ws_send_ping(ws_conn *w);
/* 返回: >0 文本长度（buf 内，NUL 结尾）；0 超时；-1 错误/关闭 */
int ws_read_text(ws_conn *w, char *buf, size_t bufsz, int timeout_s);
void ws_close(ws_conn *w);

#endif
