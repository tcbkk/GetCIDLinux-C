/* ws.c - 极简 RFC6455 客户端实现（仅 ws://，客户端帧一律带掩码）
   Linux 版：BSD socket；帧解析逻辑与 router-c 的 Linux 版一致。 */
#include "ws.h"
#include "b64.h"

#define INVALID_SOCKET (-1)
#define SD_BOTH        SHUT_RDWR
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)
#define WSAGetLastError() errno
#define WSAEINTR       EINTR
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAETIMEDOUT   EAGAIN

static int set_nonblock(SOCKET s, int on) {
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -1;
    fl = on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, fl);
}

static int tcp_connect(const char *host, const char *port, int timeout_s) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return -1;

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        /* 非阻塞连接 + select 超时 */
        set_nonblock(s, 1);
        int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK &&
            WSAGetLastError() != EINPROGRESS) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }
        if (rc == SOCKET_ERROR) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            struct timeval tv = { timeout_s, 0 };
            if (select(s + 1, NULL, &wset, NULL, &tv) <= 0) { closesocket(s); s = INVALID_SOCKET; continue; }
            int err = 0;
            socklen_t len = sizeof err;
            getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) { closesocket(s); s = INVALID_SOCKET; continue; }
        }
        set_nonblock(s, 0);
        break;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) return -1;

    {
        struct timeval tv;
        tv.tv_sec = timeout_s;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    /* TCP keepalive：WS 心跳只能发现"对端主动断"，NAT/防火墙静默丢表时
       要靠内核探测包才能及时判定死连接（30s 空闲 + 10s 间隔 + 3 次探测）。 */
    {
        int ka = 1;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof ka);
#ifdef TCP_KEEPIDLE
        {
            int idle = 30, intvl = 10, cnt = 3;
            setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof idle);
            setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
            setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof cnt);
        }
#endif
    }
    return (int)s;
}

static void mask_key(unsigned char *k) {
    static unsigned counter = 0;
    unsigned v = (unsigned)time(NULL) ^ (unsigned)clock() ^ (++counter << 16) ^ (unsigned)(intptr_t)&k;
    for (int i = 0; i < 4; i++) k[i] = (unsigned char)((v >> (i * 7)) & 0xFF);
}

static int ws_last_err = 0;

static int send_all(SOCKET s, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        int r = send(s, p, (int)n, 0);
        if (r == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            ws_last_err = e;
            return -1;
        }
        if (r == 0) { ws_last_err = -1; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int recv_some(SOCKET s, void *buf, size_t n) {
    for (;;) {
        int r = recv(s, (char *)buf, (int)n, 0);
        if (r > 0) { ws_last_err = 0; return r; }
        if (r == 0) { ws_last_err = 0; return 0; }
        int e = WSAGetLastError();
        if (e == WSAEINTR) continue;
        if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) { ws_last_err = e; return -2; } /* 超时 */
        ws_last_err = e;
        return -1;
    }
}

static int read_exact(SOCKET s, void *buf, size_t n) {
    char *p = buf;
    size_t got = 0;
    int idle = 0;
    while (got < n) {
        int r = recv_some(s, p + got, n - got);
        if (r > 0) { got += (size_t)r; idle = 0; continue; }
        if (r == -2) {
            /* recv 超时不是断线：半帧必须继续等，否则帧错位 */
            if (got == 0 && ++idle >= 3) return -3;
            continue;
        }
        return r;
    }
    return (int)got;
}

int ws_connect(ws_conn *w, const char *url) {
    memset(w, 0, sizeof *w);
    w->sock = INVALID_SOCKET;
    pthread_mutex_init(&w->mu, NULL);
    const char *p = url;
    if (strncmp(p, "ws://", 5) == 0) p += 5;
    else if (strncmp(p, "wss://", 6) == 0) { log_err("[ws] 不支持 wss://，用 ws://"); return -1; }
    char host[128] = "", port[16] = "80", path[128] = "/";
    char *slash = strchr(p, '/');
    if (slash) {
        snprintf(path, sizeof path, "%s", slash);
        size_t hl = (size_t)(slash - p);
        if (hl >= sizeof host) hl = sizeof host - 1;
        memcpy(host, p, hl); host[hl] = 0;
    } else {
        snprintf(host, sizeof host, "%s", p);
    }
    char *colon = strchr(host, ':');
    if (colon) { *colon = 0; snprintf(port, sizeof port, "%s", colon + 1); }

    int fd = tcp_connect(host, port, 20);
    if (fd < 0) return -1;
    SOCKET s = (SOCKET)fd;

    /* 握手 */
    unsigned char key[16];
    mask_key(key);
    char keyb64[32];
    b64_encode(key, 16, keyb64);
    char req[512];
    int rl = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, port, keyb64);
    if (send_all(s, req, (size_t)rl) != 0) { closesocket(s); return -1; }

    /* 读响应头：必须逐字节收到完整 \r\n\r\n（少读一个字节会让后续帧整体错位） */
    char hdr[2048];
    size_t hn = 0;
    for (;;) {
        if (hn >= sizeof hdr - 1) break;
        char c;
        int r = recv_some(s, &c, 1);
        if (r <= 0) { closesocket(s); return -1; }
        hdr[hn++] = c;
        if (hn >= 4 && memcmp(hdr + hn - 4, "\r\n\r\n", 4) == 0) break;
    }
    hdr[hn] = 0;
    if (!strstr(hdr, "101") || !strstr(hdr, "Upgrade")) {
        log_err("[ws] 握手失败: %.120s", hdr);
        closesocket(s);
        return -1;
    }
    w->sock = s;
    w->connected = 1;
    return 0;
}

static int ws_send_frame(ws_conn *w, unsigned char opcode, const unsigned char *data, size_t n) {
    unsigned char hdr[14];
    unsigned char key[4];
    mask_key(key);
    size_t hl = 2;
    hdr[0] = (unsigned char)(0x80 | opcode);
    if (n < 126) hdr[1] = (unsigned char)(0x80 | (unsigned char)n);
    else if (n < 65536) { hdr[1] = 0x80 | 126; hdr[2] = (unsigned char)(n >> 8); hdr[3] = (unsigned char)n; hl = 4; }
    else { hdr[1] = 0x80 | 127; for (int i = 0; i < 8; i++) hdr[2 + i] = (unsigned char)(n >> (56 - i * 8)); hl = 10; }
    memcpy(hdr + hl, key, 4);
    hl += 4;

    pthread_mutex_lock(&w->mu);
    int ok = send_all(w->sock, hdr, hl) == 0;
    if (ok && n > 0) {
        unsigned char masked[8192];
        size_t off = 0;
        while (off < n) {
            size_t chunk = n - off > sizeof masked ? sizeof masked : n - off;
            for (size_t i = 0; i < chunk; i++) masked[i] = data[off + i] ^ key[(off + i) & 3];
            if (send_all(w->sock, masked, chunk) != 0) { ok = 0; break; }
            off += chunk;
        }
    }
    pthread_mutex_unlock(&w->mu);
    if (!ok) {
        /* 半帧致命：立即判死让上层重连 */
        if (w->connected) {
            w->connected = 0;
            shutdown(w->sock, SD_BOTH);
        }
        return -1;
    }
    return 0;
}

int ws_send_text(ws_conn *w, const char *data, size_t n) {
    if (!w->connected) return -1;
    return ws_send_frame(w, 0x1, (const unsigned char *)data, n);
}

int ws_send_ping(ws_conn *w) {
    if (!w->connected) return -1;
    return ws_send_frame(w, 0x9, NULL, 0);
}

void ws_close(ws_conn *w) {
    if (w->sock != INVALID_SOCKET) {
        w->connected = 0;
        shutdown(w->sock, SD_BOTH);
        closesocket(w->sock);
        w->sock = INVALID_SOCKET;
    }
}

/* 逐帧读；控制帧内部处理；文本帧拷到 buf。返回 0=超时 -1=错误 */
int ws_read_text(ws_conn *w, char *buf, size_t bufsz, int timeout_s) {
    if (w->sock == INVALID_SOCKET) return -1;
    {
        struct timeval tv;
        tv.tv_sec = timeout_s;
        tv.tv_usec = 0;
        setsockopt(w->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    unsigned char *frag = w->rxfrag;

    for (;;) {
        unsigned char h[2];
        int r = read_exact(w->sock, h, 2);
        if (r == -3) return 0;          /* 空闲：调用方 ping 探活后继续读 */
        if (r <= 0) {
            if (r == 0)
                log_err("[ws] 对端关闭连接（EOF），无 close 帧");
            else
                log_err("[ws] 帧头读取失败 r=%d errno=%d(%s)", r, ws_last_err,
                        ws_last_err ? strerror(ws_last_err) : "?");
            return -1;
        }
        int fin = h[0] & 0x80;
        unsigned char opcode = h[0] & 0x0F;
        int masked = h[1] & 0x80;
        size_t len = h[1] & 0x7F;
        if (len == 126) {
            unsigned char e[2];
            r = read_exact(w->sock, e, 2);
            if (r <= 0) { log_err("[ws] 扩展长度读取失败 r=%d", r); return -1; }
            len = ((size_t)e[0] << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            r = read_exact(w->sock, e, 8);
            if (r <= 0) { log_err("[ws] 扩展长度读取失败 r=%d", r); return -1; }
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
        }
        unsigned char mkey[4] = {0};
        if (masked) {
            r = read_exact(w->sock, mkey, 4);
            if (r <= 0) { log_err("[ws] 掩码读取失败 r=%d", r); return -1; }
        }

        /* 文本帧、ping、pong 不再逐帧打日志（心跳每 20 秒一条，太吵）；
           文本帧的内容由 worker 的 [收] 那条负责记录 */
        if (opcode != 0x1 && opcode != 0x9 && opcode != 0xA)
            log_print("[ws] <- op=%d len=%lu fin=%d mask=%d", opcode, (unsigned long)len, fin, masked);
        if (len > sizeof w->rxfrag) {
            log_err("[ws] 帧超长 %lu > %lu", (unsigned long)len, (unsigned long)sizeof w->rxfrag);
            return -1;
        }
        if (len > 0) {
            r = read_exact(w->sock, frag, len);
            if (r <= 0) { log_err("[ws] 帧体读取失败 r=%d len=%lu", r, (unsigned long)len); return -1; }
        }
        if (masked) for (size_t i = 0; i < len; i++) frag[i] ^= mkey[i & 3];

        switch (opcode) {
        case 0x1:
            if (len >= bufsz) { log_err("[ws] 文本帧超出缓冲 %lu >= %lu", (unsigned long)len, (unsigned long)bufsz); return -1; }
            memcpy(buf, frag, len);
            buf[len] = 0;
            (void)fin;
            return (int)len;
        case 0x9:
            ws_send_frame(w, 0xA, (const unsigned char *)frag, len);
            continue;
        case 0xA: continue;
        case 0x8:
            log_err("[ws] <- 收到 close 帧（对端主动关闭）len=%lu code=%d",
                    (unsigned long)len, len >= 2 ? (frag[0] << 8 | frag[1]) : -1);
            ws_send_frame(w, 0x8, (const unsigned char *)frag, len > 125 ? 125 : len);
            return -1;
        default: continue;
        }
    }
}
