/* main.c - 入口：GUI（GTK）或无头守护进程（--config appsettings.json） */
#include <locale.h>
#include "common.h"
#include "app.h"
#include "config.h"

int gui_main(int argc, char **argv);
int daemon_main(int argc, char **argv);

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv) {
    int is_daemon = 0;

    signal(SIGPIPE, SIG_IGN);
    setlocale(LC_ALL, "C.UTF-8");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "--daemon") == 0) is_daemon = 1;
    }

    if (is_daemon) {
        signal(SIGTERM, on_signal);
        signal(SIGINT, on_signal);
        return daemon_main(argc, argv);
    }

    config_init_paths();
#ifdef WITH_GTK
    return gui_main(argc, argv);
#else
    fprintf(stderr, "本机没编译 GUI（缺 GTK3）。无头模式请用：getcid --config appsettings.json\n");
    return 2;
#endif
}
