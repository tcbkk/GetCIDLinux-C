#!/bin/sh
# build.sh - 编译 GetCIDLinux
#   无头守护进程（服务器用，不需要图形库）：
#       ./build.sh daemon
#   GUI 版（GTK3，需要 libgtk-3-dev）：
#       ./build.sh gui
#   两个都要：
#       ./build.sh all
set -e
cd "$(dirname "$0")"

CC=${CC:-gcc}
CFLAGS="-O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare"
LIBS="-lcurl -lcrypto -lpthread"
SRC="$(ls src/*.c | grep -v 'src/gui_gtk.c' | tr '\n' ' ')"

mkdir -p build

build_daemon() {
    echo "== 编译无头守护进程 =="
    $CC $CFLAGS -Isrc $SRC -o build/getcid $LIBS
    echo "完成: build/getcid ($(stat -c%s build/getcid) 字节)"
}

build_gui() {
    if ! pkg-config --exists gtk+-3.0; then
        echo "缺 GTK3 开发包：apt-get install -y libgtk-3-dev" >&2
        exit 1
    fi
    echo "== 编译 GUI 版 =="
    GTK_FLAGS=$(pkg-config --cflags gtk+-3.0)
    GTK_LIBS=$(pkg-config --libs gtk+-3.0)
    $CC $CFLAGS -DWITH_GTK $GTK_FLAGS -Isrc $SRC src/gui_gtk.c -o build/getcid-gui $LIBS $GTK_LIBS
    echo "完成: build/getcid-gui ($(stat -c%s build/getcid-gui) 字节)"
}

case "${1:-daemon}" in
    daemon) build_daemon ;;
    gui)    build_gui ;;
    all)    build_daemon; build_gui ;;
    *) echo "用法: ./build.sh [daemon|gui|all]" >&2; exit 1 ;;
esac
