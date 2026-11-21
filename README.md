# GetCIDLinux

GetCID 的 **Linux 纯 C 实现**：同一套源码编出两个产物——

| 产物 | 用途 | 依赖 |
| --- | --- | --- |
| `build/getcid` | 无头守护进程。跑在服务器上，人机交互走「文件通道」（`prompt/request.txt` ↔ `prompt/answer.txt`），可被任何 Web 控制台复用 | libcurl、OpenSSL、pthread |
| `build/getcid-gui` | GTK3 桌面版，界面/功能对齐 Windows 版 [GetCID-C](https://github.com/tcbkk/GetCID-C) | 上面三个 + GTK3 |

实测常驻内存 RSS 约 13–18 MB，空闲 CPU < 1%。

## 依赖

Debian / Ubuntu：

```sh
sudo apt-get update
sudo apt-get install -y build-essential libcurl4-openssl-dev libssl-dev pkg-config libgtk-3-dev
```

只跑无头版可以不装 `libgtk-3-dev`。

## 编译

```sh
./build.sh daemon   # 只编无头版 → build/getcid
./build.sh gui      # 只编 GUI 版 → build/getcid-gui
./build.sh all      # 两个都编
```

## 两种运行方式

### 1. 无头守护进程

```sh
./getcid --config /opt/serverclient01/appsettings.json
```

配置（与 C# 版同名字段，可直接接管旧部署）：

```json
{
  "Server": "ws://getcid.live:8082",
  "ClientName": "serverclient01",
  "Username": "you@example.com",
  "Password": "your-password",
  "Prompt": "file",
  "LogDirectory": "logs"
}
```

- 工作目录切到配置所在目录，token 存 `<目录>/vs_tokens.json`（与旧版同名同格式，可直接拷贝接管，无需重新登录）。
- `Prompt` 取 `file`（密码 + 邮箱安全码，验证码走文件通道）或 `device`（设备码，免密码）。
- 日志用 `log_set_console(1)` 打到 stdout，配 systemd 就是 `journalctl -u <unit>`。

### 2. GTK3 桌面版

```sh
./getcid-gui          # 同目录读 config.json
```

配置（exe 同目录 `config.json`）：

```json
{
  "server": "ws://getcid.live:8082",
  "instances": [
    {
      "client_name": "serverclient01",
      "server": "ws://getcid.live:8082",
      "account": "you@example.com",
      "password": "your-password",
      "mode": "account",
      "login": "password",
      "lang": 1,
      "autostart": 1
    }
  ]
}
```

数据布局：

```
config.json
instances/<client_name>/vs_tokens.json
instances/<client_name>/logs/yyyymmdd.log
logs/app.log
```

## 部署示例

`deploy/` 下给了可以直接改的模板：

- `deploy/getcid.service` —— 无头实例（`Prompt=file` 时用这个）
- `deploy/getcid-gui.service` —— 桌面版，要求目标机有 X 显示（xrdp / Xorg / Xvfb 都行）
- `deploy/appsettings.json` / `deploy/config.json` —— 配置样例

```sh
sudo install -m755 build/getcid /opt/serverclient01/getcid
sudo cp deploy/getcid.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now getcid
```

注意两点（踩过的坑）：

- 覆盖二进制前先 `systemctl stop`，否则 `cp` 会 `ETXTBSY`。
- 应用 `pkill -f getcid` 会匹配到自己的 ssh 命令行，用 `pkill -x` 或带括号的特征串。

## 文件通道协议（给 Web 控制台用）

守护进程需要人工介入时写 `prompt/request.txt`：

```
ID=<请求号>
TYPE=ask|device
TITLE=<标题>
MESSAGE=<一句话说明>
OPTION1..N=<可选项，TYPE=select 时>
TIMEOUT=<秒>
```

`TYPE=device` 时额外带 `URL=`、`CODE=`。控制台把答案写进 `prompt/answer.txt`：

```
ID=<同一个请求号>
VALUE=<答案>
```

`ID` 对不上会被当成上一轮的旧答案丢弃。账号登录默认先问「收件邮箱」，发码后再问「6 位验证码」。

## 目录结构

```
src/
  main.c        入口：--config/--daemon → 守护进程；否则 GTK 界面
  daemon.c      无头版主循环、人工应答、指数退避
  gui_gtk.c     GTK3 界面（固定坐标布局，对齐 Windows 版）
  prompt_file.c 文件通道提示器
  mslogin.c     微软网页登录（密码 / 一次性邮箱验证码 / 设备码）
  msft.c        DPoP、token 刷新（OpenSSL EC/ECDSA）
  https.c       libcurl 封装
  ws.c          WebSocket 客户端（BSD socket）
  worker.c      实例状态机、取号
  aes.c         AES-256-CBC（OpenSSL）
  ...
deploy/         systemd 单元与配置样例
build.sh        编译脚本
```

## 相关仓库

- Windows 版（Win32 GUI）：https://github.com/tcbkk/GetCID-C

## 说明

本项目仅用于管理自己的 Microsoft 账号与自有取号服务器之间的通信，请勿用于未授权的账号操作。
