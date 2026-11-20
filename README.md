# portknock

一个很小的 Go 服务：访客在网页上点一下，就把自己当前的 IP 加进本机 ufw 防火墙白名单；
管理员在后台控制哪些端口对外开放、哪些 IP 永久放行。适合"平时端口全关，需要时临时放自己进来"的场景。

单文件二进制，只依赖 Go 标准库，没有外部依赖。**只能跑在 Linux + ufw 上**——
它直接调用 `ufw` 命令，并读 `/proc/net/nf_conntrack` 判断连接活动。

## 它是怎么放行的

两套互不相干的规则：

- **白名单 IP**（固定的或用户自助提交的）：这个 IP 能访问本机**所有端口**（`ufw allow from <ip>`）。
- **开放端口**：这个 TCP 端口对**任何来源**开放（`ufw allow <port>/tcp`）。

三个页面/行为：

- **用户页 `/`**：自动识别访客 IP 并显示出来，点确认就放行该 IP（全端口）。
- **管理台 `/admin`**（密码保护）：设置对外开放的端口、管理固定 IP 白名单、查看和撤销当前放行的 IP。
- **空闲回收**：用户自助放行的 IP，如果 **48 小时内没有任何连接**，就连同它的防火墙规则一起删除。
  固定 IP 不会过期。

## 一键部署

目标机器需要 root 和 ufw（Debian 12/13、Ubuntu 24.04+ 之类都行）：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash
```

脚本做这些事：按 CPU 架构下载最新 Release 二进制并校验 → 装到 `/usr/local/bin/portknock`
（同时装一个管理命令 `portknock-ctl`）→ 预置默认开放端口 `80, 443, 22, 222` →
自动放行 SSH 端口防止把自己锁在外面 → 生成随机的**管理密码**和 **API 密钥**
（写进 `/etc/portknock.env`，权限 600）→ 注册并启动 systemd 服务。装完会在终端打印密码和访问地址。
重复执行就是原地升级，状态和密码都保留。

本地直接跑 `sudo portknock-ctl`（不带参数）会进一个交互菜单，首次安装也可以走里面的引导向导，
一步步问你监听地址、端口、SSH 口、是否反代。

### 默认开放端口

首次安装会写一个初始 `state.json`，预置开放 `80, 443, 22, 222`（对所有 IP）。
想换用 `PORTKNOCK_DEFAULT_PORTS="80 443"`。已经存在的 `state.json` 不会被覆盖，之后都在管理台里改。

### SSH 防锁死

安装时会单独下一条放行 SSH 的规则（默认 22，会自动探测你 sshd 实际监听的端口，比如 222）。
这条规则带 `portknock-install:` 注释，**独立于应用状态**——管理台删不掉、也不会被规则重建清掉，
就是为了保证你任何时候都能 SSH 进来。其余端口（包括预置的 80/443/222）都是普通端口，随时能删。
想改受保护的端口用 `PORTKNOCK_SSH_PORT=2222`，完全不要这条规则用 `PORTKNOCK_NO_SSH=1`。

### 监听地址与端口

默认只监听 `127.0.0.1:8080`，也就是只有本机能连，外面访问不到。用 `PORTKNOCK_LISTEN` 改：

```sh
# 对外监听，之后用 http://服务器IP:8080/ 访问
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_LISTEN=0.0.0.0:8080 bash

# 换端口（比如 8080 被占了）
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_LISTEN=0.0.0.0:8888 bash
```

安装时如果发现端口被别的进程占了会提示你换一个。

对外监听（`0.0.0.0`）之前想清楚几点：这个端口得自己放行（管理台加进开放端口，或先
`sudo ufw allow 8080/tcp`），否则 ufw 一开就把管理口也挡了；而且是明文 HTTP，
密码和 API 密钥都走明文；用户页对公网开放意味着任何人都能打开它放行自己，面向公众时最好加口令或只给可信网络。

只想自己偶尔管一下、不想暴露端口的话，**SSH 隧道最省心**（保持默认 `127.0.0.1:8080` 不动）：

```sh
# 本地执行，-p 换成你的 SSH 端口，然后浏览器开 http://localhost:8080
ssh -L 8080:127.0.0.1:8080 -p 222 root@服务器IP
```

### 管理命令 `portknock-ctl`

装好后本地直接用，远程也能 `curl ... | sudo bash -s -- <命令>`：

| 命令 | 作用 |
|------|------|
| `sudo portknock-ctl` | 不带参数进交互菜单 |
| `sudo portknock-ctl status` | 服务状态 + 白名单概览 |
| `sudo portknock-ctl urls` | 打印访问链接和能直接跑的 API 示例 |
| `sudo portknock-ctl creds` | 看管理密码 / API 密钥 |
| `sudo portknock-ctl reset-password` | 重新生成密码和密钥并重启 |
| `sudo portknock-ctl update` | 原地升级到最新 Release |
| `sudo portknock-ctl logs` | 跟随日志 |
| `sudo portknock-ctl restart` | 重启 |
| `sudo portknock-ctl backup [文件]` | 备份 `state.json` |
| `sudo portknock-ctl restore <文件>` | 从备份恢复并重启 |
| `sudo portknock-ctl uninstall [--purge]` | 卸载（`--purge` 连状态、密钥、SSH 规则一起删） |

## 反向代理和真实 IP

portknock 靠访客 IP 决定放行谁，所以要不要开 `--trust-proxy`，取决于你怎么暴露它。

**直连、没有反代**（直接开 `http://服务器IP:端口`）：别开 `PORTKNOCK_TRUST_PROXY`，
装完那句"反代：未启用"忽略即可。这种情况下开了反而危险——没有可信代理挡在前面时，
任何人都能伪造 `X-Forwarded-For` 来放行任意 IP。

**前面有 nginx/Caddy**：不开 `--trust-proxy` 的话，portknock 只看得到反代的 `127.0.0.1`，
所有访客都变成同一个 IP，放行就失效了。这时候两边都要配。先重装并打开信任代理（状态和密码会保留）：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_TRUST_PROXY=1 bash
```

nginx 这边要把真实 IP 透传过来，关键是 `X-Forwarded-For`：

```nginx
server {
    listen 443 ssl;
    server_name portknock.example.com;        # 换成你的域名
    ssl_certificate     /etc/letsencrypt/live/portknock.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portknock.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

开了 `--trust-proxy` 就一定要让 portknock 只监听本地（默认的 `127.0.0.1:8080`），
保证唯一入口是反代，否则有人绕过 nginx 直连 8080 伪造头照样能骗过去。portknock 取的是
`X-Forwarded-For` 的**最后一跳**，配合 nginx 的 `$proxy_add_x_forwarded_for`，既拿到真实 IP 又防伪造。

想确认生效没：打开用户页，看"检测到的来访 IP"是不是你真实的公网 IP，而不是 `127.0.0.1`。

### HTTPS 与 Secure cookie

`--secure-cookie` 默认**关**，而且和 `--trust-proxy` 相互独立——"有反代"不等于"走 HTTPS"。
只有确实通过 `https://` 访问时才加 `PORTKNOCK_SECURE_COOKIE=1`：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_TRUST_PROXY=1 PORTKNOCK_SECURE_COOKIE=1 bash
```

如果在明文 HTTP 下开了 Secure cookie，浏览器会丢掉登录/CSRF 的 cookie，表现就是
**登录之后立刻跳回登录页**，很像密码错了。遇到这种情况先把它关掉。

## 管理台里有什么

- **概览**：开放端口 / 固定 IP / 动态 IP 的数量，一眼看到。
- **防火墙总开关**：规则配错把自己挡外面时的紧急逃生——一键 `ufw disable` 让所有端口恢复可达，
  排障完再一键启用。
- **IPv6 开关**：切换 ufw 管不管 IPv6。受控时 IPv6 和 IPv4 一样走白名单；放开则 ufw 不碰 IPv6、
  所有 IPv6 端口直通（改 `/etc/default/ufw` 并 reload，有二次确认）。
- **自我锁定提醒**：当前 IP 不在固定白名单时会提示你，并给个"把我加进固定白名单"的快捷按钮，
  免得规则过期后进不来。
- **规则预览确认**：改端口、增删 IP、撤销之前，会弹窗显示当前 ufw 规则和这次会增删哪些，确认了才真正下发。
- **本地时间 + 空闲预警**：放行时间按本地时区显示，空闲时长超过回收窗口 60% 变黄、90% 变红。
- **自动刷新 + 移动端适配**：页面每 30 秒刷新空闲状态（输入时暂停），窄屏下表格变成卡片。

## JSON API

设了 `--api-key`（或环境变量 `PORTKNOCK_API_KEY`）就会开一个放行接口，方便脚本 / CI / 家里路由器调用：

```sh
# 放行调用方自己的 IP
curl -X POST https://host/api/grant -H "Authorization: Bearer $PORTKNOCK_API_KEY"

# 放行指定 IP
curl -X POST https://host/api/grant \
     -H "Authorization: Bearer $PORTKNOCK_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"ip":"203.0.113.9"}'
# -> {"ip":"203.0.113.9","status":"granted"}
```

通过 API 放行的 IP 也是动态的，和网页放行一样全端口、48 小时空闲回收。密钥是常量时间比较的；
没配密钥时这个接口返回 404。

## 手动安装（不装 Go）

每打一个 `v*` tag，GitHub Actions 就会编译出静态 Linux 二进制。直接下载就能跑：

```sh
curl -fsSL -o portknock \
  https://github.com/huya1121/portknock/releases/latest/download/portknock-linux-amd64
chmod +x portknock
sudo PORTKNOCK_ADMIN_PASS='你的强密码' ./portknock --listen 127.0.0.1:8080
```

arm64 也有：`portknock-linux-arm64`。

## 从源码编译

```sh
go build -o portknock .
# 交叉编译 Linux 版：
GOOS=linux GOARCH=amd64 go build -o portknock .
```

## 参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `--listen` | `:8080` | 监听地址 |
| `--state` | `/var/lib/portknock/state.json` | 状态文件路径 |
| `--admin-pass` | — | 管理密码（或环境变量 `PORTKNOCK_ADMIN_PASS`） |
| `--trust-proxy` | `false` | 信任 `X-Forwarded-For` 最后一跳（**仅**在可信反代后面开） |
| `--poll` | `2m` | conntrack 轮询间隔 |
| `--expiry` | `48h` | 动态 IP 的空闲回收窗口 |
| `--dry-run` | `false` | 只打印 ufw 命令不执行（无 ufw 环境下测试用） |
| `--secure-cookie` | `false` | 给 cookie 加 Secure，**仅** HTTPS 下开（明文 HTTP 下开了会登不上） |
| `--api-key` | — | JSON API 的 bearer token（或 `PORTKNOCK_API_KEY`），空则关闭 API |

## 实现大概

- **状态**（`store.go`）是一个 JSON 文件，记 `ports` / `fixed_ips` / `dynamic`，是唯一事实来源；
  写入用临时文件加 rename，保证原子。
- **防火墙**（`firewall.go`）包一层 ufw。每条规则都带注释：IP 放行是 `portknock:dyn:<ip>` /
  `portknock:fixed:<ip>`（`ufw allow from <ip>`），开放端口是 `portknock:port:<port>`。
  改动时做 diff，只加缺的、只删多余的，保留的规则不动，避免访问中断。
- **回收**（`janitor.go`）按 `--poll` 读 conntrack，任何来自动态 IP 的连接都刷新它的 last_seen；
  空闲超过 `--expiry` 就撤销。IPv6 地址会规范化后再比对，避免展开/压缩格式不一致导致误删。

conntrack 是定时采样的，所以两次采样之间开了又关的连接可能漏掉——但在 48 小时的尺度下无所谓，
真正活跃的 IP 会在很多次采样里出现。如果内核没加载 conntrack 模块，会退化成纯计时（从放行/上次刷新算 48 小时）。

## 安全说明

- 以 root 运行（ufw 要求）。建议只监听本地，前面用反代终止 TLS，管理台尤其如此。
- 默认取 TCP 对端地址当客户端 IP。`X-Forwarded-For` 只在 `--trust-proxy` 下才信；
  没有可信反代就开，等于让人随便伪造头放行任意 IP。
- 管理密码常量时间比较，session 存在进程内存里（cookie 带 `HttpOnly` / `SameSite=Strict`），
  所有改状态的 POST 都带 CSRF token。
- 用户页 `/grant` 也有 CSRF 保护（双重提交 token），避免别的网站偷偷让访客放行自己。

## 测试

```sh
go test ./...
```

覆盖 conntrack 解析、状态读写与过期、ufw 规则构造/解析、客户端 IP 提取等。

---

# portknock (English)

A tiny Go service that lets a visitor whitelist their own IP in the host's ufw
firewall from a web page, while an admin controls which ports are open and which
IPs are permanently trusted. Single static binary, standard library only,
**Linux + ufw only**.

**Access model** — two independent rule families: a whitelisted IP (fixed or
user-submitted) reaches *all* ports (`ufw allow from <ip>`); a whitelisted port
is open to *any* source (`ufw allow <port>/tcp`). User-submitted IPs expire after
48h with no connection activity; fixed IPs never do.

**Install:**

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash
```

Downloads the latest release binary, seeds default open ports `80,443,22,222`,
keeps SSH reachable to avoid lockout, generates an admin password + API key in
`/etc/portknock.env`, and starts a systemd service. Manage it later with
`sudo portknock-ctl` (run with no args for an interactive menu). Override the
listen address with `PORTKNOCK_LISTEN=0.0.0.0:8080`.

**Behind a reverse proxy:** reinstall with `PORTKNOCK_TRUST_PROXY=1` so the real
client IP is read from the last `X-Forwarded-For` hop, and have nginx set that
header. Keep portknock bound to localhost. Add `PORTKNOCK_SECURE_COOKIE=1` only
when actually served over HTTPS — a Secure cookie on plain HTTP breaks login.

**Flags:** `--listen`, `--state`, `--admin-pass`, `--trust-proxy`, `--poll`,
`--expiry`, `--dry-run`, `--secure-cookie`, `--api-key` (see the Chinese table
above for defaults and meaning).

**JSON API:** with `--api-key` set, `POST /api/grant` with
`Authorization: Bearer <key>` grants the caller's IP (or `{"ip":"..."}`).

Build from source: `go build -o portknock .` (cross-compile with
`GOOS=linux GOARCH=amd64`). Run `go test ./...` for the unit tests.

