# portknock

一个很小的 Go 服务：访客在网页上点一下，就把自己当前的 IP 加进本机 ufw 防火墙白名单；
管理员在后台控制哪些端口对外开放、哪些 IP 永久放行。适合"平时端口全关，需要时临时放自己进来"的场景。

单文件二进制，只依赖 Go 标准库，没有外部依赖。**只能跑在 Linux + ufw 上**——
它直接调用 `ufw` 命令，并读 `/proc/net/nf_conntrack` 判断连接活动。

**全程 HTTPS**：服务只监听 HTTPS，首次启动自动生成自签证书（存在状态目录，过期自动续）。
浏览器会提示证书不受信任，点"继续访问"即可——连接本身是加密的，管理密码、API 密钥、
节点间同步都不会明文过网。用 `curl` 调 API 记得加 `-k`。

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

目标机器需要 root（Debian 12/13、Ubuntu 24.04+ 之类都行；ufw 没装脚本会自动装）：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash
```

脚本做这些事：检测 ufw，没装就用系统包管理器自动装（apt/dnf/yum/zypper/pacman/apk）→
按 CPU 架构下载最新 Release 二进制并校验 → 装到 `/usr/local/bin/portknock`
（同时装一个管理命令 `portknock-ctl`）→ 预置默认开放端口 `80, 443, 22, 222` →
自动放行 SSH 端口防止把自己锁在外面 → 生成随机的**管理密码**和 **API 密钥**
（写进 `/etc/portknock.env`，权限 600）→ 注册并启动 systemd 服务。
不管首装还是重装，结尾都会完整打印访问地址、管理密码、API 密钥和所有管理命令。
重复执行就是原地升级，状态和密码都保留。

在终端直接跑这条一键命令会进一个交互菜单，可以选引导安装（一步步问你监听地址、端口、
SSH 口、是否反代），也能查状态、看密码、重启等。装好后用 `portknock-ctl`（不带参数）
随时再进这个菜单。要无人值守、不弹菜单直接装，用：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash -s -- install
```

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
# 对外监听，之后用 https://服务器IP:8080/ 访问
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_LISTEN=0.0.0.0:8080 bash

# 换端口（比如 8080 被占了）
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_LISTEN=0.0.0.0:8888 bash
```

对外监听（`0.0.0.0`）时，安装脚本会自动放行这个监听端口（带 `portknock-install:` 注释，
管理台删不掉、升级也保留），不用再手动开，否则 ufw 一启用会把管理口自己挡掉。安装时如果
发现端口被别的进程占了也会提示你换一个。

但要注意：对外是明文 HTTP，密码和 API 密钥都走明文传输；用户页对公网开放意味着任何人都能
打开它放行自己。面向公众时最好加口令、套 HTTPS 反代，或只放给可信网络。

只想自己偶尔管一下、不想暴露端口的话，**SSH 隧道最省心**（保持默认 `127.0.0.1:8080` 不动）：

```sh
# 本地执行，-p 换成你的 SSH 端口，然后浏览器开 https://localhost:8080
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

> 文档里的 `sudo` 是给普通用户看的。如果你本来就是 root（很多 VPS 默认 root 登录，也没装 sudo），把命令里的 `sudo ` 去掉直接跑即可，否则会报 `sudo: command not found`。

## 反向代理和真实 IP

portknock 靠访客 IP 决定放行谁，所以要不要开 `--trust-proxy`，取决于你怎么暴露它。

**直连、没有反代**（直接开 `https://服务器IP:端口`）：别开 `PORTKNOCK_TRUST_PROXY`，
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
        # portknock 自身是 HTTPS（自签证书），所以上游用 https 且关掉校验
        proxy_pass https://127.0.0.1:8080;
        proxy_ssl_verify off;
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

### 关于 HTTPS 证书

portknock 自身就是 HTTPS（自签证书，自动生成）。前置 nginx/Caddy 时，反代用自己的
正式证书对外，到 portknock 的上游连接用 `https://127.0.0.1:8080` 并关掉证书校验
（`proxy_ssl_verify off`，因为那是自签的）。cookie 始终带 Secure，无需配置。

## 管理台里有什么

- **概览**：开放端口 / 固定 IP / 动态 IP 的数量，一眼看到。
- **防火墙总开关**：规则配错把自己挡外面时的紧急逃生——一键 `ufw disable` 让所有端口恢复可达，
  排障完再一键启用。
- **IPv6 开关**：切换 ufw 管不管 IPv6。受控时 IPv6 和 IPv4 一样走白名单；放开则 ufw 不碰 IPv6、
  所有 IPv6 端口直通（改 `/etc/default/ufw` 并 reload，有二次确认）。
- **自我锁定提醒**：当前 IP 不在固定白名单时会提示你，并给个"把我加进固定白名单"的快捷按钮，
  免得规则过期后进不来。
- **规则预览确认**：改端口、增删 IP、撤销之前，会弹窗显示当前 ufw 规则和这次会增删哪些，确认了才真正下发。
- **子节点同步**：配置其它 portknock 节点（地址 + API 密钥），本机放行的用户 IP 自动推送过去（见下）。
- **API 信息**：直接显示 API 密钥、接口地址和可复制的 curl 调用示例。
- **标签分页**：顶部标签切换（概览 / 白名单 / 防火墙 / 集群·API），不用一路滚到底。
- **本地时间 + 空闲预警**：放行时间按本地时区显示，空闲时长超过回收窗口 60% 变黄、90% 变红。
- **自动刷新 + 移动端适配**：页面每 30 秒刷新空闲状态（输入时暂停），窄屏下表格变成卡片。

## JSON API

设了 `--api-key`（或环境变量 `PORTKNOCK_API_KEY`）就会开一个放行接口，方便脚本 / CI / 家里路由器调用：

`-k` 是因为证书自签：

```sh
# 放行调用方自己的 IP
curl -k -X POST https://host/api/grant -H "Authorization: Bearer $PORTKNOCK_API_KEY"

# 放行指定 IP
curl -k -X POST https://host/api/grant \
     -H "Authorization: Bearer $PORTKNOCK_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"ip":"203.0.113.9"}'
# -> {"ip":"203.0.113.9","status":"granted"}
```

通过 API 放行的 IP 也是动态的，和网页放行一样全端口、48 小时空闲回收。密钥是常量时间比较的；
没配密钥时这个接口返回 404。

管理台的「JSON API」卡片会直接显示密钥、接口地址和可复制的调用示例，不用去翻配置文件。

## 多节点同步

部署了多台 portknock 时，可以让一台当"中心"，在它网页上放行的 IP 自动同步到其它节点，
不用逐台操作。配置全在管理台，不需要外部脚本。

**怎么配**：在中心节点管理台的「子节点同步」卡片里，逐个填子节点的地址（如
`https://10.0.0.11:8080`）和它的 **API 密钥**（子节点要配 `PORTKNOCK_API_KEY` 开启 API，
在它自己管理台的「JSON API」卡片能看到）。之后中心每次有用户自助放行，就在后台调所有子节点的
`/api/grant` 把这个 IP 推过去；不阻塞页面，某个子节点离线只记日志、不影响其余。janitor 每轮
（默认 2 分钟）会重推一遍存活的动态 IP，保证子节点上的规则不会因 48 小时空闲被回收。

**角色随时切换**：每台跑的都是同一个二进制，配了子节点就是中心、没配就是普通节点，在管理台
加/删子节点即可，不用重装或重启。

**防循环**：节点间同步推送带一个内部标记，收到后只在本地放行、**不再继续转发**（最多一跳）。
所以即便两台互相把对方设为子节点，也不会无限互推——可以放心组任意拓扑。

**注意**：
- 只有**用户自助放行的动态 IP** 会同步；admin 手动加的固定 IP 不同步。
- 节点间同步走 HTTPS（自签证书），传输已加密。但中心会把子节点的 API 密钥**明文存**进自己的
  `state.json`（权限 600）——确保中心主机本身安全。

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
| `--api-key` | — | JSON API 的 bearer token（或 `PORTKNOCK_API_KEY`），空则关闭 API |
| `--grant-pass` | — | 用户页放行口令（或 `PORTKNOCK_GRANT_PASSWORD`），空则无门槛 |

## 实现大概

- **状态**（`store.go`）是一个 JSON 文件，记 `ports` / `fixed_ips` / `dynamic`，是唯一事实来源；
  写入用临时文件加 rename，保证原子。
- **防火墙**（`firewall.go`）包一层 ufw。每条规则都带注释：IP 放行是 `portknock:dyn:<ip>` /
  `portknock:fixed:<ip>`（`ufw allow from <ip>`），开放端口是 `portknock:port:<port>`。
  改动时做 diff，只加缺的、只删多余的，保留的规则不动，避免访问中断。
- **回收**（`janitor.go`）按 `--poll` 读 conntrack，任何来自动态 IP 的连接都刷新它的 last_seen；
  空闲超过 `--expiry` 就撤销。IPv6 地址会规范化后再比对，避免展开/压缩格式不一致导致误删。
- **同步**（`syncer.go`）把动态放行并发推给各子节点的 `/api/grant`，全程后台不阻塞；节点间推送带
  内部标记，收到不再转发，防止成环。

conntrack 是定时采样的，所以两次采样之间开了又关的连接可能漏掉——但在 48 小时的尺度下无所谓，
真正活跃的 IP 会在很多次采样里出现。如果内核没加载 conntrack 模块，会退化成纯计时（从放行/上次刷新算 48 小时）。

## 安全说明

- 以 root 运行（ufw 要求）。全程 HTTPS（自签证书），所有流量加密。
- 默认取 TCP 对端地址当客户端 IP。`X-Forwarded-For` 只在 `--trust-proxy` 下才信；
  没有可信反代就开，等于让人随便伪造头放行任意 IP。
- 管理密码常量时间比较，session 存在进程内存里（cookie 带 `Secure` / `HttpOnly` /
  `SameSite=Strict`），所有改状态的 POST 都带 CSRF token。登录失败同一 IP 累计 5 次锁定 5 分钟，防暴力破解。
- 用户页 `/grant` 有 CSRF 保护（双重提交 token）；可用 `--grant-pass` 设共享口令，
  要求访客输入口令才放行——**面向公网时强烈建议开**，否则任何人都能放行自己访问全部端口。

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

**HTTPS:** the service is HTTPS-only with an auto-generated self-signed cert
(browsers warn; connection is encrypted). Use `curl -k` for the API.

**Behind a reverse proxy:** reinstall with `PORTKNOCK_TRUST_PROXY=1` so the real
client IP is read from the last `X-Forwarded-For` hop; have nginx `proxy_pass
https://127.0.0.1:8080` with `proxy_ssl_verify off`.

**User-page password:** set `PORTKNOCK_GRANT_PASSWORD` so visitors must enter a
shared password before granting — recommended for any public-facing deployment.

**Flags:** `--listen`, `--state`, `--admin-pass`, `--trust-proxy`, `--poll`,
`--expiry`, `--dry-run`, `--api-key`, `--grant-pass` (see the Chinese table
above for defaults and meaning).

**JSON API:** with `--api-key` set, `POST /api/grant` with
`Authorization: Bearer <key>` grants the caller's IP (or `{"ip":"..."}`). The
admin console shows the key and ready-to-run examples.

**Multi-node sync:** in the admin console add other nodes (URL + their API key);
IPs granted on this node are pushed to them automatically in the background, and
re-pushed each janitor pass to keep them alive. Inter-node pushes are not
forwarded again (one-hop cap), so any topology is loop-safe.

Build from source: `go build -o portknock .` (cross-compile with
`GOOS=linux GOARCH=amd64`). Run `go test ./...` for the unit tests.

