# portknock

A small Go service that lets a visitor open the host's firewall (ufw) to **their
own IP** through a web page, while an admin controls which **ports** are reachable
and which **IPs** are permanently trusted.

Access model — two **independent** rule families:

- **Whitelisted IP** (fixed or user-submitted) → that IP may reach **all ports**
  on the host (`ufw allow from <ip>`).
- **Whitelisted port** → that TCP port is open to **any source**
  (`ufw allow <port>/tcp`).

Pages:

- **User page** (`/`) — auto-detects the visitor's IP, shows it, and on confirm
  grants that IP all-port access.
- **Admin page** (`/admin`, password-protected) — set the publicly-open ports,
  manage a permanent fixed-IP whitelist, and view/revoke currently-granted IPs.
- **Idle expiry** — a user-granted (dynamic) IP and its firewall rule are removed
  after **48 hours with no connection activity** (any connection from that IP
  counts). Fixed/admin IPs never expire.

Single binary, Go standard library only (no external dependencies). **Linux +
ufw only** — it shells out to `ufw` and reads `/proc/net/nf_conntrack`.

## 一键部署（推荐）

在目标服务器（Debian 12/13、Ubuntu 24.04+ 等，需 root 与 ufw）上执行：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash
```

脚本会：识别 CPU 架构 → 下载最新 Release 二进制并校验 → 安装到
`/usr/local/bin/portknock`（并安装管理命令 `portknock-ctl`）→ **预置默认开放端口
`80, 443, 22, 222`** → **自动放行本机 SSH 端口**（防锁死，见下）→ 生成随机
**管理密码**和 **API 密钥**（存入 `/etc/portknock.env`，权限 600）→ 注册并启动
systemd 服务。完成后终端会打印密码和访问地址。重复执行即原地升级（状态与密码保留）。

**默认开放端口**：首次安装会写入初始 `state.json`，预置开放 `80, 443, 22, 222`
（对所有 IP 开放）。可用 `PORTKNOCK_DEFAULT_PORTS="80 443"` 覆盖。已存在的
`state.json` 不会被覆盖，之后随时可在管理台增删。

**SSH 防锁死**：安装时自动下发一条 `ufw allow 22/tcp` 规则，带
`portknock-install:` 注释，**独立于应用状态**——这是**唯一**管理界面删不掉、
也不会被规则重建清除的端口，用来保证你永远能 SSH 进来。其余端口（含预置的
80 / 443 / 222）都是普通可删端口，随时可在管理台增删。覆盖受保护端口用
`PORTKNOCK_SSH_PORT=2222`，完全跳过用 `PORTKNOCK_NO_SSH=1`。

> 若你的 sshd 实际监听的不是 22，安装时会提示——此时 22 的兜底规则保护不到你，
> 请把真实端口也设为受保护（`PORTKNOCK_SSH_PORT=<真实端口>`）或手动放行。

默认只监听 `127.0.0.1:8080`。要对外监听：

```sh
curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh \
  | sudo PORTKNOCK_LISTEN=0.0.0.0:8080 bash
```

> 生产环境建议仍监听本地，前面用 nginx/Caddy 终止 TLS 反代，尤其是 `/admin`。

### 管理命令（`portknock-ctl`）

安装后本地可直接调用（或远程 `curl ... | sudo bash -s -- <命令>`）：

| 命令 | 作用 |
|------|------|
| `sudo portknock-ctl status` | 服务状态 + 白名单概览 |
| `sudo portknock-ctl creds` | 打印管理密码 / API 密钥 |
| `sudo portknock-ctl reset-password` | 重新生成密码与密钥并重启 |
| `sudo portknock-ctl update` | 原地升级到最新 Release |
| `sudo portknock-ctl logs` | 实时跟随日志 |
| `sudo portknock-ctl restart` | 重启服务 |
| `sudo portknock-ctl backup [文件]` | 备份 `state.json` |
| `sudo portknock-ctl restore <文件>` | 从备份恢复并重启 |
| `sudo portknock-ctl uninstall [--purge]` | 卸载（`--purge` 连状态、密钥、install 的 SSH 规则一起删） |

## Install a prebuilt binary manually (no Go needed)

Each `v*` git tag triggers a GitHub Actions release with static Linux binaries.
Download, verify, and run — no toolchain required:

```sh
curl -fsSL -o portknock \
  https://github.com/huya1121/portknock/releases/latest/download/portknock-linux-amd64
chmod +x portknock
sudo PORTKNOCK_ADMIN_PASS='your-strong-password' ./portknock --listen 127.0.0.1:8080
```

(arm64 binary is published too: `portknock-linux-arm64`.)

## Build from source

```sh
go build -o portknock .
```

Cross-compiling from another OS (e.g. the Windows dev box):

```sh
GOOS=linux GOARCH=amd64 go build -o portknock .
```

## Run

ufw requires root, so the service runs as root.

```sh
sudo PORTKNOCK_ADMIN_PASS='your-strong-password' ./portknock \
    --listen 127.0.0.1:8080 \
    --state /var/lib/portknock/state.json \
    --expiry 48h --poll 2m
```

Make sure ufw itself is enabled (`sudo ufw enable`) and that your base policy
allows the service in — e.g. keep SSH open with your own rule so you don't lock
yourself out.

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen` | `:8080` | HTTP listen address |
| `--state` | `/var/lib/portknock/state.json` | state file path |
| `--admin-pass` | — | admin password (or env `PORTKNOCK_ADMIN_PASS`) |
| `--trust-proxy` | `false` | honor last `X-Forwarded-For` hop (set **only** behind a trusted reverse proxy) |
| `--poll` | `2m` | conntrack poll interval |
| `--expiry` | `48h` | idle-expiry window for dynamic IPs |
| `--dry-run` | `false` | log ufw commands instead of executing them (test without ufw) |
| `--secure-cookie` | `true` | set `Secure` on the session cookie (disable only for local HTTP testing) |
| `--api-key` | — | bearer token for the JSON API (or env `PORTKNOCK_API_KEY`); empty disables the API |

## JSON API

When `--api-key` (or `PORTKNOCK_API_KEY`) is set, a programmatic grant endpoint
is enabled for scripts / CI / home routers:

```sh
# grant the caller's own IP
curl -X POST https://host/api/grant -H "Authorization: Bearer $PORTKNOCK_API_KEY"

# grant a specific IP
curl -X POST https://host/api/grant \
     -H "Authorization: Bearer $PORTKNOCK_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"ip":"203.0.113.9"}'
# -> {"ip":"203.0.113.9","status":"granted"}
```

Granted IPs are dynamic — same all-port access and same 48h idle expiry as the
web page. The token is compared in constant time; the endpoint returns 404 when
no key is configured.

## Admin console features

- **Overview** — counts of open ports / fixed IPs / dynamic IPs at a glance.
- **Self-lockout guard** — warns when your current IP isn't in the fixed
  whitelist (so an expiring/removed rule could lock you out), with a one-click
  "add my IP as fixed" shortcut.
- **Humanized times** — grant/last-seen shown in local time; idle duration turns
  amber past 60% of the expiry window and red past 90%.
- **Rule-preview confirmation** — every change (save ports, add/remove fixed IP,
  revoke) first shows a modal with the current ufw rules plus the exact rules
  that would be added / deleted; nothing is written to ufw until you confirm.
  Backed by `GET /admin/preview` (read-only, auth required), which computes the
  diff via `Firewall.Preview` without touching the firewall.
- **Auto-refresh** — the page refreshes idle status every 30s (paused while you
  type), and is fully responsive on mobile (tables become stacked cards).

## How it works

- **State** (`store.go`) is a JSON file: `ports`, `fixed_ips`, and `dynamic`
  (each with `added_at` / `last_seen`). It is the single source of truth; writes
  are atomic (temp file + rename).
- **Firewall** (`firewall.go`) wraps ufw. Every managed rule carries a comment:
  `portknock:dyn:<ip>` / `portknock:fixed:<ip>` for all-port IP grants
  (`ufw allow from <ip>`), and `portknock:port:<port>` for public ports
  (`ufw allow <port>/tcp`). Changing ports or the IP lists triggers a full
  reconcile: purge all `portknock:` rules, then re-add from state. ufw is invoked
  with an argument slice (never a shell string).
- **Janitor** (`janitor.go`) polls `/proc/net/nf_conntrack` every `--poll`. Any
  live connection whose source is a dynamic IP refreshes that IP's `last_seen`
  (since dynamic IPs have all-port access, destination port is not filtered). Any
  dynamic IP idle longer than `--expiry` is revoked.

### Caveat: connection detection

Activity is sampled from conntrack on an interval, so a connection that both opens
and closes entirely between two polls can be missed. Over a 48h window this is
immaterial — a genuinely active IP appears across many polls. If the conntrack
table isn't readable (nf_conntrack module not loaded), the service logs a warning
and falls back to pure time-based expiry (48h from grant / last refresh), so it
still works, just without activity-based renewal.

## Security notes

- Runs as root (ufw requirement). Bind to localhost and front it with a reverse
  proxy that terminates TLS, especially for `/admin`.
- Client IP comes from the TCP peer by default. `X-Forwarded-For` is trusted
  **only** with `--trust-proxy`; enabling it without a trusted proxy in front lets
  anyone whitelist an arbitrary IP via a spoofed header.
- Admin auth is a single password (constant-time compared) with an in-memory
  session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) and per-session CSRF
  tokens on all state-changing POSTs.
- The public `/grant` form is CSRF-protected too, via a double-submit token
  (`HttpOnly`, `SameSite=Strict` cookie that the form value must match), so a
  cross-site page can't silently whitelist a visitor's IP.

## Test

```sh
go test ./...
```

Unit tests cover conntrack parsing, state round-trip + expiry, ufw rule
construction/parsing, and client-IP extraction.

## systemd

See [`portknock.service`](portknock.service). Install the binary to
`/usr/local/bin/portknock`, edit the password, then:

```sh
sudo cp portknock /usr/local/bin/
sudo cp portknock.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now portknock
```
