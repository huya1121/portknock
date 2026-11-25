#!/usr/bin/env bash
# portknock installer & management script.
#
# Quick install (default command):
#   curl -fsSL https://raw.githubusercontent.com/huya1121/portknock/main/install.sh | sudo bash
#
# Any subcommand, remotely:
#   curl -fsSL .../install.sh | sudo bash -s -- <command>
#
# Once installed, this script is also available locally as `portknock-ctl`:
#   sudo portknock-ctl <command>
#
# Run with no arguments on a terminal (sudo portknock-ctl) to open an
# interactive menu. A piped install (curl | sudo bash) runs install directly.
#
# Commands:
#   install            Install or upgrade, then start (default).
#   update             Alias of install (in-place upgrade; state & creds kept).
#   uninstall          Stop, disable, and remove the service & binary.
#                        Add --purge to also delete state dir and env file.
#   status             Show service status and current whitelist summary.
#   urls               Print access URLs and a ready-to-run API example.
#   creds              Print the admin password and API key.
#   reset-password     Generate a new admin password (and API key) and restart.
#   logs               Follow the service logs (journalctl -f).
#   restart            Restart the service.
#   backup [FILE]      Save state.json to FILE (default: ./portknock-backup-<ts>.json).
#   restore FILE       Replace state.json with FILE and restart.
#   version            Print installed binary version.
set -euo pipefail

REPO="huya1121/portknock"
BIN_DIR="/usr/local/bin"
BIN_PATH="${BIN_DIR}/portknock"
CTL_PATH="${BIN_DIR}/portknock-ctl"
STATE_DIR="/var/lib/portknock"
STATE_FILE="${STATE_DIR}/state.json"
ENV_FILE="/etc/portknock.env"
SERVICE="/etc/systemd/system/portknock.service"
LISTEN="${PORTKNOCK_LISTEN:-127.0.0.1:8080}"
# Set PORTKNOCK_TRUST_PROXY=1 when portknock sits behind a reverse proxy
# (nginx/Caddy). It makes the service read the real client IP from the last
# X-Forwarded-For hop instead of the proxy's 127.0.0.1. Only enable this when a
# trusted proxy is actually in front AND portknock listens on localhost, or
# anyone could spoof the header to whitelist arbitrary IPs.
TRUST_PROXY="${PORTKNOCK_TRUST_PROXY:-0}"
# Optional shared password for the user page: when set, visitors must enter it
# before their IP is granted. Empty = no gate (anyone who opens the page can grant).
GRANT_PASS="${PORTKNOCK_GRANT_PASSWORD:-}"
# Keep SSH reachable so enabling/using ufw can't lock you out. Set
# PORTKNOCK_SSH_PORT to override detection; set PORTKNOCK_NO_SSH=1 to skip.
SSH_PORT="${PORTKNOCK_SSH_PORT:-}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# SUDO is the prefix shown in hints printed to the user. On a machine without
# sudo (e.g. logged in as root directly) it's empty, so copied commands don't
# fail with "sudo: command not found".
if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo "
else
  SUDO=""
fi

need_root() { [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo）。"; }

gen_secret() { head -c "${1:-18}" /dev/urandom | base64 | tr -d '/+=' | cut -c1-"${2:-24}"; }

# ensure_ufw makes sure the ufw command is available, installing it via the
# system package manager when missing. Dies if it can't be installed, since the
# whole service is useless without ufw.
ensure_ufw() {
  command -v ufw >/dev/null 2>&1 && return
  say "未检测到 ufw，尝试自动安装 ..."
  # Run the install under `|| true` so a package-manager failure (e.g. no
  # network) falls through to the friendly check below instead of aborting
  # abruptly under `set -e`.
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ufw || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ufw || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ufw || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ufw || true
  elif command -v apk >/dev/null 2>&1; then
    apk add ufw || true
  else
    die "无法自动安装 ufw：未识别的包管理器，请手动安装后重试。"
  fi
  command -v ufw >/dev/null 2>&1 || die "ufw 自动安装失败（可能无网络或源问题），请手动安装后重试。"
  say "ufw 已安装。"
}

# check_port warns if the configured LISTEN port is already in use by a process
# other than portknock itself (so re-installs/upgrades don't false-alarm).
check_port() {
  local port="${LISTEN##*:}"
  case "$port" in (*[!0-9]*|'') return;; esac
  local line=""
  if command -v ss >/dev/null 2>&1; then
    line="$(ss -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p')"
  elif command -v netstat >/dev/null 2>&1; then
    line="$(netstat -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p')"
  else
    return  # no tool to check; skip quietly
  fi
  [ -z "$line" ] && return
  # Ignore if it's our own service already listening (upgrade case).
  printf '%s' "$line" | grep -q 'portknock' && return
  warn "端口 ${port} 似乎已被占用："
  printf '    %s\n' "$line" >&2
  warn "若非 portknock，启动可能失败。可用 PORTKNOCK_LISTEN=地址:端口 换一个端口重装，例如："
  warn "    curl -fsSL .../install.sh | ${SUDO}PORTKNOCK_LISTEN=0.0.0.0:8888 bash"
}

# --- install / update -------------------------------------------------------

cmd_install() {
  need_root
  command -v systemctl >/dev/null 2>&1 || die "需要 systemd（systemctl 未找到）。"
  # Re-resolve here too: the install wizard exports these AFTER the top-level
  # assignment ran, so pick up anything it set.
  TRUST_PROXY="${PORTKNOCK_TRUST_PROXY:-$TRUST_PROXY}"
  GRANT_PASS="${PORTKNOCK_GRANT_PASSWORD:-$GRANT_PASS}"
  SSH_PORT="${PORTKNOCK_SSH_PORT:-$SSH_PORT}"
  LISTEN="${PORTKNOCK_LISTEN:-$LISTEN}"
  ensure_ufw

  if command -v ufw >/dev/null 2>&1; then
    ver="$(ufw --version 2>/dev/null | awk '/ufw/{print $2; exit}')"
    if [ -n "${ver:-}" ]; then
      say "检测到 ufw ${ver}"
      if [ "$(printf '%s\n0.35\n' "$ver" | sort -V | head -n1)" != "0.35" ]; then
        warn "ufw ${ver} 可能过旧（需要 >= 0.35 以支持 comment）。"
      fi
    fi
  fi

  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "不支持的架构：$(uname -m)（仅提供 amd64/arm64）" ;;
  esac

  local asset="portknock-linux-${ARCH}"
  local url="https://github.com/${REPO}/releases/latest/download/${asset}"

  say "下载 ${asset} ..."
  local tmp; tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "$url" || { rm -f "$tmp"; die "下载失败：${url}（确认已打 v* tag 并生成 Release）"; }

  if curl -fsSL -o "$tmp.sha256" "${url}.sha256" 2>/dev/null; then
    local want got
    want="$(awk '{print $1}' "$tmp.sha256")"
    got="$(sha256sum "$tmp" | awk '{print $1}')"
    if [ -z "$want" ]; then
      warn "校验和文件为空，无法验证二进制完整性（继续安装）。"
    elif [ "$want" != "$got" ]; then
      rm -f "$tmp" "$tmp.sha256"
      die "校验和不匹配，已中止（期望 ${want}，实际 ${got}）。"
    else
      say "校验和 OK"
    fi
  else
    # Checksum fetch failed (network/CDN/attacker dropping just this object).
    # Don't silently skip — the release always publishes a .sha256, so warn loudly.
    warn "无法获取校验和文件（${url}.sha256），本次安装未验证二进制完整性。如介意请重试或手动核对。"
  fi

  install -m 0755 "$tmp" "$BIN_PATH"
  rm -f "$tmp" "$tmp.sha256"
  say "已安装二进制：${BIN_PATH}"
  mkdir -p "$STATE_DIR"

  # Install this script as portknock-ctl for later management.
  if [ -f "${BASH_SOURCE[0]:-}" ] && [ "${BASH_SOURCE[0]}" != "$CTL_PATH" ]; then
    install -m 0755 "${BASH_SOURCE[0]}" "$CTL_PATH" 2>/dev/null && say "管理命令已安装：${CTL_PATH}"
  else
    # Running via a pipe (curl | bash): fetch a copy for local use.
    if curl -fsSL -o "$CTL_PATH" "https://raw.githubusercontent.com/${REPO}/main/install.sh" 2>/dev/null; then
      chmod 0755 "$CTL_PATH"; say "管理命令已安装：${CTL_PATH}"
    fi
  fi

  local newcreds=0
  if [ ! -f "$ENV_FILE" ]; then
    umask 077
    cat > "$ENV_FILE" <<EOF
# portknock 运行配置（本文件含密钥，权限 600）
PORTKNOCK_ADMIN_PASS=$(gen_secret 18 24)
PORTKNOCK_API_KEY=$(gen_secret 24 32)
EOF
    chmod 600 "$ENV_FILE"
    newcreds=1
  else
    say "沿用已有配置：${ENV_FILE}"
  fi

  # If a user-page password was provided, set/replace it in the env file.
  if [ -n "$GRANT_PASS" ]; then
    sed -i '/^PORTKNOCK_GRANT_PASSWORD=/d' "$ENV_FILE"
    printf 'PORTKNOCK_GRANT_PASSWORD=%s\n' "$GRANT_PASS" >> "$ENV_FILE"
    say "已设置用户页放行口令。"
  fi

  seed_state
  allow_ssh
  allow_listen_port
  enable_ufw   # after the allow rules above, so enabling can't lock us out
  check_port

  write_service
  say "注册并启动服务 ..."
  systemctl daemon-reload
  systemctl enable --now portknock
  sleep 1
  systemctl is-active --quiet portknock || { journalctl -u portknock -n 20 --no-pager || true; die "服务未能启动，见上方日志。"; }

  echo
  say "✅ 部署完成。监听地址：${LISTEN}"
  # Always show credentials — on a fresh install they're newly generated, on an
  # upgrade/reinstall they're the existing ones, but either way the user wants
  # to see them here.
  print_creds
  if [ "$newcreds" != "1" ]; then
    echo "  （以上为已有密码，本次升级未改动；如需更换用 ${SUDO}portknock-ctl reset-password）"
  fi
  echo "  用户页：  https://${LISTEN}/"
  echo "  管理台：  https://${LISTEN}/admin"
  echo "  （HTTPS 自签证书，浏览器会提示不安全，点“继续/高级→仍然访问”即可）"
  echo "  SSH：     已放行 $(protected_ssh_port)/tcp（防锁死，仅此端口管理台删不掉）"
  if [ "$TRUST_PROXY" = "1" ]; then
    echo "  反代：    已启用 --trust-proxy（从 X-Forwarded-For 读取真实客户端 IP）"
  else
    echo "  反代：    未启用。若前面有 nginx/Caddy，请用 PORTKNOCK_TRUST_PROXY=1 重装，否则只会看到代理 IP"
  fi
  if [ -n "$GRANT_PASS" ]; then
    echo "  用户口令：已设置（访客需输入口令才能放行）"
  else
    echo "  用户口令：未设置（任何人打开用户页即可放行自己）。可用 PORTKNOCK_GRANT_PASSWORD=... 重装开启"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qi 'active'; then
    echo "  防火墙：  ufw 已启用，白名单规则生效中"
  fi
  echo
  echo "管理命令（直接运行 ${SUDO}portknock-ctl 不带参数可进交互菜单）："
  echo "  ${SUDO}portknock-ctl status          服务状态 + 白名单概览"
  echo "  ${SUDO}portknock-ctl urls            访问链接 + API 调用示例"
  echo "  ${SUDO}portknock-ctl creds           查看管理密码 / API 密钥"
  echo "  ${SUDO}portknock-ctl reset-password  重新生成密码并重启"
  echo "  ${SUDO}portknock-ctl update          升级到最新版本"
  echo "  ${SUDO}portknock-ctl logs            实时日志"
  echo "  ${SUDO}portknock-ctl restart         重启服务"
  echo "  ${SUDO}portknock-ctl backup [文件]   备份状态"
  echo "  ${SUDO}portknock-ctl uninstall       卸载（--purge 连状态密钥一起删）"
}

# Default publicly-open ports seeded into a fresh state.json (and allowed via
# the SSH-style install rules). Override with PORTKNOCK_DEFAULT_PORTS="80 443".
DEFAULT_PORTS="${PORTKNOCK_DEFAULT_PORTS:-80 443 22 222}"

# seed_state writes an initial state.json with DEFAULT_PORTS open, only if no
# state file exists yet (never clobbers an existing configuration).
seed_state() {
  [ -f "$STATE_FILE" ] && { say "沿用已有状态：${STATE_FILE}"; return; }
  local csv=""
  for p in $DEFAULT_PORTS; do
    case "$p" in (*[!0-9]*|'') continue;; esac
    [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || continue
    csv="${csv:+$csv, }$p"
  done
  mkdir -p "$STATE_DIR"
  cat > "$STATE_FILE" <<EOF
{
  "ports": [${csv}],
  "fixed_ips": [],
  "dynamic": []
}
EOF
  chmod 600 "$STATE_FILE"
  say "已预置默认开放端口：${DEFAULT_PORTS// /, }"
}

# detect_ssh_port prints the sshd listen port (first Port directive), else 22.
detect_ssh_port() {
  local p=""
  if [ -n "$SSH_PORT" ]; then echo "$SSH_PORT"; return; fi
  # Prefer the live sshd config; fall back to sshd_config file, then 22.
  if command -v sshd >/dev/null 2>&1; then
    p="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')" || true
  fi
  if [ -z "$p" ] && [ -f /etc/ssh/sshd_config ]; then
    p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config)" || true
  fi
  echo "${p:-22}"
}

# protected_ssh_port prints the single SSH port guarded against lockout. It
# follows the actually-detected sshd port (PORTKNOCK_SSH_PORT override > live
# sshd config > sshd_config > 22), so a non-standard SSH port is protected
# automatically. This is the ONLY port the installer makes undeletable; all
# other ports are normal and deletable from the panel.
protected_ssh_port() { detect_ssh_port; }

# allow_ssh opens the protected SSH port to any source with an install-managed
# ufw rule. The comment prefix is "portknock-install:" (NOT "portknock:"), so the
# app's reconcileAll never deletes it — you can't get locked out of SSH.
allow_ssh() {
  [ "${PORTKNOCK_NO_SSH:-0}" = "1" ] && { warn "按 PORTKNOCK_NO_SSH=1 跳过 SSH 防锁死放行。"; return; }
  command -v ufw >/dev/null 2>&1 || { warn "无 ufw，跳过 SSH 放行。"; return; }
  local p; p="$(protected_ssh_port)"
  case "$p" in (*[!0-9]*|'') warn "SSH 端口异常（$p），跳过。"; return;; esac

  local status; status="$(ufw status 2>/dev/null || true)"
  if printf '%s' "$status" | grep -q "portknock-install:ssh:${p}\b"; then
    say "SSH 端口 ${p} 已放行（防锁死规则存在）。"
    return
  fi
  if ufw allow "${p}/tcp" comment "portknock-install:ssh:${p}" >/dev/null 2>&1; then
    say "已放行 SSH 端口 ${p}/tcp（防锁死，管理台删不掉）。"
  else
    warn "放行 SSH 端口 ${p} 失败，请手动执行： ufw allow ${p}/tcp"
  fi
}

# allow_listen_port opens the web listen port when portknock binds to a public
# address, so enabling ufw doesn't block the panel itself. Uses an install-
# managed rule (comment "portknock-install:listen:<port>") so it survives
# upgrades and the panel can't delete it. Skipped for localhost binds (reached
# via SSH tunnel or a reverse proxy, which needs 80/443 instead).
allow_listen_port() {
  command -v ufw >/dev/null 2>&1 || return
  local host="${LISTEN%:*}" port="${LISTEN##*:}"
  case "$host" in
    127.0.0.1|localhost|::1|"") return ;;  # local-only: no rule needed
  esac
  case "$port" in (*[!0-9]*|'') return;; esac
  local status; status="$(ufw status 2>/dev/null || true)"
  if printf '%s' "$status" | grep -q "portknock-install:listen:${port}\b"; then
    say "监听端口 ${port} 已放行。"
    return
  fi
  if ufw allow "${port}/tcp" comment "portknock-install:listen:${port}" >/dev/null 2>&1; then
    say "已放行管理监听端口 ${port}/tcp（对外访问用，管理台删不掉）。"
  else
    warn "放行监听端口 ${port} 失败，请手动执行： ufw allow ${port}/tcp"
  fi
}

# enable_ufw turns ufw on so the whitelist rules actually take effect. MUST run
# only AFTER allow_ssh + allow_listen_port, so enabling can never lock us out of
# SSH or the management port. "ufw --force enable" skips the interactive y/n
# prompt (we've already opened the escape-hatch ports above).
enable_ufw() {
  command -v ufw >/dev/null 2>&1 || { warn "无 ufw，跳过启用。"; return; }
  local status; status="$(ufw status 2>/dev/null | head -1 || true)"
  if printf '%s' "$status" | grep -qi 'Status: active'; then
    say "ufw 已处于启用状态。"
    return
  fi
  if ufw --force enable >/dev/null 2>&1; then
    say "✅ 已启用 ufw 防火墙（白名单规则即刻生效）。"
  else
    warn "启用 ufw 失败，请手动执行： ${SUDO}ufw enable"
  fi
}

write_service() {
  local extra=""
  # Behind a reverse proxy, read the real client IP from X-Forwarded-For.
  [ "$TRUST_PROXY" = "1" ] && extra="${extra} --trust-proxy"
  cat > "$SERVICE" <<EOF
[Unit]
Description=portknock - web-based ufw IP whitelist
After=network-online.target
Wants=network-online.target

[Service]
User=root
# Ensure /usr/sbin (where ufw lives) is on PATH; systemd's default omits it.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} --listen ${LISTEN} --state ${STATE_FILE} --expiry 48h --poll 2m${extra}
Restart=on-failure
RestartSec=3
# ProtectSystem=full makes /etc read-only; ufw must write its rule files there,
# so allow-list the paths ufw and portknock need to write. The leading "-" on
# each optional path tells systemd to ignore it if it doesn't exist (paths vary
# by distro; a missing one would otherwise abort startup with 226/NAMESPACE).
ProtectSystem=full
ReadWritePaths=${STATE_DIR} /etc/ufw /etc/default -/lib/ufw -/var/lib/ufw -/run
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
}

# --- management subcommands -------------------------------------------------

print_creds() {
  [ -f "$ENV_FILE" ] || die "未找到 ${ENV_FILE}，服务可能尚未安装。"
  echo "  管理密码： $(grep PORTKNOCK_ADMIN_PASS "$ENV_FILE" | cut -d= -f2-)"
  echo "  API 密钥： $(grep PORTKNOCK_API_KEY "$ENV_FILE" | cut -d= -f2-)"
  echo "  （来自 ${ENV_FILE}）"
}

cmd_creds() { need_root; print_creds; }

# effective_listen reads the actual --listen value from the installed service
# (so it reflects what's really running), falling back to the script default.
effective_listen() {
  if [ -f "$SERVICE" ]; then
    local l
    l="$(grep -oE -- '--listen[ =][^ ]+' "$SERVICE" 2>/dev/null | head -n1 | sed -E 's/--listen[ =]//')"
    [ -n "${l:-}" ] && { echo "$l"; return; }
  fi
  echo "$LISTEN"
}

# cmd_urls prints the access URLs and a ready-to-run API example (with key).
cmd_urls() {
  need_root
  local listen host port base apikey
  listen="$(effective_listen)"
  host="${listen%:*}"; port="${listen##*:}"
  # A bind on 0.0.0.0/:: is reachable via the machine's public IP; 127.0.0.1 is
  # local-only (typically fronted by a reverse proxy).
  case "$host" in
    0.0.0.0|""|"::") host="<服务器IP或域名>" ;;
  esac
  base="https://${host}:${port}"   # service is HTTPS-only

  echo "  用户提交页： ${base}/"
  echo "  管理控制台： ${base}/admin"
  echo
  if [ -f "$ENV_FILE" ]; then
    apikey="$(grep PORTKNOCK_API_KEY "$ENV_FILE" | cut -d= -f2-)"
  fi
  # -k because the cert is self-signed.
  if [ -n "${apikey:-}" ]; then
    echo "  API 提交（放行调用方自己的 IP）："
    echo "    curl -k -X POST ${base}/api/grant \\"
    echo "         -H \"Authorization: Bearer ${apikey}\""
    echo
    echo "  API 提交（放行指定 IP）："
    echo "    curl -k -X POST ${base}/api/grant \\"
    echo "         -H \"Authorization: Bearer ${apikey}\" \\"
    echo "         -H \"Content-Type: application/json\" \\"
    echo "         -d '{\"ip\":\"203.0.113.9\"}'"
  else
    warn "未找到 API 密钥（${ENV_FILE}）；API 可能未配置。"
  fi
}

cmd_status() {
  systemctl status portknock --no-pager -l 2>/dev/null || warn "服务未安装或未运行。"
  echo
  if [ -f "$BIN_PATH" ]; then echo "二进制： $("$BIN_PATH" --version 2>/dev/null || echo '?') @ ${BIN_PATH}"; fi
  if [ -f "$STATE_FILE" ]; then
    echo "状态文件：${STATE_FILE}"
    # Summarize without jq: count occurrences in the JSON.
    local ports fixed dyn
    ports="$(grep -o '"ports"[^]]*]' "$STATE_FILE" 2>/dev/null | grep -o '[0-9]\+' | wc -l || echo 0)"
    fixed="$(grep -o '"fixed_ips"[^]]*]' "$STATE_FILE" 2>/dev/null | grep -o '"[0-9a-fA-F:.]\+"' | wc -l || echo 0)"
    dyn="$(grep -o '"ip"' "$STATE_FILE" 2>/dev/null | wc -l || echo 0)"
    echo "概览：   开放端口≈${ports}  固定IP≈${fixed}  动态IP≈${dyn}"
  fi
}

cmd_reset_password() {
  need_root
  [ -f "$ENV_FILE" ] || die "未找到 ${ENV_FILE}。"
  local pass apikey
  pass="$(gen_secret 18 24)"; apikey="$(gen_secret 24 32)"
  umask 077
  cat > "$ENV_FILE" <<EOF
# portknock 运行配置（本文件含密钥，权限 600）
PORTKNOCK_ADMIN_PASS=${pass}
PORTKNOCK_API_KEY=${apikey}
EOF
  chmod 600 "$ENV_FILE"
  systemctl restart portknock
  say "已生成新密码并重启。"
  print_creds
}

cmd_logs()    { need_root; journalctl -u portknock -f --no-pager; }
cmd_restart() { need_root; systemctl restart portknock && say "已重启。"; }

cmd_version() {
  [ -f "$BIN_PATH" ] || die "未安装。"
  "$BIN_PATH" --version 2>/dev/null || warn "二进制不支持 --version。"
}

cmd_backup() {
  need_root
  [ -f "$STATE_FILE" ] || die "无状态文件可备份。"
  local dest="${1:-./portknock-backup-$(date +%Y%m%d-%H%M%S).json}"
  cp "$STATE_FILE" "$dest"
  say "已备份到：${dest}"
}

cmd_restore() {
  need_root
  local src="${1:-}"
  [ -n "$src" ] && [ -f "$src" ] || die "用法：portknock-ctl restore <文件>"
  mkdir -p "$STATE_DIR"
  cp "$src" "$STATE_FILE"
  systemctl restart portknock 2>/dev/null || true
  say "已恢复并重启（防火墙规则会在启动时与状态对齐）。"
}

cmd_uninstall() {
  need_root
  local purge=0
  [ "${1:-}" = "--purge" ] && purge=1
  say "停止并移除服务 ..."
  systemctl disable --now portknock 2>/dev/null || true
  rm -f "$SERVICE"; systemctl daemon-reload 2>/dev/null || true
  rm -f "$BIN_PATH" "$CTL_PATH"
  if [ "$purge" = "1" ]; then
    rm -rf "$STATE_DIR"; rm -f "$ENV_FILE"
    # Remove our install-managed rules (purge means remove everything we added):
    # the SSH lockout-guard and any listen-port rule, found by their comments.
    if command -v ufw >/dev/null 2>&1; then
      ufw delete allow "$(protected_ssh_port)/tcp" >/dev/null 2>&1 || true
      local lp
      for lp in $(ufw status 2>/dev/null | awk '/portknock-install:listen:/{split($1,a,"/"); print a[1]}' | sort -u); do
        ufw delete allow "${lp}/tcp" >/dev/null 2>&1 || true
      done
    fi
    say "已彻底卸载（含状态、密钥与 install 放行的 SSH / 监听端口规则）。"
    warn "注意：应用运行期下发的 portknock: 规则不由本脚本清理；如需检查请看 'ufw status'。"
  else
    say "已卸载二进制与服务。状态 ${STATE_DIR} 与配置 ${ENV_FILE} 已保留（加 --purge 可一并删除）。"
  fi
}

# --- dispatch ---------------------------------------------------------------

run_cmd() {
  local cmd="$1"; shift || true
  case "$cmd" in
    install|update)   cmd_install ;;
    uninstall|remove) cmd_uninstall "$@" ;;
    status)           cmd_status ;;
    creds|password)   cmd_creds ;;
    urls|url|api)     cmd_urls ;;
    reset-password)   cmd_reset_password ;;
    logs|log)         cmd_logs ;;
    restart)          cmd_restart ;;
    backup)           cmd_backup "$@" ;;
    restore)          cmd_restore "$@" ;;
    version)          cmd_version ;;
    -h|--help|help)   sed -n '2,/^set -euo/{/^set -euo/!p}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) die "未知命令：$cmd（用 help 查看所有命令）" ;;
  esac
}

# installed reports whether portknock is already installed on this host.
installed() { [ -f "$BIN_PATH" ] && [ -f "$SERVICE" ]; }

# read_tty reads one line from the terminal and prints it. In a piped install
# (curl | bash) the shell's stdin is the script text, so reads must come from
# /dev/tty to reach the keyboard; when there's no tty, fall back to stdin.
read_tty() {
  local ans
  if [ -r /dev/tty ]; then
    read -r ans </dev/tty || return 1
  else
    read -r ans || return 1
  fi
  printf '%s' "$ans"
}

# ask prints a prompt (with a default shown) and reads an answer, echoing the
# default when the user just presses enter. The caller captures the answer with
# $(...), so the prompt must go to stderr — otherwise it'd be swallowed.
ask() {
  local prompt="$1" def="$2" ans
  printf '%s [%s]: ' "$prompt" "$def" >&2
  ans="$(read_tty)" || ans=""
  echo "${ans:-$def}"
}

# install_wizard interactively collects config, then runs cmd_install with the
# answers exported as the same env vars the piped installer honors. Used by the
# menu's "install" entry so first-time setup is guided.
install_wizard() {
  echo
  say "安装向导（直接回车用方括号内的默认值）"
  echo "  ----------------------------------------"

  # 1) 对外还是仅本机
  local scope host
  echo "  监听范围：1) 仅本机 127.0.0.1（最安全，需 SSH 隧道/反代访问）"
  echo "            2) 对外 0.0.0.0（可用 https://服务器IP 直接访问）"
  scope="$(ask "  选择 1 或 2" "1")"
  case "$scope" in
    2) host="0.0.0.0" ;;
    *) host="127.0.0.1" ;;
  esac

  # 2) 端口
  local port; port="$(ask "  监听端口" "8080")"
  case "$port" in (*[!0-9]*|'') warn "端口无效，用 8080。"; port=8080 ;; esac
  export PORTKNOCK_LISTEN="${host}:${port}"

  # 3) SSH 端口（防锁死保护口，默认自动探测）
  local detected; detected="$(detect_ssh_port)"
  local sshp; sshp="$(ask "  受防锁死保护的 SSH 端口" "$detected")"
  [ "$sshp" != "$detected" ] && export PORTKNOCK_SSH_PORT="$sshp"

  # 4) 反代
  local proxy; proxy="$(ask "  是否在 nginx/Caddy 反代后面？(y/N)" "N")"
  case "$proxy" in
    y|Y) export PORTKNOCK_TRUST_PROXY=1 ;;
  esac

  # 5) 用户页放行口令（可选，回车跳过 = 无门槛）
  local gp; gp="$(ask "  用户页放行口令（留空=任何人可放行）" "")"
  [ -n "$gp" ] && export PORTKNOCK_GRANT_PASSWORD="$gp"

  echo "  ----------------------------------------"
  say "即将安装：监听 ${PORTKNOCK_LISTEN}  SSH保护 ${sshp}  反代 ${PORTKNOCK_TRUST_PROXY:-0}"
  local go; go="$(ask "  确认开始？(Y/n)" "Y")"
  case "$go" in
    n|N) warn "已取消。"; return 0 ;;
  esac
  cmd_install
}

# menu shows an interactive menu (only on a real terminal with no subcommand).
menu() {
  while true; do
    echo
    printf '\033[1;36m╔══════════════════════════════════════╗\033[0m\n'
    printf '\033[1;36m║        portknock 管理菜单            ║\033[0m\n'
    printf '\033[1;36m╚══════════════════════════════════════╝\033[0m\n'
    if installed; then
      local act="已安装"; systemctl is-active --quiet portknock 2>/dev/null && act="运行中" || act="已停止"
      echo "  状态：${act}    监听：$(effective_listen)"
    else
      echo "  状态：未安装"
    fi
    echo "  --------------------------------------"
    echo "   1) 引导安装 / 升级"
    echo "   2) 查看状态与白名单概览"
    echo "   3) 查看访问链接 / API 调用示例"
    echo "   4) 查看管理密码 / API 密钥"
    echo "   5) 重置管理密码"
    echo "   6) 查看实时日志"
    echo "   7) 重启服务"
    echo "   8) 备份状态"
    echo "   9) 恢复状态"
    echo "  10) 卸载"
    echo "   0) 退出"
    echo "  --------------------------------------"
    printf "请选择 [0-10]: "
    # Read from the terminal (stdin is the script text under curl|bash). A failed
    # read means EOF/closed tty — leave the menu instead of looping forever.
    local choice
    if [ -r /dev/tty ]; then
      read -r choice </dev/tty || { echo; return 0; }
    else
      read -r choice || { echo; return 0; }
    fi
    case "$choice" in
      1) install_wizard ;;
      2) run_cmd status ;;
      3) run_cmd urls ;;
      4) run_cmd creds ;;
      5) run_cmd reset-password ;;
      6) run_cmd logs ;;
      7) run_cmd restart ;;
      8) run_cmd backup ;;
      9)
        printf "请输入备份文件路径: "; local f; f="$(read_tty)"
        [ -n "${f:-}" ] && run_cmd restore "$f" || warn "未输入路径，已取消。"
        ;;
      10)
        printf "确认卸载？彻底删除(含状态与密钥)请输入 purge，仅卸载请输入 y，其它取消: "
        local c; c="$(read_tty)"
        case "$c" in
          purge) run_cmd uninstall --purge ;;
          y|Y)   run_cmd uninstall ;;
          *)     warn "已取消。" ;;
        esac
        ;;
      0) echo "再见。"; return 0 ;;
      *) warn "无效选择：$choice" ;;
    esac
    printf "\n按回车返回菜单..."; read_tty >/dev/null || return 0
  done
}

main() {
  # An explicit subcommand always runs directly, so automation like
  # `... | bash -s -- install` and `portknock-ctl status` stays non-interactive.
  if [ "$#" -gt 0 ]; then
    run_cmd "$@"
    return
  fi
  # No arguments: show the interactive menu, even for the piped one-liner
  # (curl | bash). When piped, stdin is the script itself, so reattach it to the
  # controlling terminal. If there's no terminal at all (truly unattended, e.g.
  # CI), fall back to a direct install so it never hangs waiting for input.
  if [ -t 0 ]; then
    menu
  elif { : </dev/tty; } 2>/dev/null; then
    exec </dev/tty
    menu
  else
    run_cmd install
  fi
}

main "$@"
