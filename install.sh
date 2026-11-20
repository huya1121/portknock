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
# Keep SSH reachable so enabling/using ufw can't lock you out. Set
# PORTKNOCK_SSH_PORT to override detection; set PORTKNOCK_NO_SSH=1 to skip.
SSH_PORT="${PORTKNOCK_SSH_PORT:-}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo）。"; }

gen_secret() { head -c "${1:-18}" /dev/urandom | base64 | tr -d '/+=' | cut -c1-"${2:-24}"; }

# --- install / update -------------------------------------------------------

cmd_install() {
  need_root
  command -v systemctl >/dev/null 2>&1 || die "需要 systemd（systemctl 未找到）。"
  command -v ufw >/dev/null 2>&1 || warn "未检测到 ufw，请先安装并启用：apt install ufw && ufw enable"

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
    [ "$want" = "$got" ] || die "校验和不匹配，已中止。"
    say "校验和 OK"
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

  seed_state
  allow_ssh

  write_service
  say "注册并启动服务 ..."
  systemctl daemon-reload
  systemctl enable --now portknock
  sleep 1
  systemctl is-active --quiet portknock || { journalctl -u portknock -n 20 --no-pager || true; die "服务未能启动，见上方日志。"; }

  echo
  say "✅ 部署完成。监听地址：${LISTEN}"
  if [ "$newcreds" = "1" ]; then
    print_creds
  fi
  echo "  用户页：  http://${LISTEN}/"
  echo "  管理台：  http://${LISTEN}/admin"
  echo "  SSH：     已放行 $(protected_ssh_port)/tcp（防锁死，仅此端口管理台删不掉）"
  if [ "$TRUST_PROXY" = "1" ]; then
    echo "  反代：    已启用 --trust-proxy（从 X-Forwarded-For 读取真实客户端 IP）"
  else
    echo "  反代：    未启用。若前面有 nginx/Caddy，请用 PORTKNOCK_TRUST_PROXY=1 重装，否则只会看到代理 IP"
  fi
  echo
  echo "以后可用： sudo portknock-ctl status | creds | update | uninstall | logs"
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

# protected_ssh_port prints the single SSH port guarded against lockout: 22 by
# default (override with PORTKNOCK_SSH_PORT). This is the ONLY port the installer
# makes undeletable; all other ports (80/443/222/…) are normal, deletable.
protected_ssh_port() { echo "${SSH_PORT:-22}"; }

# allow_ssh opens the protected SSH port to any source with an install-managed
# ufw rule. The comment prefix is "portknock-install:" (NOT "portknock:"), so the
# app's reconcileAll never deletes it — you can't get locked out of SSH.
allow_ssh() {
  [ "${PORTKNOCK_NO_SSH:-0}" = "1" ] && { warn "按 PORTKNOCK_NO_SSH=1 跳过 SSH 防锁死放行。"; return; }
  command -v ufw >/dev/null 2>&1 || { warn "无 ufw，跳过 SSH 放行。"; return; }
  local p; p="$(protected_ssh_port)"
  case "$p" in (*[!0-9]*|'') warn "SSH 端口异常（$p），跳过。"; return;; esac

  # If sshd actually listens elsewhere, 22 alone may not protect you — warn.
  local real; real="$(detect_ssh_port)"
  if [ "$real" != "$p" ]; then
    warn "检测到 sshd 实际端口为 ${real}，但防锁死规则只保护 ${p}。如需保护 ${real}，请手动： ufw allow ${real}/tcp"
  fi

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

write_service() {
  local extra=""
  # A reverse proxy implies HTTPS is terminated in front, so mark cookies Secure.
  # Plain-HTTP installs leave Secure off, or browsers would drop the CSRF/session
  # cookie and every form POST would fail.
  [ "$TRUST_PROXY" = "1" ] && extra=" --trust-proxy --secure-cookie=true"
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
ReadWritePaths=${STATE_DIR} /etc/ufw -/lib/ufw -/var/lib/ufw -/run
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
  local listen host port scheme base apikey
  listen="$(effective_listen)"
  host="${listen%:*}"; port="${listen##*:}"
  # A bind on 0.0.0.0/:: is reachable via the machine's public IP; 127.0.0.1 is
  # local-only (typically fronted by a reverse proxy).
  case "$host" in
    0.0.0.0|""|"::") host="<服务器IP或域名>" ;;
  esac
  scheme="http"
  grep -q -- '--secure-cookie=true' "$SERVICE" 2>/dev/null && scheme="https"
  base="${scheme}://${host}:${port}"

  echo "  用户提交页： ${base}/"
  echo "  管理控制台： ${base}/admin"
  echo
  if [ -f "$ENV_FILE" ]; then
    apikey="$(grep PORTKNOCK_API_KEY "$ENV_FILE" | cut -d= -f2-)"
  fi
  if [ -n "${apikey:-}" ]; then
    echo "  API 提交（放行调用方自己的 IP）："
    echo "    curl -X POST ${base}/api/grant \\"
    echo "         -H \"Authorization: Bearer ${apikey}\""
    echo
    echo "  API 提交（放行指定 IP）："
    echo "    curl -X POST ${base}/api/grant \\"
    echo "         -H \"Authorization: Bearer ${apikey}\" \\"
    echo "         -H \"Content-Type: application/json\" \\"
    echo "         -d '{\"ip\":\"203.0.113.9\"}'"
  else
    warn "未找到 API 密钥（${ENV_FILE}）；API 可能未配置。"
  fi
  if [ "$scheme" = "http" ] && [ "$host" != "127.0.0.1" ]; then
    echo
    warn "当前为明文 HTTP。生产环境建议前置 nginx/Caddy 终止 HTTPS，并用 PORTKNOCK_TRUST_PROXY=1 重装。"
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
    # Remove our install-managed SSH rule (purge means remove everything we added).
    if command -v ufw >/dev/null 2>&1; then
      ufw delete allow "$(protected_ssh_port)/tcp" >/dev/null 2>&1 || true
    fi
    say "已彻底卸载（含状态、密钥与 install 放行的 SSH 规则）。"
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
    echo "   1) 安装 / 升级"
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
    local choice; read -r choice || { echo; return 0; }
    case "$choice" in
      1) run_cmd install ;;
      2) run_cmd status ;;
      3) run_cmd urls ;;
      4) run_cmd creds ;;
      5) run_cmd reset-password ;;
      6) run_cmd logs ;;
      7) run_cmd restart ;;
      8) run_cmd backup ;;
      9)
        printf "请输入备份文件路径: "; local f; read -r f
        [ -n "${f:-}" ] && run_cmd restore "$f" || warn "未输入路径，已取消。"
        ;;
      10)
        printf "确认卸载？彻底删除(含状态与密钥)请输入 purge，仅卸载请输入 y，其它取消: "
        local c; read -r c
        case "$c" in
          purge) run_cmd uninstall --purge ;;
          y|Y)   run_cmd uninstall ;;
          *)     warn "已取消。" ;;
        esac
        ;;
      0) echo "再见。"; return 0 ;;
      *) warn "无效选择：$choice" ;;
    esac
    printf "\n按回车返回菜单..."; read -r _ || return 0
  done
}

main() {
  # With an explicit subcommand (or piped via curl|bash), run it directly so the
  # one-line install command is unaffected. Only drop into the interactive menu
  # when run with no arguments on a real terminal.
  if [ "$#" -gt 0 ]; then
    run_cmd "$@"
    return
  fi
  if [ -t 0 ] && [ -t 1 ]; then
    menu
  else
    run_cmd install
  fi
}

main "$@"

