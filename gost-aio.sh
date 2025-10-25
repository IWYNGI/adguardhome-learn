#!/usr/bin/env bash
set -euo pipefail

# GOST v3 安装/卸载/交互配置一体脚本（TLS/WS/WSS + KCP/QUIC/SSH，TCP+UDP）
# 菜单：
# 1 安装/更新   2 卸载
# 3 直连转发(可选UDP)
# 4 加密隧道客户端 (tls/ws/wss，默认开启 UDP，本地同端口 TCP+UDP)
# 5 加密隧道服务端 (tls/ws/wss，服务仅 TCP 监听；UDP 为隧道封装)
# 6 加密隧道客户端 (kcp/quic/ssh，默认开启 UDP，本地同端口 TCP+UDP)
# 7 加密隧道服务端 (kcp=UDP / quic=UDP / ssh=TCP)
# 8 代理服务 (HTTP/SOCKS5；SOCKS5 可选 UDP)
# 9 查看 YAML   10 清空重建
# 12 重启并显示状态

BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/gost"
MAIN_CONF="$CONF_DIR/config.yaml"
SERV_D="$CONF_DIR/services.d"
CHAIN_D="$CONF_DIR/chains.d"
SERVICE="/etc/systemd/system/gost.service"
SERVICE_TPL="/etc/systemd/system/gost@.service"

green(){ printf "\033[32m%s\033[0m\n" "$*"; }
red(){   printf "\033[31m%s\033[0m\n" "$*" >&2; }
cyan(){  printf "\033[36m%s\033[0m\n" "$*"; }
ok(){    green "[OK] $*"; }
fail(){  red   "[FAIL] $*"; }
info(){  cyan  "[*] $*"; }

need_root(){ [[ $EUID -eq 0 ]] || { fail "需要 root"; exit 1; }; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || { fail "缺少依赖: $1"; exit 1; }; }
yaml_escape(){ sed 's/\\/\\\\/g;s/"/\\"/g' <<<"$1"; }

read_clean(){ local p="$1" v; read -r -p "$p" v; v=$(printf '%s' "$v" | LC_ALL=C tr -cd '\011\012\015\040-\176'); v=${v//$'\r'/}; v=$(printf '%s' "$v" | sed 's/^[[:space:]]\+//;s/[[:space:]]\+$//'); printf '%s' "$v"; }
read_ws_host(){ local v; v="$(read_clean "Host 伪装(可空): ")"; v=$(printf '%s' "$v" | LC_ALL=C tr -cd 'A-Za-z0-9\.\-'); printf '%s' "$v"; }

valid_hostport(){ local s="$1" p; if [[ "$s" =~ ^\[?[0-9A-Fa-f:.]+\]?:[0-9]{1,5}$ || "$s" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]]; then p="${s##*:}"; (( p>=1 && p<=65535 )) || return 1; return 0; fi; return 1; }
read_hostport(){ local p="$1" v; v="$(read_clean "$p")"; v="${v#tcp://}"; v="${v#udp://}"; v="${v#http://}"; v="${v#https://}"; v=$(printf '%s' "$v" | LC_ALL=C tr -cd 'A-Za-z0-9\.\-\:\[\]'); valid_hostport "$v" || { fail "格式应为 host:port"; return 1; }; printf '%s' "$v"; }

has_ss(){ command -v ss >/dev/null 2>&1; }
is_listen_tcp(){ local p="$1"; if has_ss; then ss -Hntl "sport = :$p" 2>/dev/null | grep -q .; else netstat -ltn 2>/dev/null | awk -v p="$p" 'NR>2{split($4,a,":"); if(a[length(a)]==p){print; exit 0}} END{exit 1}'; fi; }
is_listen_udp(){ local p="$1"; if has_ss; then ss -Hnul "sport = :$p" 2>/dev/null | grep -q .; else netstat -lun 2>/dev/null | awk -v p="$p" 'NR>2{split($4,a,":"); if(a[length(a)]==p){print; exit 0}} END{exit 1}'; fi; }
ensure_port_free(){ local proto="$1" port="$2"; if [[ "$proto" == tcp ]]; then is_listen_tcp "$port" && { fail "TCP $port 已占用"; return 1; } || ok "tcp/$port 可用"; else is_listen_udp "$port" && { fail "UDP $port 已占用"; return 1; } || ok "udp/$port 可用"; fi; }

wait_listen(){ # 不吐日志，失败给排错指令
  local proto="$1" port="$2" tries=48
  for _ in $(seq 1 $tries); do
    if [[ "$proto" == tcp ]]; then is_listen_tcp "$port" && { ok "已监听 tcp/$port"; return 0; }
    else is_listen_udp "$port" && { ok "已监听 udp/$port"; return 0; }
    fi
    sleep 0.25
  done
  fail "未检测到监听 $proto/$port"; tips_troubleshoot; return 1
}

tips_troubleshoot(){
  cat >&2 <<'TIPS'
排错建议：
  1) 查看服务状态：    systemctl status gost --no-pager
  2) 看最近日志：      journalctl -u gost -n 200 --no-pager
  3) 看端口监听：
       ss -ltnp | grep gost
       ss -lunp | grep gost
  4) 校验 YAML：       sed -n '1,300p' /etc/gost/config.yaml
TIPS
}

ensure_dirs(){ mkdir -p "$CONF_DIR"; :> "$SERV_D"; :> "$CHAIN_D"; :> "$MAIN_CONF"; }
sanitize_yaml(){ local f="$MAIN_CONF"; sed -i '1s/^\xEF\xBB\xBF//' "$f" || true; sed -i 's/\r$//' "$f" || true; sed -i 's/�//g' "$f" || true; command -v iconv >/dev/null 2>&1 && iconv -f UTF-8 -t UTF-8 -c "$f" -o "$f.tmp" && mv "$f.tmp" "$f" || true; }
rebuild_yaml(){ { printf "services:\n\n"; [[ -s "$SERV_D"  ]] && sed 's/^/  /' "$SERV_D"; printf "\nchains:\n\n"; [[ -s "$CHAIN_D" ]] && sed 's/^/  /' "$CHAIN_D"; printf "\n"; } > "$MAIN_CONF"; sanitize_yaml; }
append_service(){ printf "%s\n\n" "$1" >>"$SERV_D"; rebuild_yaml; ok "写入 services 成功"; }
append_chain(){   printf "%s\n\n" "$1" >>"$CHAIN_D"; rebuild_yaml; ok "写入 chains 成功"; }

compute_nofile(){
  local nr_open hard target
  nr_open=$(cat /proc/sys/fs/nr_open 2>/dev/null || echo 1048576)
  hard=$(ulimit -Hn 2>/dev/null || echo 1048576)
  [[ "$hard" == "unlimited" ]] && hard="$nr_open"
  [[ "$hard" =~ ^[0-9]+$ ]] || hard=1048576
  target=524288
  (( target>nr_open )) && target=$nr_open
  (( target>hard )) && target=$hard
  (( target<65536 )) && target=65536
  echo "$target"
}

systemd_units(){
  local NOFILE; NOFILE="$(compute_nofile)"
  cat >"$SERVICE" <<UNIT
[Unit]
Description=GOST Service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost -D -C /etc/gost/config.yaml
Restart=always
RestartSec=2s
LimitNOFILE=$NOFILE
[Install]
WantedBy=multi-user.target
UNIT

  cat >"$SERVICE_TPL" <<UNIT
[Unit]
Description=GOST Service Instance %i
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost -D -C /etc/gost/%i.yaml
Restart=always
RestartSec=2s
LimitNOFILE=$NOFILE
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

force_fix_limits_and_restart(){
  # 兜底：若仍未运行，降到 262144 再试
  if ! systemctl is-active --quiet gost.service; then
    sed -i 's/^LimitNOFILE=.*/LimitNOFILE=262144/' "$SERVICE" 2>/dev/null || true
    sed -i 's/^LimitNOFILE=.*/LimitNOFILE=262144/' "$SERVICE_TPL" 2>/dev/null || true
    systemctl daemon-reload
    systemctl restart gost.service || true
  fi
}

service_enable_restart(){
  systemctl daemon-reload
  systemctl enable --now gost.service >/dev/null 2>&1 || true
  systemctl restart gost.service || true
  if systemctl is-active --quiet gost.service; then
    ok "服务运行中"
  else
    fail "服务未运行，尝试自动修正文件句柄上限"
    force_fix_limits_and_restart
    if systemctl is-active --quiet gost.service; then
      ok "服务运行中（已自动降低 LimitNOFILE）"
    else
      fail "服务未运行"
      tips_troubleshoot
    fi
  fi
}

service_restart_status(){
  systemctl daemon-reload
  systemctl restart gost.service || true
  if systemctl is-active --quiet gost.service; then
    ok "服务运行中"
  else
    fail "服务未运行，尝试自动修正文件句柄上限"
    force_fix_limits_and_restart
    systemctl --no-pager status gost.service || true
    return
  fi
  systemctl --no-pager status gost.service
}

# ---------- 安装/卸载 ----------
install_or_update(){
  info "安装/更新 GOST v3"
  need_cmd tar; command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { fail "需要 curl 或 wget"; exit 1; }
  local JSON URL TAG ARCH ALT
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;; aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv7) ARCH="armv7" ;; armv6l|armv6) ARCH="armv6" ;;
    armv5l|armv5) ARCH="armv5" ;; i386|i686) ARCH="386" ;; *) fail "未支持架构: $(uname -m)"; exit 1 ;;
  esac
  ALT="$ARCH"; [[ "$ARCH" == "amd64" && "${GOST_PREFERRED_AMD64:-}" == "v3" ]] && ARCH="amd64v3"
  if command -v curl >/dev/null 2>&1; then JSON="$(curl -fsSL https://api.github.com/repos/go-gost/gost/releases/latest)"; else JSON="$(wget -qO- https://api.github.com/repos/go-gost/gost/releases/latest)"; fi
  TAG="$(echo "$JSON" | { command -v jq >/dev/null 2>&1 && jq -r '.tag_name'; } || echo "$JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')" || true
  URL="$(echo "$JSON" | (command -v jq >/dev/null 2>&1 && jq -r --arg a "$ARCH" --arg b "$ALT" '.assets[]?.browser_download_url|select(test("_linux_"+$a+"\\.tar\\.gz$")) // select(test("_linux_"+$b+"\\.tar\\.gz$"))' || grep -oE 'https://[^"]+\.tar\.gz' | grep -E "_linux_(${ARCH}|${ALT})\.tar\.gz$") | head -n1)"
  [[ -z "$URL" ]] && { fail "未找到发行包"; exit 1; }
  local TMP; TMP="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$TMP/gost.tar.gz" "$URL"; else wget -q -O "$TMP/gost.tar.gz" "$URL"; fi
  tar -C "$TMP" -xzf "$TMP/gost.tar.gz"
  install -m 0755 "$TMP/gost" "$BIN_DIR/gost"
  [[ -d "$CONF_DIR" ]] || ensure_dirs
  rebuild_yaml
  [[ -f "$SERVICE" ]] || systemd_units
  service_enable_restart
  "$BIN_DIR/gost" -V >/dev/null 2>&1 && ok "安装/更新完成 $TAG" || fail "gost -V 失败"
}
uninstall_all(){ info "完全卸载"; systemctl disable --now gost.service >/dev/null 2>&1 || true; systemctl disable --now 'gost@*'.service >/dev/null 2>&1 || true; rm -f "$SERVICE" "$SERVICE_TPL" || true; systemctl daemon-reload || true; rm -f "$BIN_DIR/gost" || true; [[ -d "$CONF_DIR" ]] && rm -rf "$CONF_DIR" || true; ok "已移除二进制/units/配置"; }

# ---------- 业务功能 ----------
# 3 直连（可选 UDP）
case1_nonencrypt(){
  local LPORT DST UDP
  LPORT="$(read_clean "本机监听端口: ")"; ensure_port_free tcp "$LPORT" || return 1
  DST="$(read_hostport "目标(例 1.2.3.4:8000): ")" || return 1
  UDP="$(read_clean "启用 UDP? [y/N]: ")"; [[ ${UDP:-N} =~ ^[Yy]$ ]] && ensure_port_free udp "$LPORT" || true
  append_service "$(cat <<EOF
- name: pf-tcp-$LPORT
  addr: ":$LPORT"
  handler: { type: tcp }
  listener: { type: tcp }
  forwarder:
    nodes:
      - { name: target-0, addr: "$(yaml_escape "$DST")" }
EOF
)"
  if [[ ${UDP:-N} =~ ^[Yy]$ ]]; then
    append_service "$(cat <<EOF
- name: pf-udp-$LPORT
  addr: ":$LPORT"
  handler: { type: udp }
  listener: { type: udp }
  forwarder:
    nodes:
      - { name: target-0, addr: "$(yaml_escape "$DST")" }
EOF
)"
  fi
  service_enable_restart
  local okall=0
  systemctl is-active --quiet gost.service || okall=1
  wait_listen tcp "$LPORT" || okall=1
  [[ ${UDP:-N} =~ ^[Yy]$ ]] && { wait_listen udp "$LPORT" || okall=1; }
  (( okall==0 )) && ok "直连配置就绪" || fail "直连配置异常"; (( okall==0 )) || tips_troubleshoot
}

# 4 加密隧道客户端 (tls/ws/wss，默认开启 UDP，本地同端口 TCP+UDP)
case2_encrypt_forward(){
  local LPORT SCHEME UP HOST_META="" H CH okall=0
  LPORT="$(read_clean "本机监听端口: ")"
  ensure_port_free tcp "$LPORT" || return 1
  ensure_port_free udp "$LPORT" || return 1
  SCHEME="$(read_clean "上游类型 (tls/ws/wss): ")"; case "$SCHEME" in tls|ws|wss) ;; *) fail "无效类型"; return 1;; esac
  UP="$(read_hostport "上游中继(域名或IP:端口): ")" || return 1
  if [[ "$SCHEME" =~ ^ws|wss$ ]]; then H="$(read_ws_host)"; [[ -n "$H" ]] && HOST_META=$'          metadata:\n            host: '"$(yaml_escape "$H")"$'\n'; fi
  CH="chain-${SCHEME}-${LPORT}"
  if [[ -n "$HOST_META" ]]; then
    append_chain "$(cat <<EOF
- name: $CH
  hops:
    - name: hop-0
      nodes:
        - name: node-0
          addr: "$(yaml_escape "$UP")"
          connector: { type: relay }
          dialer:
            type: $SCHEME
$HOST_META
EOF
)"
  else
    append_chain "$(cat <<EOF
- name: $CH
  hops:
    - name: hop-0
      nodes:
        - name: node-0
          addr: "$(yaml_escape "$UP")"
          connector: { type: relay }
          dialer: { type: $SCHEME }
EOF
)"
  fi
  append_service "$(cat <<EOF
- name: enc-${SCHEME}-tcp-$LPORT
  addr: ":$LPORT"
  handler: { type: tcp, chain: "$CH" }
  listener: { type: tcp }
EOF
)"
  append_service "$(cat <<EOF
- name: enc-${SCHEME}-udp-$LPORT
  addr: ":$LPORT"
  handler: { type: udp, chain: "$CH" }
  listener: { type: udp }
EOF
)"
  service_enable_restart
  systemctl is-active --quiet gost.service || okall=1
  wait_listen tcp "$LPORT" || okall=1
  wait_listen udp "$LPORT" || okall=1
  (( okall==0 )) && ok "加密客户端就绪" || fail "加密客户端异常"; (( okall==0 )) || tips_troubleshoot
}

# 5 加密隧道服务端 (tls/ws/wss)，服务仅 TCP 监听（UDP 为隧道封装），handler=relay
case3_land_simple(){
  local LTYPE LPORT DST CERT KEY TLS_BLOCK="" okall=0
  LTYPE="$(read_clean "入站类型 (tls/ws/wss): ")"; case "$LTYPE" in tls|ws|wss) ;; *) fail "无效类型"; return 1;; esac
  LPORT="$(read_clean "本机监听端口: ")"
  ensure_port_free tcp "$LPORT" || return 1   # 仅 TCP
  DST="$(read_hostport "解密后转发目标(例 127.0.0.1:18080): ")" || return 1
  if [[ "$LTYPE" == tls || "$LTYPE" == wss ]]; then
    CERT="$(read_clean "证书路径(PEM，可空): ")"; KEY="$(read_clean "私钥路径(PEM，可空): ")"
    if [[ -n "$CERT" ]]; then [[ -r "$CERT" ]] || { fail "证书不可读"; return 1; }; [[ -z "$KEY" || -r "$KEY" ]] || { fail "私钥不可读"; return 1; }; TLS_BLOCK=$'  tls:\n    certFile: '"$(yaml_escape "$CERT")"$'\n    keyFile: '"$(yaml_escape "$KEY")"$'\n'; fi
  fi
  append_service "$(cat <<EOF
- name: dec-$LTYPE-$LPORT
  addr: ":$LPORT"
  listener:
    type: $LTYPE
$TLS_BLOCK  handler:
    type: relay
  forwarder:
    nodes:
      - { name: target-0, addr: "$(yaml_escape "$DST")" }
EOF
)"
  service_enable_restart
  systemctl is-active --quiet gost.service || okall=1
  wait_listen tcp "$LPORT" || okall=1   # 不检查 UDP，避免误报
  (( okall==0 )) && ok "加密服务端就绪" || fail "加密服务端异常"; (( okall==0 )) || tips_troubleshoot
}

# 6 加密隧道客户端 (kcp/quic/ssh，默认开启 UDP，本地同端口 TCP+UDP)
case6_tunnel_client(){
  local LPORT SCHEME UP CH okall=0
  LPORT="$(read_clean "本机监听端口: ")"
  ensure_port_free tcp "$LPORT" || return 1
  ensure_port_free udp "$LPORT" || return 1
  SCHEME="$(read_clean "上游隧道类型 (kcp/quic/ssh): ")"; case "$SCHEME" in kcp|quic|ssh) ;; *) fail "无效类型"; return 1;; esac
  UP="$(read_hostport "隧道服务端(域名或IP:端口): ")" || return 1
  CH="chain-${SCHEME}-${LPORT}"
  append_chain "$(cat <<EOF
- name: $CH
  hops:
    - name: hop-0
      nodes:
        - name: node-0
          addr: "$(yaml_escape "$UP")"
          connector: { type: relay }
          dialer: { type: $SCHEME }
EOF
)"
  append_service "$(cat <<EOF
- name: enc-${SCHEME}-tcp-$LPORT
  addr: ":$LPORT"
  handler: { type: tcp, chain: "$CH" }
  listener: { type: tcp }
EOF
)"
  append_service "$(cat <<EOF
- name: enc-${SCHEME}-udp-$LPORT
  addr: ":$LPORT"
  handler: { type: udp, chain: "$CH" }
  listener: { type: udp }
EOF
)"
  service_enable_restart
  systemctl is-active --quiet gost.service || okall=1
  wait_listen tcp "$LPORT" || okall=1
  wait_listen udp "$LPORT" || okall=1
  (( okall==0 )) && ok "隧道客户端就绪" || fail "隧道客户端异常"; (( okall==0 )) || tips_troubleshoot
}

# 7 加密隧道服务端 (kcp/quic/ssh)，kcp/quic=UDP监听，ssh=TCP监听，handler=relay
case7_tunnel_server(){
  local LTYPE LPORT DST okall=0
  LTYPE="$(read_clean "入站隧道类型 (kcp/quic/ssh): ")"; case "$LTYPE" in kcp|quic|ssh) ;; *) fail "无效类型"; return 1;; esac
  LPORT="$(read_clean "本机监听端口: ")"
  if [[ "$LTYPE" == "ssh" ]]; then ensure_port_free tcp "$LPORT" || return 1; else ensure_port_free udp "$LPORT" || return 1; fi
  DST="$(read_hostport "解密后直转目标(例 127.0.0.1:23333): ")" || return 1
  append_service "$(cat <<EOF
- name: dec-$LTYPE-$LPORT
  addr: ":$LPORT"
  listener:
    type: $LTYPE
  handler:
    type: relay
  forwarder:
    nodes:
      - { name: target-0, addr: "$(yaml_escape "$DST")" }
EOF
)"
  service_enable_restart
  systemctl is-active --quiet gost.service || okall=1
  if [[ "$LTYPE" == "ssh" ]]; then
    wait_listen tcp "$LPORT" || okall=1
  else
    wait_listen udp "$LPORT" || okall=1
  fi
  (( okall==0 )) && ok "隧道服务端就绪" || fail "隧道服务端异常"; (( okall==0 )) || tips_troubleshoot
}

# 8 代理（HTTP / SOCKS5；SOCKS5 可选 UDP）
case8_proxy(){
  local HT LPORT AUTH="" U P ENABLE_UDP="N" okall=0
  HT="$(read_clean "代理类型 (http/socks5): ")"; case "$HT" in http|socks5) ;; *) fail "无效类型"; return 1;; esac
  LPORT="$(read_clean "本机监听端口: ")"; ensure_port_free tcp "$LPORT" || return 1
  if [[ "$HT" == "socks5" ]]; then read -r -p "启用 SOCKS5 UDP? [y/N]: " ENABLE_UDP; fi
  read -r -p "启用用户名密码? [y/N]: " x
  if [[ ${x:-N} =~ ^[Yy]$ ]]; then U="$(read_clean "用户名: ")"; P="$(read_clean "密码: ")"; AUTH=$'    auth:\n      username: "'"$(yaml_escape "$U")"$'"\n      password: "'"$(yaml_escape "$P")"$'"\n'; fi
  if [[ "$HT" == "http" ]]; then
    append_service "$(cat <<EOF
- name: http-$LPORT
  addr: ":$LPORT"
  handler: { type: http }
$AUTH  listener: { type: tcp }
EOF
)"
  else
    local META=""; [[ ${ENABLE_UDP:-N} =~ ^[Yy]$ ]] && META=$'    metadata:\n      udp: true\n'
    append_service "$(cat <<EOF
- name: socks5-$LPORT
  addr: ":$LPORT"
  handler:
    type: socks5
$META$AUTH  listener: { type: tcp }
EOF
)"
  fi
  service_enable_restart
  systemctl is-active --quiet gost.service || okall=1
  wait_listen tcp "$LPORT" || okall=1
  (( okall==0 )) && ok "代理服务就绪" || fail "代理服务异常"; (( okall==0 )) || tips_troubleshoot
}

# ---------- 运维 ----------
view_yaml(){ rebuild_yaml; echo "----- $MAIN_CONF -----"; sed -n '1,500p' "$MAIN_CONF"; echo "----------------------"; }
clear_yaml(){ :> "$SERV_D"; :> "$CHAIN_D"; rebuild_yaml; service_enable_restart; ok "已清空"; }
restart_status(){ service_restart_status; }

menu(){ cat <<'EOF'

================ GOST v3 一体化脚本 ================
1) 安装/更新 GOST (v3 最新稳定版)
2) 完全卸载（移除所有改动：二进制/units/配置）
-----------------------------------------------
3) 不加密端口转发（直连，可选启用 UDP）
4) 加密隧道客户端 (tls/ws/wss，默认开启 UDP，同端口 TCP+UDP)
5) 加密隧道服务端 (tls/ws/wss，服务仅 TCP 监听)
6) 加密隧道客户端 (kcp/quic/ssh，默认开启 UDP，同端口 TCP+UDP)
7) 加密隧道服务端 (kcp=UDP / quic=UDP / ssh=TCP)
8) 代理服务 (HTTP / SOCKS5；SOCKS5 可选 UDP)
-----------------------------------------------
9) 查看当前 YAML
10) 清空并重建 YAML
12) 重启并显示状态
0) 退出
EOF
}

need_root
need_cmd awk
command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1 || { fail "需要 ss 或 netstat"; exit 1; }
[[ -f "$SERVICE" ]] || systemd_units
[[ -d "$CONF_DIR" ]] || ensure_dirs
rebuild_yaml

while true; do
  menu
  read -r -p "选择: " c
  case "$c" in
    1) install_or_update ;;
    2) uninstall_all ;;
    3) case1_nonencrypt ;;
    4) case2_encrypt_forward ;;
    5) case3_land_simple ;;
    6) case6_tunnel_client ;;
    7) case7_tunnel_server ;;
    8) case8_proxy ;;
    9) view_yaml ;;
    10) clear_yaml ;;
    12) restart_status ;;
    0) ok "退出"; exit 0 ;;
    *) red "无效选择" ;;
  esac
done
