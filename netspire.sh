#!/usr/bin/env bash
# ============================================================
# GRE Tunnel Optimizer - Safe + Performance + Persistent
# Repo-ready single-file installer
#
# Features:
# - GRE tunnel (iproute2) with RFC1918 tunnel IPs (default 10.10.10.0/30)
# - MTU auto-detect (WAN MTU - GRE overhead)
# - MSS clamping (PMTU + explicit tunnel MSS)
# - Optional NAT (MASQUERADE)
# - Optional policy routing (mark-based) - safer than changing default route
# - systemd persistence (service + helper scripts) for reboot survival
# - Non-destructive iptables changes (NO flush)
#
# Requirements:
# - Run as root
# - iproute2, iptables; optional: tc, ethtool
#
# IMPORTANT:
# - GRE is protocol 47. Many providers/paths block it. If GRE is blocked, tunnel won't pass traffic.
# - GRE is not encrypted. Use IPsec/WireGuard if confidentiality is needed.
# ============================================================

set -euo pipefail

# -----------------------------
# Pretty output
# -----------------------------
if command -v tput >/dev/null 2>&1; then
  CYAN=$(tput setaf 6); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
  RED=$(tput setaf 1); BLUE=$(tput setaf 4); RESET=$(tput sgr0); BOLD=$(tput bold)
else
  CYAN=""; YELLOW=""; GREEN=""; RED=""; BLUE=""; RESET=""; BOLD=""
fi

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[x]${RESET} $*"; }

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Run as root (sudo)."
    exit 1
  fi
}

# -----------------------------
# Defaults (overridable by env)
# -----------------------------
TUN_NAME="${TUN_NAME:-gre-tun0}"

# Tunnel addressing (RFC1918)
TUN_NET_CIDR="${TUN_NET_CIDR:-10.10.10.0/30}"
# role-based defaults:
TUN_LOCAL_IP="${TUN_LOCAL_IP:-}"
TUN_PEER_IP="${TUN_PEER_IP:-}"

# GRE parameters
TTL="${TTL:-255}"
TOS="${TOS:-inherit}"
TXQLEN="${TXQLEN:-2000}"

# Tuning toggles
ENABLE_BBR="${ENABLE_BBR:-1}"
ENABLE_FQ_CODEL="${ENABLE_FQ_CODEL:-1}"

# iptables behavior
CLAMP_MSS_MODE="${CLAMP_MSS_MODE:-both}"  # pmtu|fixed|both

# NAT optional
ENABLE_NAT="${ENABLE_NAT:-0}"
NAT_OUT_IFACE="${NAT_OUT_IFACE:-}"        # empty => WAN iface

# Safer routing (recommended)
ENABLE_POLICY_ROUTE="${ENABLE_POLICY_ROUTE:-0}"
POLICY_MARK="${POLICY_MARK:-0x66}"
POLICY_TABLE="${POLICY_TABLE:-66}"
POLICY_DST_CIDR="${POLICY_DST_CIDR:-}"    # required if policy route enabled

# Unsafe routing (not recommended)
ENABLE_UNSAFE_DEFAULT_ROUTE="${ENABLE_UNSAFE_DEFAULT_ROUTE:-0}" # 1 to add default route via tunnel

# sysctl drop-in
SYSCTL_DROPIN="/etc/sysctl.d/99-gre-tunnel.conf"

# persistence
STATE_DIR="/etc/gre-tunnel"
STATE_FILE="${STATE_DIR}/${TUN_NAME}.env"
SERVICE_NAME="gre-tunnel-${TUN_NAME}.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
APPLY_SCRIPT="/usr/local/sbin/gre-tunnel-${TUN_NAME}-apply"
DOWN_SCRIPT="/usr/local/sbin/gre-tunnel-${TUN_NAME}-down"

ROLE=""
IP_LOCAL_PUBLIC=""
IP_REMOTE_PUBLIC=""
WAN_IFACE=""

# -----------------------------
# Package installation (best-effort)
# -----------------------------
detect_pkg_manager() {
  if has_cmd apt-get; then echo "apt"
  elif has_cmd dnf; then echo "dnf"
  elif has_cmd yum; then echo "yum"
  else echo ""
  fi
}

install_deps() {
  log "Checking/installing dependencies (best-effort)..."
  local pm
  pm=$(detect_pkg_manager)

  case "$pm" in
    apt)
      apt-get update -y
      apt-get install -y iproute2 iptables iputils-ping net-tools ethtool >/dev/null 2>&1 || true
      apt-get install -y iproute2 tc >/dev/null 2>&1 || true
      ;;
    dnf)
      dnf install -y iproute iptables iputils net-tools ethtool iproute-tc >/dev/null 2>&1 || true
      ;;
    yum)
      yum install -y iproute iptables iputils net-tools ethtool iproute-tc >/dev/null 2>&1 || true
      ;;
    *)
      warn "No supported package manager found. Ensure you have: ip, iptables, ping (and optionally tc, ethtool)."
      ;;
  esac
  ok "Dependency step done."
}

# -----------------------------
# Network detection / MTU
# -----------------------------
get_default_iface() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

get_iface_mtu() {
  local iface="$1"
  ip link show dev "$iface" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}'
}

calc_gre_overhead_ipv4() {
  # Outer IPv4 header (20) + GRE base header (4) = 24 bytes
  echo 24
}

calc_tun_mtu() {
  local wan="$1"
  local base overhead m
  base=$(get_iface_mtu "$wan" || true)
  overhead=$(calc_gre_overhead_ipv4)

  if [[ -z "${base}" ]]; then
    echo 1476
    return 0
  fi

  m=$(( base - overhead ))
  # sanity
  if (( m < 1300 )); then
    warn "Computed tunnel MTU looks low ($m). Forcing 1400."
    echo 1400
  else
    echo "$m"
  fi
}

calc_mss() {
  local tun_mtu="$1"
  echo $(( tun_mtu - 40 ))  # IPv4(20) + TCP(20)
}

# -----------------------------
# sysctl tuning
# -----------------------------
sysctl_apply() {
  log "Applying sysctl tuning via ${SYSCTL_DROPIN} ..."
  mkdir -p /etc/sysctl.d

  cat > "${SYSCTL_DROPIN}" <<'EOF'
# GRE Tunnel performance & stability

# Forwarding
net.ipv4.ip_forward = 1

# Socket buffers (high but sane caps)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP buffers (min default max)
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Backlogs
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096

# TCP behavior
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Helps when ICMP is filtered (PMTU issues)
net.ipv4.tcp_mtu_probing = 1
EOF

  sysctl --system >/dev/null 2>&1 || sysctl -p "${SYSCTL_DROPIN}" >/dev/null 2>&1 || true
  ok "sysctl applied."
}

bbr_enable_if_possible() {
  if [[ "$ENABLE_BBR" != "1" ]]; then
    warn "BBR disabled by config."
    return 0
  fi
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    ok "BBR enabled."
  else
    warn "BBR not available on this kernel."
  fi
}

# -----------------------------
# qdisc tuning
# -----------------------------
qdisc_apply() {
  local dev="$1"
  if [[ "$ENABLE_FQ_CODEL" != "1" ]]; then
    warn "FQ_CoDel disabled by config."
    return 0
  fi
  if ! has_cmd tc; then
    warn "tc not available; skipping qdisc."
    return 0
  fi
  tc qdisc del dev "$dev" root 2>/dev/null || true
  tc qdisc add dev "$dev" root fq_codel quantum 300 limit 10240 flows 4096 2>/dev/null || true
  ok "qdisc fq_codel applied on $dev."
}

# -----------------------------
# iptables (non-destructive)
# -----------------------------
iptables_add_rule_once() {
  local table="$1"; shift
  if iptables -t "$table" -C "$@" >/dev/null 2>&1; then
    return 0
  fi
  iptables -t "$table" -A "$@"
}

iptables_allow_gre_icmp() {
  # Allow protocol 47 (GRE) and ICMP frag-needed (type 3 code 4)
  log "Ensuring GRE (proto 47) + ICMP PMTU are allowed (non-destructive)..."
  iptables_add_rule_once filter INPUT  -p 47 -j ACCEPT
  iptables_add_rule_once filter OUTPUT -p 47 -j ACCEPT
  iptables_add_rule_once filter INPUT  -p icmp --icmp-type 3/4 -j ACCEPT || true
  iptables_add_rule_once filter OUTPUT -p icmp -j ACCEPT || true
  ok "GRE/ICMP allow rules ensured."
}

iptables_setup_mss() {
  local tun="$1"
  local tun_mtu="$2"
  local mss
  mss=$(calc_mss "$tun_mtu")

  log "Configuring MSS clamping (mode=$CLAMP_MSS_MODE, MTU=$tun_mtu, MSS=$mss)..."
  case "$CLAMP_MSS_MODE" in
    pmtu)
      iptables_add_rule_once mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      ;;
    fixed)
      iptables_add_rule_once mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
      ;;
    both)
      iptables_add_rule_once mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      iptables_add_rule_once mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
      ;;
    *)
      warn "Unknown CLAMP_MSS_MODE=$CLAMP_MSS_MODE; skipping MSS rules."
      ;;
  esac
  ok "MSS rules ensured."
}

iptables_setup_nat() {
  local out_if="$1"
  log "Enabling NAT MASQUERADE out of $out_if ..."
  iptables_add_rule_once nat POSTROUTING -o "$out_if" -j MASQUERADE
  ok "NAT enabled."
}

# -----------------------------
# Routing options
# -----------------------------
policy_routing_setup() {
  local tun="$1"
  local peer_ip="$2"

  if [[ "$ENABLE_POLICY_ROUTE" != "1" ]]; then
    return 0
  fi
  if [[ -z "$POLICY_DST_CIDR" ]]; then
    err "ENABLE_POLICY_ROUTE=1 but POLICY_DST_CIDR is empty."
    exit 1
  fi

  log "Setting up policy routing via tunnel (mark=$POLICY_MARK table=$POLICY_TABLE dst=$POLICY_DST_CIDR)..."
  ip route replace default via "$peer_ip" dev "$tun" table "$POLICY_TABLE"
  ip rule add fwmark "$POLICY_MARK" lookup "$POLICY_TABLE" priority 10000 2>/dev/null || true
  iptables_add_rule_once mangle OUTPUT -d "$POLICY_DST_CIDR" -j MARK --set-mark "$POLICY_MARK"
  ok "Policy routing configured."
}

unsafe_default_route_setup() {
  local tun="$1"
  local peer_ip="$2"
  if [[ "$ENABLE_UNSAFE_DEFAULT_ROUTE" != "1" ]]; then
    return 0
  fi
  warn "UNSAFE: Adding default route via tunnel (may break SSH/network)."
  ip route replace default via "$peer_ip" dev "$tun" metric 200
  ok "Default route via tunnel added (metric 200)."
}

# -----------------------------
# Tunnel create
# -----------------------------
tunnel_delete_if_exists() {
  ip link show "$TUN_NAME" >/dev/null 2>&1 && ip link del "$TUN_NAME" 2>/dev/null || true
}

tunnel_create() {
  local local_pub="$1"
  local remote_pub="$2"
  local tun_local="$3"
  local tun_net="$4"
  local wan_if="$5"

  local tun_mtu
  tun_mtu=$(calc_tun_mtu "$wan_if")

  log "Creating GRE tunnel: name=$TUN_NAME wan=$wan_if mtu=$tun_mtu"
  tunnel_delete_if_exists

  ip tunnel add "$TUN_NAME" mode gre local "$local_pub" remote "$remote_pub" ttl "$TTL" tos "$TOS"
  ip link set "$TUN_NAME" up mtu "$tun_mtu" txqueuelen "$TXQLEN"
  ip addr replace "$tun_local/30" dev "$TUN_NAME"
  ip route replace "$tun_net" dev "$TUN_NAME"

  ok "Tunnel up: $TUN_NAME ($tun_local) mtu=$tun_mtu"
}

# -----------------------------
# Persistence (systemd)
# -----------------------------
persist_state() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  cat > "$STATE_FILE" <<EOF
# Auto-generated GRE state
ROLE="${ROLE}"
IP_LOCAL_PUBLIC="${IP_LOCAL_PUBLIC}"
IP_REMOTE_PUBLIC="${IP_REMOTE_PUBLIC}"
WAN_IFACE="${WAN_IFACE}"
TUN_NAME="${TUN_NAME}"
TUN_NET_CIDR="${TUN_NET_CIDR}"
TUN_LOCAL_IP="${TUN_LOCAL_IP}"
TUN_PEER_IP="${TUN_PEER_IP}"
TTL="${TTL}"
TOS="${TOS}"
TXQLEN="${TXQLEN}"
ENABLE_BBR="${ENABLE_BBR}"
ENABLE_FQ_CODEL="${ENABLE_FQ_CODEL}"
CLAMP_MSS_MODE="${CLAMP_MSS_MODE}"
ENABLE_NAT="${ENABLE_NAT}"
NAT_OUT_IFACE="${NAT_OUT_IFACE}"
ENABLE_POLICY_ROUTE="${ENABLE_POLICY_ROUTE}"
POLICY_MARK="${POLICY_MARK}"
POLICY_TABLE="${POLICY_TABLE}"
POLICY_DST_CIDR="${POLICY_DST_CIDR}"
ENABLE_UNSAFE_DEFAULT_ROUTE="${ENABLE_UNSAFE_DEFAULT_ROUTE}"
EOF

  chmod 600 "$STATE_FILE"
  ok "State saved: $STATE_FILE"
}

install_systemd_units() {
  if ! has_cmd systemctl; then
    warn "systemd not detected (no systemctl). Skipping persistence."
    return 0
  fi

  log "Installing systemd service: $SERVICE_NAME"

  # Helper apply script (idempotent)
  cat > "$APPLY_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# STATE_FILE is injected via systemd EnvironmentFile
# shellcheck disable=SC1090
source "$STATE_FILE"

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

get_iface_mtu(){
  ip link show dev "$1" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}'
}
calc_tun_mtu(){
  local base overhead m
  overhead=24
  base=$(get_iface_mtu "$WAN_IFACE" || true)
  if [[ -z "$base" ]]; then echo 1476; else
    m=$(( base - overhead ))
    if (( m < 1300 )); then echo 1400; else echo "$m"; fi
  fi
}
calc_mss(){ echo $(( $1 - 40 )); }

iptables_add_rule_once(){
  local table="$1"; shift
  if iptables -t "$table" -C "$@" >/dev/null 2>&1; then return 0; fi
  iptables -t "$table" -A "$@"
}

# Apply sysctl (best-effort)
sysctl --system >/dev/null 2>&1 || true

# Recreate tunnel
tun_mtu=$(calc_tun_mtu)
ip link show "$TUN_NAME" >/dev/null 2>&1 && ip link del "$TUN_NAME" 2>/dev/null || true
ip tunnel add "$TUN_NAME" mode gre local "$IP_LOCAL_PUBLIC" remote "$IP_REMOTE_PUBLIC" ttl "$TTL" tos "$TOS"
ip link set "$TUN_NAME" up mtu "$tun_mtu" txqueuelen "$TXQLEN"
ip addr replace "$TUN_LOCAL_IP/30" dev "$TUN_NAME"
ip route replace "$TUN_NET_CIDR" dev "$TUN_NAME"

# Allow GRE/ICMP PMTU
iptables_add_rule_once filter INPUT  -p 47 -j ACCEPT
iptables_add_rule_once filter OUTPUT -p 47 -j ACCEPT
iptables_add_rule_once filter INPUT  -p icmp --icmp-type 3/4 -j ACCEPT || true
iptables_add_rule_once filter OUTPUT -p icmp -j ACCEPT || true

# MSS clamp
mss=$(calc_mss "$tun_mtu")
case "$CLAMP_MSS_MODE" in
  pmtu)
    iptables_add_rule_once mangle POSTROUTING -o "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ;;
  fixed)
    iptables_add_rule_once mangle POSTROUTING -o "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    ;;
  both)
    iptables_add_rule_once mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    iptables_add_rule_once mangle POSTROUTING -o "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    ;;
esac

# Enable BBR if available
if [[ "$ENABLE_BBR" == "1" ]]; then
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
  fi
fi
sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true

# qdisc
if [[ "$ENABLE_FQ_CODEL" == "1" ]] && has_cmd tc; then
  tc qdisc del dev "$TUN_NAME" root 2>/dev/null || true
  tc qdisc add dev "$TUN_NAME" root fq_codel quantum 300 limit 10240 flows 4096 2>/dev/null || true
fi

# NAT optional
if [[ "$ENABLE_NAT" == "1" ]]; then
  out_if="$NAT_OUT_IFACE"
  if [[ -z "$out_if" ]]; then out_if="$WAN_IFACE"; fi
  iptables_add_rule_once nat POSTROUTING -o "$out_if" -j MASQUERADE
fi

# Policy routing optional
if [[ "$ENABLE_POLICY_ROUTE" == "1" ]]; then
  if [[ -z "$POLICY_DST_CIDR" ]]; then
    echo "POLICY_DST_CIDR is empty; cannot apply policy routing." >&2
    exit 1
  fi
  ip route replace default via "$TUN_PEER_IP" dev "$TUN_NAME" table "$POLICY_TABLE"
  ip rule add fwmark "$POLICY_MARK" lookup "$POLICY_TABLE" priority 10000 2>/dev/null || true
  iptables_add_rule_once mangle OUTPUT -d "$POLICY_DST_CIDR" -j MARK --set-mark "$POLICY_MARK"
fi

# Unsafe default route optional
if [[ "$ENABLE_UNSAFE_DEFAULT_ROUTE" == "1" ]]; then
  ip route replace default via "$TUN_PEER_IP" dev "$TUN_NAME" metric 200
fi

exit 0
EOF

  # Helper down script
  cat > "$DOWN_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1090
source "$STATE_FILE"
ip link show "$TUN_NAME" >/dev/null 2>&1 && ip link del "$TUN_NAME" 2>/dev/null || true
exit 0
EOF

  chmod +x "$APPLY_SCRIPT" "$DOWN_SCRIPT"

  # systemd unit
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Persistent GRE Tunnel (${TUN_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=${STATE_FILE}
ExecStart=${APPLY_SCRIPT}
ExecStop=${DOWN_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  ok "systemd service installed & enabled: $SERVICE_NAME"
}

# -----------------------------
# Tests / diagnostics
# -----------------------------
test_basic() {
  log "Testing tunnel connectivity..."
  if [[ -z "$TUN_PEER_IP" ]]; then
    warn "TUN_PEER_IP is empty; skipping ping test."
    return 0
  fi
  ping -c 4 -I "$TUN_NAME" "$TUN_PEER_IP" | tail -n 2 || true

  log "PMTU probe (DF ping) quick test..."
  if ping -c 1 -I "$TUN_NAME" -M do -s 1360 "$TUN_PEER_IP" >/dev/null 2>&1; then
    ok "DF ping (1360 bytes) OK"
  else
    warn "DF ping failed (might be MTU/PMTU issue or ping flag unsupported)."
  fi
}

show_summary() {
  echo -e "${BLUE}Configuration Summary${RESET}"
  echo "--------------------------------------------"
  echo "ROLE                 : $ROLE"
  echo "LOCAL_PUBLIC_IP      : $IP_LOCAL_PUBLIC"
  echo "REMOTE_PUBLIC_IP     : $IP_REMOTE_PUBLIC"
  echo "WAN_IFACE            : $WAN_IFACE"
  echo "TUN_NAME             : $TUN_NAME"
  echo "TUN_NET_CIDR         : $TUN_NET_CIDR"
  echo "TUN_LOCAL_IP         : $TUN_LOCAL_IP"
  echo "TUN_PEER_IP          : $TUN_PEER_IP"
  echo "ENABLE_BBR           : $ENABLE_BBR"
  echo "ENABLE_FQ_CODEL      : $ENABLE_FQ_CODEL"
  echo "CLAMP_MSS_MODE       : $CLAMP_MSS_MODE"
  echo "ENABLE_NAT           : $ENABLE_NAT"
  echo "NAT_OUT_IFACE        : ${NAT_OUT_IFACE:-<auto>}"
  echo "ENABLE_POLICY_ROUTE  : $ENABLE_POLICY_ROUTE"
  echo "POLICY_DST_CIDR      : ${POLICY_DST_CIDR:-<none>}"
  echo "UNSAFE_DEFAULT_ROUTE : $ENABLE_UNSAFE_DEFAULT_ROUTE"
  echo "--------------------------------------------"
}

# -----------------------------
# Interaction
# -----------------------------
header() {
  clear || true
  echo -e "${CYAN}${BOLD}"
  echo "============================================================"
  echo "     GRE Tunnel Optimizer - Safe + Optimized + Persistent"
  echo "============================================================"
  echo -e "${RESET}"
}

prompt_nonempty() {
  local varname="$1" prompt="$2" default="${3:-}"
  local val=""
  while true; do
    if [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " val
      val="${val:-$default}"
    else
      read -r -p "$prompt: " val
    fi
    if [[ -n "$val" ]]; then
      printf -v "$varname" '%s' "$val"
      return 0
    fi
  done
}

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

main() {
  need_root
  header

  echo -e "${YELLOW}Notes:${RESET}"
  echo " - GRE is protocol 47. If blocked by provider/ISP, tunnel won't pass traffic."
  echo " - GRE is NOT encrypted."
  echo " - This script is non-destructive to iptables (no flush)."
  echo ""

  echo "Select this server role:"
  echo "1) IRAN"
  echo "2) FOREIGN"
  read -r -p "Enter 1 or 2: " sel
  case "$sel" in
    1) ROLE="IRAN";   TUN_LOCAL_IP="10.10.10.2"; TUN_PEER_IP="10.10.10.1" ;;
    2) ROLE="FOREIGN";TUN_LOCAL_IP="10.10.10.1"; TUN_PEER_IP="10.10.10.2" ;;
    *) err "Invalid selection."; exit 1 ;;
  esac

  prompt_nonempty IP_LOCAL_PUBLIC  "Enter THIS server public IPv4"
  prompt_nonempty IP_REMOTE_PUBLIC "Enter REMOTE server public IPv4"

  if ! is_ipv4 "$IP_LOCAL_PUBLIC"; then err "Invalid local IPv4"; exit 1; fi
  if ! is_ipv4 "$IP_REMOTE_PUBLIC"; then err "Invalid remote IPv4"; exit 1; fi

  WAN_IFACE=$(get_default_iface || true)
  if [[ -z "$WAN_IFACE" ]]; then
    prompt_nonempty WAN_IFACE "Could not detect WAN iface. Enter WAN iface (e.g. eth0/ens3)"
  fi

  # NAT suggestion (common on FOREIGN)
  if [[ "$ROLE" == "FOREIGN" ]]; then
    echo ""
    read -r -p "Enable NAT (MASQUERADE) out of WAN on this server? (y/n) [n]: " ans
    ans="${ans:-n}"
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      ENABLE_NAT="1"
      NAT_OUT_IFACE="$WAN_IFACE"
    fi
  fi

  # Policy routing (recommended)
  echo ""
  read -r -p "Enable POLICY ROUTING via tunnel for specific destinations (safe)? (y/n) [n]: " ans2
  ans2="${ans2:-n}"
  if [[ "$ans2" =~ ^[Yy]$ ]]; then
    ENABLE_POLICY_ROUTE="1"
    prompt_nonempty POLICY_DST_CIDR "Enter destination CIDR to route via tunnel (e.g. 0.0.0.0/0 or 1.1.1.1/32)"
  fi

  # Unsafe default route
  echo ""
  read -r -p "UNSAFE: Add default route via tunnel (can break SSH). Do it? (y/n) [n]: " ans3
  ans3="${ans3:-n}"
  if [[ "$ans3" =~ ^[Yy]$ ]]; then
    ENABLE_UNSAFE_DEFAULT_ROUTE="1"
  fi

  echo ""
  show_summary
  echo ""

  install_deps
  sysctl_apply
  bbr_enable_if_possible

  tunnel_create "$IP_LOCAL_PUBLIC" "$IP_REMOTE_PUBLIC" "$TUN_LOCAL_IP" "$TUN_NET_CIDR" "$WAN_IFACE"
  iptables_allow_gre_icmp

  local tun_mtu
  tun_mtu=$(get_iface_mtu "$TUN_NAME" || echo 1476)
  iptables_setup_mss "$TUN_NAME" "$tun_mtu"

  qdisc_apply "$TUN_NAME"

  if [[ "$ENABLE_NAT" == "1" ]]; then
    local out_if="${NAT_OUT_IFACE:-$WAN_IFACE}"
    iptables_setup_nat "$out_if"
  fi

  policy_routing_setup "$TUN_NAME" "$TUN_PEER_IP"
  unsafe_default_route_setup "$TUN_NAME" "$TUN_PEER_IP"

  persist_state
  install_systemd_units

  ok "Setup complete."

  echo ""
  read -r -p "Run basic tunnel tests now? (y/n) [y]: " t
  t="${t:-y}"
  if [[ "$t" =~ ^[Yy]$ ]]; then
    test_basic
  fi

  echo -e "\n${GREEN}${BOLD}Useful commands${RESET}"
  echo " - Interface: ip a show $TUN_NAME"
  echo " - Routes:    ip route; ip rule; ip route show table $POLICY_TABLE"
  echo " - MSS rules: iptables -t mangle -S | grep TCPMSS"
  echo " - Service:   systemctl status $SERVICE_NAME"
  echo " - Restart:   systemctl restart $SERVICE_NAME"
}

main "$@"
