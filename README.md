# NetSpire — GRE Tunnel Optimizer (Safe + Performance + Persistent)

NetSpire is a **single-file Bash** installer that provisions and tunes a **GRE (protocol 47) tunnel** between two Linux servers (e.g., **IRAN ↔ FOREIGN**) with a focus on **safety**, **throughput**, and **reboot persistence**.

**Key features**

- Automatic **WAN interface** + **MTU** detection
- **MSS clamping** (PMTU + fixed MSS on tunnel egress)
- Optional **NAT (MASQUERADE)**
- Optional **policy routing** (safe alternative to changing default route)
- **systemd persistence** (auto-restore after reboot)
- **Non-destructive firewall behavior** (**NO iptables flush**)

> ⚠️ Important
>
> - GRE is **protocol 47**. Some providers/ISPs **block or rate-limit GRE**.
> - GRE is **NOT encrypted**. For confidentiality/integrity, use **GRE over IPsec** or **WireGuard**.

## Why NetSpire

A lot of GRE scripts found online are risky or brittle:

- Use **public IP ranges** inside the tunnel (bad practice).
- **Flush iptables** (locks you out / breaks host firewall).
- Blindly set **default route** via tunnel (breaks SSH/network).
- Persist using **distro-specific** networking tools (fails across environments).

NetSpire is built to be:

- **Safe-by-default**
- **Idempotent** (re-run without stacking destructive changes)
- **Portable on systemd-based Linux distros**

## Requirements

- Linux server with **root** access
- Packages (NetSpire attempts best-effort installation on common distros):
  - `iproute2` (ip/tunnel)
  - `iptables`
  - `ping`
  - Optional: `tc` (for fq_codel), `ethtool`
- `systemd` is required for persistence (without it, the tunnel can still come up, but won’t auto-restore after reboot).

## Quick Start

### 1) Recommended: One-liner install & run (curl)

Run on **both** servers (IRAN and FOREIGN):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/power0matin/NetSpire/main/netspire.sh)
```

### 2) Alternative: Clone & run

```bash
git clone https://github.com/power0matin/NetSpire.git
cd NetSpire
chmod +x netspire.sh
sudo ./netspire.sh
```

### 3) Run on BOTH servers

- On the IRAN server: choose role **IRAN**
- On the FOREIGN server: choose role **FOREIGN**
- Provide correct **public IPv4** for both ends

## What NetSpire Configures

### Tunnel addressing (RFC1918 by default)

NetSpire uses private addressing on the tunnel:

- FOREIGN: `10.10.10.1/30`
- IRAN: `10.10.10.2/30`
- Network: `10.10.10.0/30`

Override if needed:

```bash
sudo TUN_NET_CIDR="10.20.30.0/30" ./netspire.sh
```

## MTU Optimization

NetSpire detects MTU from the default route interface and applies:

- `tunnel_mtu = wan_mtu - 24` (IPv4 + GRE overhead)
- If computed MTU is suspiciously low, it falls back to `1400`

Why it matters: wrong MTU causes fragmentation, retransmissions, and major TCP throughput loss.

## MSS Clamping (Critical for GRE)

To prevent TCP fragmentation issues across the GRE overhead:

- Adds `TCPMSS --clamp-mss-to-pmtu`
- Adds explicit `TCPMSS --set-mss (MTU-40)` for tunnel egress

Modes:

- `pmtu` → clamp only
- `fixed` → fixed MSS only
- `both` → default (recommended)

```bash
sudo CLAMP_MSS_MODE=pmtu ./netspire.sh
```

## sysctl Performance Tuning

NetSpire writes a drop-in sysctl profile:

- `/etc/sysctl.d/99-gre-tunnel.conf`

Includes:

- `net.ipv4.ip_forward = 1`
- Larger socket buffers (rmem/wmem)
- Improved backlogs (somaxconn, netdev_max_backlog)
- `tcp_mtu_probing = 1`
- Optional **BBR** (enabled if kernel supports it)

## Queue Discipline (Optional)

If `tc` is available, NetSpire applies `fq_codel` on the tunnel interface (helps with latency under load).

Disable:

```bash
sudo ENABLE_FQ_CODEL=0 ./netspire.sh
```

## NAT (Optional)

Common setup: enable NAT on the **FOREIGN** server so traffic from IRAN can egress via FOREIGN.

Interactive prompt appears when role = FOREIGN, or set via env:

```bash
sudo ENABLE_NAT=1 NAT_OUT_IFACE=eth0 ./netspire.sh
```

If `NAT_OUT_IFACE` is not provided, NetSpire uses the detected WAN interface.

## Routing Modes

### 1) Policy Routing (Recommended)

Instead of changing the system default route (which often breaks SSH), route only specific destinations via the tunnel using a fwmark + separate routing table.

Route **all** destinations via tunnel (host-originated traffic only):

```bash
sudo ENABLE_POLICY_ROUTE=1 POLICY_DST_CIDR="0.0.0.0/0" ./netspire.sh
```

Route only a specific subnet:

```bash
sudo ENABLE_POLICY_ROUTE=1 POLICY_DST_CIDR="203.0.113.0/24" ./netspire.sh
```

Notes:

- NetSpire marks traffic in `mangle OUTPUT` (locally generated traffic).
- If you need to route forwarded traffic, you’ll typically add marking in `mangle PREROUTING` (advanced use).

### 2) Default Route via Tunnel (UNSAFE)

Not recommended; can break connectivity if misused.

```bash
sudo ENABLE_UNSAFE_DEFAULT_ROUTE=1 ./netspire.sh
```

## Persistence (systemd)

If `systemd` is available, NetSpire persists configuration and auto-restores the tunnel on reboot.

Created artifacts:

- State file:
  - `/etc/gre-tunnel/<TUN_NAME>.env`

- systemd service:
  - `gre-tunnel-<TUN_NAME>.service`

- Helper scripts:
  - `/usr/local/sbin/gre-tunnel-<TUN_NAME>-apply`
  - `/usr/local/sbin/gre-tunnel-<TUN_NAME>-down`

Manage the service (default tunnel name is `gre-tun0`):

```bash
sudo systemctl status gre-tunnel-gre-tun0.service
sudo systemctl restart gre-tunnel-gre-tun0.service
```

## Verification

### Check tunnel interface

```bash
ip a show gre-tun0
ip link show gre-tun0
```

### Ping through tunnel

On FOREIGN:

```bash
ping -c 3 -I gre-tun0 10.10.10.2
```

On IRAN:

```bash
ping -c 3 -I gre-tun0 10.10.10.1
```

### MTU/PMTU test (DF ping)

```bash
ping -c 1 -I gre-tun0 -M do -s 1360 10.10.10.2
```

### Confirm MSS rules

```bash
iptables -t mangle -S | grep TCPMSS
```

## Troubleshooting

### Tunnel interface exists but ping fails

Most common causes:

1. GRE blocked by provider/ISP (proto 47)
2. Host firewall default-drop blocks GRE/ICMP
3. GRE across NAT (often fails without special handling)
4. ICMP blocked causing PMTU blackholes

Optional sniff (if available):

```bash
tcpdump -ni <WAN_IFACE> proto 47
```

### Quick diagnostics checklist

- Confirm GRE allowed:

  ```bash
  iptables -S INPUT | grep -- "-p 47"
  ```

- Confirm endpoint reachability (public IP):

  ```bash
  ping -c 2 <REMOTE_PUBLIC_IP>
  ```

- Confirm tunnel counters increase:

  ```bash
  ip -s link show gre-tun0
  ```

## Security Note

GRE provides **no encryption**. If you need confidentiality/integrity:

- Use **GRE over IPsec**
- or replace with **WireGuard**
- or use **OpenVPN**

## License

MIT — see `LICENSE`.
