# GRE Tunnel Optimizer (Safe + Performance + Persistent)

A single-file Bash script to create and optimize a GRE tunnel between two Linux servers (e.g., IRAN ↔ FOREIGN) with:

- MTU auto-detection
- MSS clamping (PMTU + fixed)
- Optional NAT
- Optional policy routing (safe alternative to changing default route)
- systemd persistence (auto-restore on reboot)
- Non-destructive firewall behavior (NO iptables flush)

> ⚠️ Important:
>
> - GRE is **protocol 47**. Many providers/ISPs block or rate-limit GRE.
> - GRE is **NOT encrypted**. For confidentiality, use IPsec/WireGuard.

## Why this repo exists

Many GRE scripts on the internet:

- use public IP ranges inside the tunnel (bad practice),
- flush all iptables rules (high risk: locks you out),
- add default route via tunnel blindly (breaks SSH),
- persist using distro-specific tools (fails on other distros).

This script is designed to be:

- **safe-by-default**
- **idempotent**
- **portable across systemd Linux distros**

## Requirements

- Linux server with root access
- Packages:
  - `iproute2` (ip/tunnel)
  - `iptables`
  - `ping`
  - Optional: `tc` (for fq_codel), `ethtool`
- `systemd` is required for persistence; without systemd, tunnel still comes up but won't auto-restore after reboot.

## Quick Start

### 1) Clone and run

```bash
git clone https://github.com/<your-username>/gre-tunnel-optimizer.git
cd gre-tunnel-optimizer
chmod +x gre-tunnel.sh
sudo ./gre-tunnel.sh
```

### 2) Run on BOTH servers

- On IRAN server: choose role **IRAN**
- On FOREIGN server: choose role **FOREIGN**
  Use the correct public IPv4 addresses for each side.

## What it configures

### Tunnel addressing

- Uses RFC1918 by default:
  - FOREIGN: `10.10.10.1/30`
  - IRAN: `10.10.10.2/30`

- Network: `10.10.10.0/30`

You can change it via environment variables:

```bash
sudo TUN_NET_CIDR="10.20.30.0/30" ./gre-tunnel.sh
```

### MTU optimization

- Detects WAN MTU from the default route interface
- Tunnel MTU = WAN MTU - 24 bytes (IPv4 + GRE overhead)
- If MTU looks suspiciously low, it falls back to `1400`

### MSS clamping

To avoid fragmentation and poor TCP performance:

- Adds `TCPMSS --clamp-mss-to-pmtu`
- Adds explicit `TCPMSS --set-mss (MTU-40)` on tunnel egress

You can change mode:

- `pmtu` (only clamp)
- `fixed` (only fixed mss)
- `both` (default)

```bash
sudo CLAMP_MSS_MODE=pmtu ./gre-tunnel.sh
```

### sysctl performance tuning

Creates/updates:

- `/etc/sysctl.d/99-gre-tunnel.conf`

Includes:

- IP forwarding
- Larger socket buffers
- Better backlogs
- MTU probing
- Optional BBR (if available)

### qdisc (optional)

Applies `fq_codel` to the tunnel interface if `tc` is available.

Disable:

```bash
sudo ENABLE_FQ_CODEL=0 ./gre-tunnel.sh
```

## NAT (Optional)

On many setups, you want **NAT on the FOREIGN server** so traffic from IRAN egresses via FOREIGN.

During interactive run, FOREIGN role is prompted:

- Enable NAT: `MASQUERADE` out of WAN interface.

Or set via env:

```bash
sudo ENABLE_NAT=1 NAT_OUT_IFACE=eth0 ./gre-tunnel.sh
```

## Routing Modes

### 1) Policy Routing (Recommended)

Instead of changing your system default route (which often breaks SSH), you can route only specific destinations via tunnel.

Example: Route **all** traffic via tunnel safely (only from this host, not forwarded unless you add PREROUTING rules):

```bash
sudo ENABLE_POLICY_ROUTE=1 POLICY_DST_CIDR="0.0.0.0/0" ./gre-tunnel.sh
```

Or only route a specific subnet:

```bash
sudo ENABLE_POLICY_ROUTE=1 POLICY_DST_CIDR="203.0.113.0/24" ./gre-tunnel.sh
```

### 2) Default Route via Tunnel (UNSAFE)

Not recommended. Can break connectivity if misused.
Interactive prompt exists, or:

```bash
sudo ENABLE_UNSAFE_DEFAULT_ROUTE=1 ./gre-tunnel.sh
```

## Persistence (systemd)

If systemd is present:

- Saves state: `/etc/gre-tunnel/<TUN_NAME>.env`
- Installs service: `gre-tunnel-<TUN_NAME>.service`
- Installs helper scripts:
  - `/usr/local/sbin/gre-tunnel-<TUN_NAME>-apply`
  - `/usr/local/sbin/gre-tunnel-<TUN_NAME>-down`

Service commands:

```bash
sudo systemctl status gre-tunnel-gre-tun0.service
sudo systemctl restart gre-tunnel-gre-tun0.service
```

## Verification & Troubleshooting

### Check the interface

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

### Check MSS rules

```bash
iptables -t mangle -S | grep TCPMSS
```

### If tunnel doesn't pass traffic

Most common causes:

1. GRE blocked by provider/ISP (proto 47)
2. Firewall default-drop without GRE allow
3. NAT in the path (GRE often fails across NAT)
4. ICMP blocked causing PMTU blackholes (keep PMTU rules / enable MTU probing)

Optional sniff (if available):

```bash
tcpdump -ni <WAN_IFACE> proto 47
```

## Security note

GRE provides **no encryption**. If you need confidentiality/integrity, use:

- GRE over IPsec
- or WireGuard
- or OpenVPN

## License

MIT License. See `LICENSE`.
