# 🌐 Router Connection Guide & Examples (Tier 2 Network Shield)

Aegis works out-of-the-box on any computer in **Tier 1 (`System Shield`)** with zero router configuration.
When you connect a supported router, Aegis unlocks **Tier 2 (`Network Gateway Shield`)**:
- **Whole-Home / Office Visibility:** Inspects smartphones, tablets, Smart TVs, Wi-Fi cameras, and IoT sensors *before* NAT or VPN encapsulation.
- **Wire-Speed L7 DPI & TLS `JA3`:** Extracts SNI, ALPN, TLS versions, RFC 8701 GREASE-filtered `JA3` hashes, Passive DNS, Shannon entropy tunneling, and Stratum mining traffic.
- **Out-of-Band Anti-Rootkit (`GHOST SOCKET`):** Compares physical gateway packets against your computer's OS kernel socket table every 250 ms.
- **Active Network Firewall Control:** Block malicious external C2 IPs or quarantine rogue IoT devices across the entire LAN using ephemeral RAM-only `nftables` / `iptables` rules.

> [!TIP]
> Have a router model not listed below? Use our ready-to-copy [**🤖 AI Router Setup Prompt**](AI_ROUTER_PROMPT.md) (or click **`🌐 Router + AI`** inside the Aegis Web Console).

---

## Step 1: Generate an `Ed25519` SSH Key on Your Computer

Run in PowerShell (Windows) or Terminal (Linux / macOS):

```bash
ssh-keygen -t ed25519 -C "aegis-local"
```
*(Press Enter to accept the default path `~/.ssh/id_ed25519`.)*

---

## Step 2: Configure Your Router Platform

### Option A: OpenWrt (23.05 / 24.10 / 25.x) & GL.iNet (Flint 2, Beryl AX, Slate)

1. **Authorize your SSH public key on the router:**
   - **Via LuCI Web UI:** `System` → `Administration` → `SSH-Keys` → paste the contents of `~/.ssh/id_ed25519.pub`.
   - **Or via CLI:**
     ```bash
     cat ~/.ssh/id_ed25519.pub | ssh root@192.168.1.1 "cat >> /etc/dropbear/authorized_keys && chmod 600 /etc/dropbear/authorized_keys"
     ```
2. **Install lightweight `tcpdump-mini` (~150 KB, zero background daemons):**
   ```bash
   scp router/openwrt_aegis_setup.sh root@192.168.1.1:/tmp/
   ssh root@192.168.1.1 "sh /tmp/openwrt_aegis_setup.sh"
   ```
3. **Launch Aegis:**
   ```bash
   aegis --router 192.168.1.1 --iface br-lan --open-browser
   ```
   *(Or copy `examples/router-openwrt.env.example` to `.env`.)*

---

### Option B: Keenetic (with Entware OPKG) & Asuswrt-Merlin

1. Enable **Entware (OPKG)** on a USB flash drive or internal storage and enable SSH (LAN only; note Keenetic Entware SSH typically uses port **`222`** and bridge **`br0`**).
2. Copy your SSH public key to `/opt/etc/dropbear/authorized_keys` (or `~/.ssh/authorized_keys`).
3. Run the Entware bootstrap script:
   ```bash
   scp -P 222 router/entware_aegis_setup.sh root@192.168.1.1:/tmp/
   ssh -p 222 root@192.168.1.1 "sh /tmp/entware_aegis_setup.sh"
   ```
   *(Ensure `/opt/sbin:/opt/bin` is in `/opt/etc/profile` or symlink `ln -s /opt/sbin/tcpdump /usr/bin/tcpdump` if root FS allows, or test with `ssh -p 222 root@192.168.1.1 "command -v tcpdump"`).*
4. **Launch Aegis:**
   ```bash
   aegis --router 192.168.1.1 --ssh-port 222 --iface br0 --open-browser
   ```
   *(See `examples/router-keenetic-entware.env.example`.)*

---

### Option C: Linux Gateway / Raspberry Pi / Debian / Ubuntu / Ubiquiti UniFi & EdgeOS

1. Copy your SSH key:
   ```bash
   ssh-copy-id root@10.0.0.1
   ```
2. Ensure `tcpdump` is installed (`apt install -y tcpdump`).
3. Identify your internal LAN interface (`ip -br link`, e.g. `br0` or `eth1`).
4. **Launch Aegis:**
   ```bash
   aegis --router 10.0.0.1 --iface eth1 --open-browser
   ```

---

## Step 3: Verify Zero-Load & Run Security Audit

1. Open **http://127.0.0.1:8765**. The top badge will turn cyan: **`TIER 2: ROUTER LAN`** + **`LIVE: ROUTER STREAM`**.
2. Click **`⏸ Pause`** anytime: the SSH pipe closes immediately and router CPU/RAM consumption drops to **`0% CPU / 0 MB RAM`**.
3. Open the **`Network Control & Router Audit`** tab and click **`🔍 Run Router Audit`** (or run `ssh root@192.168.1.1 "sh -s" < router/openwrt_security_audit.sh`) to verify your router's WAN firewall posture!
