"""
Deep Packet Inspection (L7 DPI), Passive DNS, and TLS JA3 Fingerprinting Engine.
Parses Ethernet frames (IPv4/IPv6/802.1Q VLAN) from live router tcpdump streams or PCAP files.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import socket
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

# GREASE values defined in RFC 8701 (ignored when computing JA3)
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


@dataclass
class ParsedPacket:
    ts: float
    wire_len: int
    raw_frame: bytes
    src_mac: str
    dst_mac: str
    ip_version: int
    src_ip: str
    dst_ip: str
    proto: str  # TCP, UDP, ICMP, OTHER
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    # L7 extracted metadata
    l7_proto: str = ""
    sni: str = ""
    alpn: str = ""
    tls_version: str = ""
    ja3: str = ""
    http_host: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_ua: str = ""
    dns_qname: str = ""
    dns_qtype: int = 0
    dns_is_response: bool = False
    dns_answers: List[Tuple[str, str]] = field(default_factory=list)
    dns_resolved_ips: List[str] = field(default_factory=list)
    ssh_banner: str = ""
    is_stratum: bool = False
    is_bittorrent: bool = False


def format_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _read_dns_name(buf: bytes, offset: int, max_jumps: int = 12) -> Tuple[str, int]:
    labels: List[str] = []
    pos = offset
    end_pos = -1
    jumps = 0
    n = len(buf)

    while pos < n:
        length = buf[pos]
        if length == 0:
            pos += 1
            if end_pos == -1:
                end_pos = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= n:
                return "", n
            if end_pos == -1:
                end_pos = pos + 2
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if ptr >= n or jumps >= max_jumps:
                break
            pos = ptr
            jumps += 1
            continue
        if (length & 0xC0) != 0:
            return "", n
        pos += 1
        if pos + length > n:
            break
        labels.append(buf[pos : pos + length].decode("ascii", errors="replace"))
        pos += length

    if end_pos == -1:
        end_pos = pos
    return ".".join(labels).lower().strip("."), end_pos


def parse_dns_payload(payload: bytes, is_tcp: bool = False) -> Optional[dict]:
    if is_tcp:
        if len(payload) < 14:
            return None
        dns_len = struct.unpack("!H", payload[:2])[0]
        payload = payload[2 : 2 + dns_len]

    if len(payload) < 12:
        return None

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    if opcode != 0 or qdcount == 0 or qdcount > 16:
        return None

    pos = 12
    qname = ""
    qtype = 0
    for i in range(qdcount):
        name, pos = _read_dns_name(payload, pos)
        if pos + 4 > len(payload):
            return None
        qt, qc = struct.unpack("!HH", payload[pos : pos + 4])
        pos += 4
        if i == 0:
            qname = name
            qtype = qt

    if not qname or "." not in qname:
        return None

    resolved_ips: List[str] = []
    answers: List[Tuple[str, str]] = []

    if qr == 1 and ancount > 0:
        max_rr = min(ancount, 25)
        for _ in range(max_rr):
            if pos >= len(payload):
                break
            rname, pos = _read_dns_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", payload[pos : pos + 10])
            pos += 10
            if pos + rdlength > len(payload):
                break
            rdata = payload[pos : pos + rdlength]
            pos += rdlength

            if rtype == 1 and rdlength == 4:  # A
                ip_str = socket.inet_ntop(socket.AF_INET, rdata)
                resolved_ips.append(ip_str)
                answers.append((rname or qname, ip_str))
            elif rtype == 28 and rdlength == 16:  # AAAA
                ip_str = socket.inet_ntop(socket.AF_INET6, rdata)
                resolved_ips.append(ip_str)
                answers.append((rname or qname, ip_str))
            elif rtype == 5:  # CNAME
                cname, _ = _read_dns_name(payload, pos - rdlength)
                if cname:
                    answers.append((rname or qname, cname))

    return {
        "qname": qname,
        "qtype": qtype,
        "is_response": bool(qr),
        "resolved_ips": resolved_ips,
        "answers": answers,
    }


TLS_VERSION_MAP = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def parse_tls_client_hello(payload: bytes) -> Optional[dict]:
    """Extract SNI, ALPN, TLS version, and compute exact JA3 MD5 fingerprint."""
    if len(payload) < 43:
        return None
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[2] > 0x04:
        return None

    hs = payload[5:]
    if len(hs) < 38 or hs[0] != 0x01:  # HandshakeType = ClientHello (1)
        return None

    client_ver = struct.unpack("!H", hs[4:6])[0]
    pos = 6 + 32  # client_version (2) + random (32)
    if pos >= len(hs):
        return None

    # Session ID
    sid_len = hs[pos]
    pos += 1 + sid_len
    if pos + 2 > len(hs):
        return None

    # Cipher Suites
    cs_len = struct.unpack("!H", hs[pos : pos + 2])[0]
    pos += 2
    cs_end = min(pos + cs_len, len(hs))
    ciphers: List[int] = []
    p = pos
    while p + 2 <= cs_end:
        c = struct.unpack("!H", hs[p : p + 2])[0]
        if c not in GREASE_VALUES:
            ciphers.append(c)
        p += 2
    pos += cs_len
    if pos >= len(hs):
        return None

    # Compression Methods
    comp_len = hs[pos]
    pos += 1 + comp_len
    if pos + 2 > len(hs):
        return None

    ext_total_len = struct.unpack("!H", hs[pos : pos + 2])[0]
    pos += 2
    ext_end = min(pos + ext_total_len, len(hs))

    extensions: List[int] = []
    curves: List[int] = []
    point_formats: List[int] = []
    sni = ""
    alpn = ""
    negotiated_ver = TLS_VERSION_MAP.get(client_ver, f"0x{client_ver:04x}")

    while pos + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", hs[pos : pos + 4])
        pos += 4
        ext_data = hs[pos : min(pos + ext_len, len(hs))]
        pos += ext_len

        if ext_type in GREASE_VALUES:
            continue
        extensions.append(ext_type)

        # Server Name Indication (0x0000)
        if ext_type == 0x0000 and len(ext_data) >= 5:
            name_type = ext_data[2]
            name_len = struct.unpack("!H", ext_data[3:5])[0]
            if name_type == 0 and 5 + name_len <= len(ext_data):
                sni = ext_data[5 : 5 + name_len].decode("ascii", errors="ignore").lower()

        # Supported Groups / Elliptic Curves (0x000a)
        elif ext_type == 0x000A and len(ext_data) >= 2:
            grp_len = struct.unpack("!H", ext_data[0:2])[0]
            gp = 2
            gend = min(2 + grp_len, len(ext_data))
            while gp + 2 <= gend:
                g = struct.unpack("!H", ext_data[gp : gp + 2])[0]
                if g not in GREASE_VALUES:
                    curves.append(g)
                gp += 2

        # EC Point Formats (0x000b)
        elif ext_type == 0x000B and len(ext_data) >= 1:
            pf_len = ext_data[0]
            for b in ext_data[1 : min(1 + pf_len, len(ext_data))]:
                point_formats.append(b)

        # ALPN (0x0010)
        elif ext_type == 0x0010 and len(ext_data) >= 3:
            proto_len = ext_data[2]
            if 3 + proto_len <= len(ext_data):
                alpn = ext_data[3 : 3 + proto_len].decode("ascii", errors="ignore")

        # Supported Versions (0x002b)
        elif ext_type == 0x002B and len(ext_data) >= 3:
            v_len = ext_data[0]
            vp = 1
            vend = min(1 + v_len, len(ext_data))
            while vp + 2 <= vend:
                v = struct.unpack("!H", ext_data[vp : vp + 2])[0]
                if v == 0x0304:
                    negotiated_ver = "TLS 1.3"
                    break
                vp += 2

    ja3_hash = ""
    if ciphers and extensions:
        ja3_str = (
            f"{client_ver},"
            f"{'-'.join(str(x) for x in ciphers)},"
            f"{'-'.join(str(x) for x in extensions)},"
            f"{'-'.join(str(x) for x in curves)},"
            f"{'-'.join(str(x) for x in point_formats)}"
        )
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

    return {
        "sni": sni,
        "alpn": alpn,
        "tls_version": negotiated_ver,
        "ja3": ja3_hash,
    }


HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ")


def parse_http_request(payload: bytes) -> Optional[dict]:
    if len(payload) < 16 or not payload.startswith(HTTP_METHODS):
        return None
    try:
        header_part = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
        lines = header_part.split("\r\n")
        parts = lines[0].split(" ")
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else "/"
        host = ""
        ua = ""
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                host = line[5:].strip().split(":")[0].lower()
            elif low.startswith("user-agent:"):
                ua = line[11:].strip()
        return {"method": method, "uri": uri[:120], "host": host, "ua": ua[:120]}
    except Exception:
        return None


def decode_ethernet_packet(ts: float, wire_len: int, raw: bytes) -> Optional[ParsedPacket]:
    if len(raw) < 14:
        return None
    dst_mac = format_mac(raw[0:6])
    src_mac = format_mac(raw[6:12])
    eth_type = struct.unpack("!H", raw[12:14])[0]
    offset = 14

    # 802.1Q / QinQ VLAN tags
    while eth_type in (0x8100, 0x88A8):
        if len(raw) < offset + 4:
            return None
        eth_type = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
        offset += 4

    ip_ver = 0
    src_ip = ""
    dst_ip = ""
    next_hdr = 0

    if eth_type == 0x0800:  # IPv4
        if len(raw) < offset + 20:
            return None
        v_ihl = raw[offset]
        ip_ver = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4
        if ip_ver != 4 or ihl < 20 or len(raw) < offset + ihl:
            return None
        next_hdr = raw[offset + 9]
        src_ip = socket.inet_ntop(socket.AF_INET, raw[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntop(socket.AF_INET, raw[offset + 16 : offset + 20])
        offset += ihl
    elif eth_type == 0x86DD:  # IPv6
        if len(raw) < offset + 40:
            return None
        ip_ver = 6
        next_hdr = raw[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 24 : offset + 40])
        offset += 40
    else:
        return None

    l4_data = raw[offset:]
    if next_hdr == 6:  # TCP
        if len(l4_data) < 20:
            return None
        sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", l4_data[:14])
        tcp_hdr_len = ((off_flags >> 12) & 0xF) * 4
        tcp_flags = off_flags & 0x3F
        payload = l4_data[tcp_hdr_len:] if len(l4_data) >= tcp_hdr_len else b""
        pkt = ParsedPacket(
            ts=ts,
            wire_len=wire_len,
            raw_frame=raw,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_version=ip_ver,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto="TCP",
            src_port=sport,
            dst_port=dport,
            tcp_flags=tcp_flags,
        )
        _inspect_tcp_payload(pkt, payload)
        return pkt

    if next_hdr == 17:  # UDP
        if len(l4_data) < 8:
            return None
        sport, dport, ulen, csum = struct.unpack("!HHHH", l4_data[:8])
        payload = l4_data[8:]
        pkt = ParsedPacket(
            ts=ts,
            wire_len=wire_len,
            raw_frame=raw,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_version=ip_ver,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto="UDP",
            src_port=sport,
            dst_port=dport,
        )
        _inspect_udp_payload(pkt, payload)
        return pkt

    if next_hdr in (1, 58):  # ICMP / ICMPv6
        return ParsedPacket(
            ts=ts,
            wire_len=wire_len,
            raw_frame=raw,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_version=ip_ver,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto="ICMP",
        )

    return None


def _inspect_tcp_payload(pkt: ParsedPacket, payload: bytes) -> None:
    if not payload:
        return

    # DNS over TCP (port 53)
    if pkt.src_port == 53 or pkt.dst_port == 53:
        dns = parse_dns_payload(payload, is_tcp=True)
        if dns:
            pkt.l7_proto = "DNS"
            pkt.dns_qname = dns["qname"]
            pkt.dns_qtype = dns["qtype"]
            pkt.dns_is_response = dns["is_response"]
            pkt.dns_resolved_ips = dns["resolved_ips"]
            pkt.dns_answers = dns["answers"]
            return

    # TLS ClientHello (inspected on any port to catch C2 over non-standard ports)
    if payload[0] == 0x16 and len(payload) >= 43:
        tls = parse_tls_client_hello(payload)
        if tls:
            pkt.l7_proto = "TLS"
            pkt.sni = tls["sni"]
            pkt.alpn = tls["alpn"]
            pkt.tls_version = tls["tls_version"]
            pkt.ja3 = tls["ja3"]
            return

    # Plaintext HTTP (inspected on any port)
    http = parse_http_request(payload)
    if http:
        pkt.l7_proto = "HTTP"
        pkt.http_method = http["method"]
        pkt.http_uri = http["uri"]
        pkt.http_host = http["host"]
        pkt.http_ua = http["ua"]
        return

    # SSH Banner
    if payload.startswith(b"SSH-"):
        pkt.l7_proto = "SSH"
        pkt.ssh_banner = payload.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")[:64]
        return

    # BitTorrent Peer Protocol
    if payload.startswith(b"\x13BitTorrent protocol"):
        pkt.l7_proto = "BitTorrent"
        pkt.is_bittorrent = True
        return

    # Stratum Crypto-Mining JSON-RPC
    if b'"mining.' in payload or b'"eth_submitLogin"' in payload or b'"stratum' in payload.lower():
        pkt.l7_proto = "Stratum-Mining"
        pkt.is_stratum = True
        return


def _inspect_udp_payload(pkt: ParsedPacket, payload: bytes) -> None:
    if not payload:
        return

    # DNS / mDNS
    if pkt.src_port in (53, 5353) or pkt.dst_port in (53, 5353):
        dns = parse_dns_payload(payload, is_tcp=False)
        if dns:
            pkt.l7_proto = "mDNS" if (5353 in (pkt.src_port, pkt.dst_port)) else "DNS"
            pkt.dns_qname = dns["qname"]
            pkt.dns_qtype = dns["qtype"]
            pkt.dns_is_response = dns["is_response"]
            pkt.dns_resolved_ips = dns["resolved_ips"]
            pkt.dns_answers = dns["answers"]
            return

    # QUIC (HTTP/3): Long/Short header on 443/8443
    if (pkt.dst_port in (443, 8443) or pkt.src_port in (443, 8443)) and len(payload) >= 20:
        if (payload[0] & 0xC0) == 0xC0 or (payload[0] & 0x40) == 0x40:
            pkt.l7_proto = "QUIC"
            return

    # STUN / WebRTC magic cookie 0x2112A442 at bytes 4..8
    if len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42":
        pkt.l7_proto = "WebRTC/STUN"
        return

    # WireGuard handshake / transport heuristics on common UDP ports
    if pkt.dst_port in (51820, 51821) or pkt.src_port in (51820, 51821):
        pkt.l7_proto = "WireGuard"
        return

    # BitTorrent Mainline DHT
    if payload.startswith(b"d1:ad2:id20:") or payload.startswith(b"d1:rd2:id20:"):
        pkt.l7_proto = "BitTorrent-DHT"
        pkt.is_bittorrent = True
        return

    if pkt.dst_port == 123 or pkt.src_port == 123:
        pkt.l7_proto = "NTP"
    elif pkt.dst_port in (67, 68) or pkt.src_port in (67, 68):
        pkt.l7_proto = "DHCP"
    elif pkt.dst_port == 1900 or pkt.src_port == 1900:
        pkt.l7_proto = "SSDP"


# ==============================================================================
# L7 Application & Service Classification Engine
# Categories use canonical IDs so the UI can display them cleanly in EN or RU.
# ==============================================================================

DOMAIN_APP_RULES: List[Tuple[Tuple[str, ...], str, str]] = [
    # AI & LLM
    (("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"), "ChatGPT / OpenAI", "AI & LLM"),
    (("anthropic.com", "claude.ai"), "Claude / Anthropic", "AI & LLM"),
    (("gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com", "notebooklm.google.com"), "Google Gemini", "AI & LLM"),
    (("perplexity.ai",), "Perplexity AI", "AI & LLM"),
    (("deepseek.com",), "DeepSeek AI", "AI & LLM"),
    (("huggingface.co",), "HuggingFace", "AI & LLM"),
    (("ollama.com",), "Ollama", "AI & LLM"),

    # Messaging & VoIP
    (("telegram.org", "t.me", "telesco.pe", "tdesktop.com", "web.telegram.org"), "Telegram", "Messaging"),
    (("whatsapp.com", "whatsapp.net"), "WhatsApp", "Messaging"),
    (("discord.com", "discordapp.com", "discord.gg", "discord.media"), "Discord", "Messaging"),
    (("signal.org", "whispersystems.org"), "Signal", "Messaging"),
    (("zoom.us", "zoomgov.com"), "Zoom", "Messaging"),
    (("slack.com", "slack-edge.com"), "Slack", "Messaging"),
    (("teams.microsoft.com",), "Microsoft Teams", "Messaging"),

    # Streaming & Media
    (("youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com"), "YouTube", "Streaming & Media"),
    (("twitch.tv", "ttvnw.net", "jtvnw.net"), "Twitch", "Streaming & Media"),
    (("spotify.com", "scdn.co", "spotifycdn.com"), "Spotify", "Streaming & Media"),
    (("netflix.com", "nflxvideo.net", "nflxso.net"), "Netflix", "Streaming & Media"),
    (("plex.tv", "plex.direct"), "Plex Media", "Streaming & Media"),

    # Social & Regional Web
    (("instagram.com", "cdninstagram.com"), "Instagram", "Social & Web"),
    (("facebook.com", "fbcdn.net"), "Facebook", "Social & Web"),
    (("twitter.com", "x.com", "twimg.com"), "X (Twitter)", "Social & Web"),
    (("tiktok.com", "tiktokcdn.com", "byteoversea.com"), "TikTok", "Social & Web"),
    (("reddit.com", "redd.it", "redditmedia.com"), "Reddit", "Social & Web"),
    (("linkedin.com", "licdn.com"), "LinkedIn", "Social & Web"),
    (("vk.com", "userapi.com", "vk-cdn.net"), "VK", "Social & Web"),
    (("yandex.ru", "yandex.net", "yastatic.net", "ya.ru", "yandexcloud.net"), "Yandex", "Social & Web"),

    # Gaming
    (("steampowered.com", "steamcommunity.com", "steamserver.net", "steamcontent.com", "valve.net", "steamstatic.com"), "Steam / Valve", "Gaming"),
    (("epicgames.com", "unrealengine.com"), "Epic Games", "Gaming"),
    (("roblox.com", "rbxcdn.com"), "Roblox", "Gaming"),
    (("riotgames.com", "leagueoflegends.com"), "Riot Games", "Gaming"),
    (("battle.net", "blizzard.com"), "Battle.net", "Gaming"),
    (("playstation.com", "playstation.net"), "PlayStation Network", "Gaming"),
    (("xboxlive.com",), "Xbox Network", "Gaming"),

    # OS & Vendor Telemetry
    (("icloud.com", "apple.com", "mzstatic.com", "cdn-apple.com", "itunes.com", "aaplimg.com", "apple-dns.net"), "Apple / iCloud", "OS & Telemetry"),
    (("events.data.microsoft.com", "vortex.data.microsoft.com", "telemetry.microsoft.com", "settings-win.data.microsoft.com"), "Windows Telemetry", "OS & Telemetry"),
    (("windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "msftconnecttest.com", "microsoft.com", "msedge.net", "live.com", "office.com"), "Microsoft / Windows", "OS & Telemetry"),
    (("ubuntu.com", "canonical.com", "snapcraft.io"), "Ubuntu / Canonical", "OS & Telemetry"),

    # Dev, Cloud & CDN
    (("github.com", "githubusercontent.com", "githubassets.com"), "GitHub", "Development"),
    (("gitlab.com",), "GitLab", "Development"),
    (("pypi.org", "pythonhosted.org"), "PyPI (Python)", "Development"),
    (("npmjs.org", "npmjs.com"), "npm Registry", "Development"),
    (("crates.io", "static.crates.io"), "Crates.io (Rust)", "Development"),
    (("docker.io", "docker.com"), "Docker Hub", "Development"),
    (("google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "1e100.net", "gvt1.com", "gvt2.com"), "Google Cloud / Web", "Cloud & Web"),
    (("cloudflare.com", "cloudflare-dns.com", "cloudflareclient.com", "1dot1dot1dot1.cloudflare-dns.com"), "Cloudflare", "Cloud & Web"),
    (("amazonaws.com", "aws.amazon.com", "cloudfront.net"), "AWS / CloudFront", "Cloud & Web"),
    (("fastly.net",), "Fastly CDN", "Cloud & Web"),
    (("akamai.net", "akamaiedge.net", "akadns.net"), "Akamai CDN", "Cloud & Web"),

    # Remote Access & Reverse Tunnels (Security-Sensitive)
    (("anydesk.com", "net.anydesk.com"), "AnyDesk", "Remote Access"),
    (("teamviewer.com",), "TeamViewer", "Remote Access"),
    (("rustdesk.com",), "RustDesk", "Remote Access"),
    (("ngrok.com", "ngrok-free.app", "ngrok.io"), "Ngrok Tunnel", "Remote Access"),
    (("argotunnel.com", "trycloudflare.com"), "Cloudflare Tunnel", "Remote Access"),
    (("tailscale.com", "tailscale.io"), "Tailscale", "VPN & Security"),

    # Crypto-Mining Pools (High-priority security alert trigger)
    (("nicehash.com", "2miners.com", "nanopool.org", "herominers.com", "supportxmr.com", "minexmr.com", "ethermine.org", "f2pool.com", "unmineable.com"), "Mining Pool", "Crypto-Mining"),
]

# Official Telegram MTProto IPv4 AS62041 / AS62014 CIDRs (often connect without prior DNS)
TELEGRAM_NETWORKS = [
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.12.0/22"),
    ipaddress.ip_network("91.108.16.0/22"),
    ipaddress.ip_network("91.108.20.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("185.76.151.0/24"),
]


def classify_application(
    domain: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    l7_proto: str,
    proc_name: str = "",
    vpn_endpoints: Optional[Iterable[str]] = None,
) -> Tuple[str, str]:
    """Return (app_name, category) using DPI domain, IP ranges, L7 protocol, and host process hint."""
    d = (domain or "").lower().strip(".")
    if d:
        for suffixes, app_name, category in DOMAIN_APP_RULES:
            for sfx in suffixes:
                s = sfx.strip()
                if d == s or d.endswith("." + s):
                    return app_name, category

    if vpn_endpoints and dst_ip in vpn_endpoints:
        return "Configured VPN Endpoint", "VPN & Security"

    try:
        ip_obj = ipaddress.ip_address(dst_ip)
        if ip_obj.version == 4:
            for net in TELEGRAM_NETWORKS:
                if ip_obj in net:
                    return "Telegram (MTProto)", "Messaging"
    except ValueError:
        pass

    if dst_ip in ("8.8.8.8", "8.8.4.4"):
        return "Google Public DNS", "Infrastructure"
    if dst_ip in ("1.1.1.1", "1.0.0.1"):
        return "Cloudflare DNS", "Infrastructure"
    if dst_ip in ("9.9.9.9", "149.112.112.112"):
        return "Quad9 DNS", "Infrastructure"
    if dst_ip in ("77.88.8.8", "77.88.8.1"):
        return "Yandex DNS", "Infrastructure"

    if l7_proto == "Stratum-Mining":
        return "Stratum Miner", "Crypto-Mining"
    if l7_proto in ("BitTorrent", "BitTorrent-DHT"):
        return "BitTorrent P2P", "P2P & Torrent"
    if l7_proto == "WireGuard":
        return "WireGuard VPN", "VPN & Security"
    if l7_proto == "WebRTC/STUN":
        return "WebRTC / VoIP", "Messaging"
    if l7_proto == "SSH" or dst_port == 22:
        return "SSH", "Administration"
    if dst_port == 3389:
        return "Microsoft RDP", "Remote Access"
    if dst_port in (5900, 5901):
        return "VNC Remote", "Remote Access"
    if l7_proto == "NTP" or dst_port == 123:
        return "NTP Time Sync", "Infrastructure"
    if l7_proto in ("DNS", "mDNS") or dst_port == 53:
        return l7_proto or "DNS", "Infrastructure"
    if l7_proto == "DHCP" or dst_port in (67, 68):
        return "DHCP", "Infrastructure"

    p = (proc_name or "").lower()
    if p:
        if "telegram" in p:
            return "Telegram Desktop", "Messaging"
        if "discord" in p:
            return "Discord", "Messaging"
        if "steam" in p:
            return "Steam", "Gaming"
        if p in ("chrome.exe", "chrome", "msedge.exe", "firefox.exe", "firefox", "brave.exe", "brave", "opera.exe", "safari"):
            return f"Browser ({proc_name})", "Cloud & Web"

    if l7_proto == "QUIC" or (proto == "UDP" and dst_port == 443):
        return "HTTPS / QUIC", "Cloud & Web"
    if l7_proto == "TLS" or (proto == "TCP" and dst_port == 443):
        return "HTTPS / TLS", "Cloud & Web"
    if l7_proto == "HTTP" or (proto == "TCP" and dst_port == 80):
        return "HTTP (Plaintext)", "Cloud & Web"

    return f"{proto}/{dst_port}" if dst_port else proto, "Unclassified"
