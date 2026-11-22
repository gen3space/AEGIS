from __future__ import annotations

import socket
import struct

from aegis.dpi_engine import (
    classify_application,
    decode_ethernet_packet,
    parse_dns_payload,
    parse_http_request,
    parse_tls_client_hello,
    shannon_entropy,
)


def _eth_ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = (b"\xaa" * 6) + (b"\xbb" * 6) + struct.pack("!H", 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
    return eth + ip + tcp + payload


def _eth_ipv4_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = (b"\xaa" * 6) + (b"\xbb" * 6) + struct.pack("!H", 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28 + len(payload),
        1,
        0x4000,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return eth + ip + udp + payload


def test_tls_client_hello_and_ja3_extraction() -> None:
    sni = b"api.github.com"
    ext_sni_body = struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni
    ext_sni = struct.pack("!HH", 0x0000, len(ext_sni_body)) + ext_sni_body
    ext_ver = struct.pack("!HHBH", 0x002B, 3, 2, 0x0304)
    # Include a GREASE cipher (0x0A0A) to verify RFC 8701 GREASE filtering
    ciphers = struct.pack("!HHH", 0x0A0A, 0x1301, 0x1302)
    exts = ext_sni + ext_ver
    body = (
        struct.pack("!H", 0x0303)
        + (b"\x22" * 32)
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

    res = parse_tls_client_hello(record)
    assert res is not None
    assert res["sni"] == "api.github.com"
    assert res["tls_version"] == "TLS 1.3"
    assert len(res["ja3"]) == 32

    pkt = decode_ethernet_packet(1.0, len(record) + 54, _eth_ipv4_tcp("192.168.1.50", "140.82.121.4", 51000, 8443, record))
    assert pkt is not None
    assert pkt.l7_proto == "TLS"
    assert pkt.sni == "api.github.com"
    assert pkt.ja3 == res["ja3"]


def test_dns_response_parsing() -> None:
    # Header: id=1, QR=1 (0x8180), qd=1, an=1
    hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)
    # Answer with DNS name pointer 0xC00C -> 93.184.216.34
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    dns_pkt = hdr + question + answer

    parsed = parse_dns_payload(dns_pkt)
    assert parsed is not None
    assert parsed["is_response"] is True
    assert parsed["qname"] == "example.com"
    assert parsed["resolved_ips"] == ["93.184.216.34"]

    pkt = decode_ethernet_packet(1.0, len(dns_pkt) + 42, _eth_ipv4_udp("1.1.1.1", "192.168.1.50", 53, 52000, dns_pkt))
    assert pkt is not None
    assert pkt.l7_proto == "DNS"
    assert pkt.dns_resolved_ips == ["93.184.216.34"]


def test_http_and_stratum_detection() -> None:
    http_raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nUser-Agent: curl/8.5\r\n\r\n"
    h = parse_http_request(http_raw)
    assert h is not None
    assert h["host"] == "api.openai.com"
    assert h["method"] == "GET"

    stratum = b'{"id":1,"method":"mining.subscribe","params":["xmrig/6.21"]}\n'
    pkt = decode_ethernet_packet(1.0, 120, _eth_ipv4_tcp("192.168.1.50", "198.51.100.10", 55000, 3333, stratum))
    assert pkt is not None
    assert pkt.is_stratum is True
    assert pkt.l7_proto == "Stratum-Mining"


def test_application_classification_and_entropy() -> None:
    app, cat = classify_application("chatgpt.com", "104.18.32.7", 443, "TCP", "TLS")
    assert app == "ChatGPT / OpenAI"
    assert cat == "AI & LLM"

    app_tg, cat_tg = classify_application("", "149.154.167.91", 443, "TCP", "TLS")
    assert "Telegram" in app_tg
    assert cat_tg == "Messaging"

    assert shannon_entropy("aaaaaaaaaa") == 0.0
    assert shannon_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6") > 3.8
