#!/usr/bin/env python3
"""Pruebas de regresión con capturas sintéticas (sin datos reales).

Uso:  python3 -I tests/test_casos.py
Cada caso reproduce un fallo visto en capturas reales de soporte:
  1. tcpdump -i any (SLL) con VLAN: copia etiquetada 802.1Q + copia sin etiquetar -> IPs basura y [RETX] falsos.
  2. Fichero rtpdump (Wireshark 'Save as rtpdump') -> "Formato no reconocido".
  3. pcap reconstruido (export Homer/sngrep) solo SIP con hora local guardada como UTC -> SIN_RTP crítico falso.
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import voip_pcap_analyzer as v  # noqa: E402

FAILS = []


def check(cond, msg):
    print(("OK   " if cond else "FALLO") + " " + msg)
    if not cond:
        FAILS.append(msg)


def ipv4_udp(src, dst, sp, dp, payload, ident=0x1234, ttl=64):
    udp = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0xBEEF) + payload
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0x4000, ttl, 17, 0,
                       bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + udp


def write_pcap(path, linktype, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for ts, data in frames:
            fh.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(data), len(data)) + data)


def sip_invite(sdp=b""):
    body = sdp
    return (b"INVITE sip:100@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
            b"From: <sip:200@10.0.0.1>;tag=a\r\nTo: <sip:100@10.0.0.2>\r\nCall-ID: test-1\r\nCSeq: 1 INVITE\r\n"
            b"Contact: <sip:200@10.0.0.1>\r\nContent-Type: application/sdp\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)


def caso_sll_vlan(tmp):
    pkt = ipv4_udp("10.0.0.1", "10.0.0.2", 5060, 5060, sip_invite())
    sll_plain = struct.pack("!HHH8sH", 4, 1, 6, b"\x00" * 8, 0x0800)
    sll_vlan = struct.pack("!HHH8sH", 4, 1, 6, b"\x00" * 8, 0x8100) + struct.pack("!HH", 30, 0x0800)
    # copia saliente con checksum UDP distinto (offload) y 19 ms de desfase, como en la captura real
    pkt2 = pkt[:26] + b"\x00\x00" + pkt[28:]
    p = os.path.join(tmp, "sll.pcap")
    write_pcap(p, 113, [(1000.0, sll_plain + pkt), (1000.0, sll_vlan + pkt), (1000.019, sll_plain + pkt2)])
    r = v.analyze(p, v.DEFAULT_SIP_PORTS, set())
    check(r["stats"].get("sip") == 1, f"SLL+VLAN: 1 solo INVITE tras deduplicar (sip={r['stats'].get('sip')})")
    check(r["stats"].get("dup_frames") == 2, f"SLL+VLAN: 2 duplicados descartados ({r['stats'].get('dup_frames')})")
    check(set(r["hosts"]) <= {"10.0.0.1", "10.0.0.2"}, f"SLL+VLAN: sin hosts inventados ({sorted(r['hosts'])})")
    check(any(f["code"] == "DUPLICADOS_CAPTURA" for f in r["findings"]), "SLL+VLAN: hallazgo DUPLICADOS_CAPTURA")


def caso_rtpdump(tmp):
    p = os.path.join(tmp, "flujo.rtp")
    with open(p, "wb") as fh:
        fh.write(b"#!rtpplay1.0 192.0.2.20/4000\n")                        # destino
        fh.write(struct.pack("!IIIHH", 1700000000, 0, 0xC0000201, 30000, 0))  # inicio + ORIGEN 192.0.2.1:30000
        for i in range(200):
            rtp = struct.pack("!BBHII", 0x80, 8, i, i * 160, 0xABCD) + bytes((x * 7 + i) & 0xFF for x in range(160))
            fh.write(struct.pack("!HHI", 8 + len(rtp), len(rtp), i * 20) + rtp)
    r = v.analyze(p, v.DEFAULT_SIP_PORTS, set())
    check(r["format"] == "rtpdump", f"rtpdump: formato reconocido ({r['format']})")
    flows = [s["flow"] for s in r["rtp_streams"]]
    check(flows == ["192.0.2.1:30000 -> 192.0.2.20:4000"], f"rtpdump: sentido correcto ({flows})")
    check(r["probable_capture_host"] == "no aplica", "rtpdump: sin deducir punto de captura")


def caso_export_solo_sip(tmp):
    real = 1717169860           # hora real (FreeSWITCH)
    shown = real - 5 * 3600     # el export guardó hora local UTC-5 como UTC
    port = 24344
    sdp = (f"v=0\r\no=FreeSWITCH {real - port} {real - port + 1} IN IP4 10.0.0.2\r\ns=FreeSWITCH\r\n"
           f"c=IN IP4 10.0.0.2\r\nt=0 0\r\nm=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n").encode()
    ok = (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\nFrom: <sip:200@10.0.0.1>;tag=a\r\n"
          b"To: <sip:100@10.0.0.2>;tag=b\r\nCall-ID: test-1\r\nCSeq: 1 INVITE\r\nContact: <sip:100@10.0.0.2>\r\n"
          b"Content-Type: application/sdp\r\nContent-Length: " + str(len(sdp)).encode() + b"\r\n\r\n" + sdp)
    ack = (b"ACK sip:100@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK2\r\n"
           b"From: <sip:200@10.0.0.1>;tag=a\r\nTo: <sip:100@10.0.0.2>;tag=b\r\nCall-ID: test-1\r\nCSeq: 1 ACK\r\n"
           b"Content-Length: 0\r\n\r\n")
    bye = ack.replace(b"ACK sip", b"BYE sip").replace(b"1 ACK", b"2 BYE").replace(b"bK2", b"bK3")
    eth = b"\x00" * 12 + b"\x08\x00"
    frames = [(shown, ipv4_udp("10.0.0.1", "10.0.0.2", 5060, 5060, sip_invite(), 0x4B2D, 30)),
              (shown + 1, ipv4_udp("10.0.0.2", "10.0.0.1", 5060, 5060, ok, 0x4B2D, 30)),
              (shown + 1.1, ipv4_udp("10.0.0.1", "10.0.0.2", 5060, 5060, ack, 0x4B2D, 30)),
              (shown + 30, ipv4_udp("10.0.0.1", "10.0.0.2", 5060, 5060, bye, 0x4B2D, 30))]
    p = os.path.join(tmp, "export.pcap")
    write_pcap(p, 1, [(t, eth + d) for t, d in frames])
    r = v.analyze(p, v.DEFAULT_SIP_PORTS, set())
    codes = {f["code"]: f for f in r["findings"]}
    check("PCAP_RECONSTRUIDO" in codes, "export: detecta pcap reconstruido (IP-ID/TTL constantes)")
    check("CAPTURA_SOLO_SIP" in codes, "export: detecta captura solo SIP")
    check(codes.get("SIN_RTP", {}).get("severity") == "info", "export: SIN_RTP baja a info (no hay medios que juzgar)")
    off = r.get("clock_offset_s")
    check(off is not None and abs(off + 18000) < 2, f"export: desfase de reloj -5 h detectado ({off})")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        caso_sll_vlan(tmp)
        caso_rtpdump(tmp)
        caso_export_solo_sip(tmp)
    print(f"\n{'TODO OK' if not FAILS else str(len(FAILS)) + ' FALLO(S)'}")
    sys.exit(1 if FAILS else 0)
