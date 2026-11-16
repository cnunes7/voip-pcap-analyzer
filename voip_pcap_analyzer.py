#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
voip_pcap_analyzer.py - Analizador VoIP (SIP / SDP / RTP / RTCP / ICMP) sin dependencias externas.

Lee pcap, pcapng (y .gz) y produce:
  * un informe legible (stdout) con resumen, hallazgos, llamadas, escalera SIP y calidad RTP
  * un JSON completo (--json) para consultas posteriores

Uso:
  python3 voip_pcap_analyzer.py captura.pcap [--json out.json] [--ladder] [--call CALL-ID]
                                [--max-calls 10] [--local-ip 10.0.0.5 ...] [--sip-port 5080 ...]

Solo usa la biblioteca estándar de Python 3.8+.
"""
import argparse
import bisect
import gzip
import ipaddress
import json
import math
import re
import socket
import struct
import sys
from array import array
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------------------
DEFAULT_SIP_PORTS = {5060, 5061, 5062, 5070, 5080, 5090}
NON_RTP_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 162, 389, 443, 500, 514, 1812, 1813,
                 1900, 4500, 5353, 9060}
STATIC_PT = {
    0: ("PCMU", 8000), 3: ("GSM", 8000), 4: ("G723", 8000), 8: ("PCMA", 8000),
    9: ("G722", 8000), 10: ("L16", 44100), 11: ("L16", 44100), 13: ("CN", 8000),
    15: ("G728", 8000), 18: ("G729", 8000), 26: ("JPEG", 90000), 31: ("H261", 90000),
    34: ("H263", 90000),
}
def _ulaw(b):
    b = ~b & 0xFF
    t = (((b & 0x0F) << 3) + 0x84) << ((b & 0x70) >> 4)
    return (0x84 - t) if (b & 0x80) else (t - 0x84)


def _alaw(b):
    b ^= 0x55
    t = (b & 0x0F) << 4
    seg = (b & 0x70) >> 4
    t = t + 8 if seg == 0 else ((t + 0x108) << (seg - 1))
    return t if (b & 0x80) else -t


G711_ABS = {0: [abs(_ulaw(i)) for i in range(256)], 8: [abs(_alaw(i)) for i in range(256)]}
G711_SQ = {k: [v * v for v in t] for k, t in G711_ABS.items()}

# E-model simplificado: (Ie, Bpl) por códec
EMODEL = {
    "PCMU": (0, 25.1), "PCMA": (0, 25.1), "G722": (13, 21.0), "G729": (11, 19.0),
    "OPUS": (6, 30.0), "GSM": (20, 10.0), "G723": (15, 16.1), "ILBC": (10, 32.0),
    "AMR": (10, 20.0), "AMR-WB": (10, 20.0),
}
COMPACT = {
    "i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact", "l": "content-length",
    "c": "content-type", "k": "supported", "s": "subject", "e": "content-encoding",
    "o": "event", "r": "refer-to", "b": "referred-by", "x": "session-expires",
    "u": "allow-events", "a": "accept-contact", "j": "reject-contact", "y": "identity",
}
SIP_START = re.compile(rb"^(?:[A-Z]{3,12} [^ \r\n]+ SIP/2\.0\r?\n|SIP/2\.0 \d{3}[ \r\n])")
SIP_START_SEARCH = re.compile(rb"(?:(?<=\n)|^)(?:[A-Z]{3,12} [^ \r\n]+ SIP/2\.0\r?\n|SIP/2\.0 \d{3}[ \r\n])")
SEV_ORDER = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}
SEV_LABEL = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MEDIO", "bajo": "BAJO", "info": "INFO"}

SIP_CODES_ES = {
    400: "Petición mal formada", 401: "Requiere autenticación (UAS)", 402: "Pago requerido",
    403: "Prohibido / rechazado por política", 404: "Destino no encontrado", 405: "Método no permitido",
    406: "No aceptable", 407: "Requiere autenticación (proxy)", 408: "Timeout de la petición",
    410: "Destino ya no existe", 413: "Petición demasiado grande", 414: "R-URI demasiado larga",
    415: "Tipo de contenido no soportado", 416: "Esquema URI no soportado", 420: "Extensión no soportada",
    421: "Extensión requerida", 422: "Session-Expires demasiado bajo", 423: "Intervalo demasiado breve",
    480: "Temporalmente no disponible", 481: "Diálogo/transacción no existe", 482: "Bucle detectado",
    483: "Demasiados saltos", 484: "Dirección incompleta", 485: "Ambiguo", 486: "Ocupado",
    487: "Petición cancelada", 488: "No aceptable aquí (SDP/códec)", 491: "Petición pendiente (glare)",
    493: "No descifrable", 500: "Error interno del servidor", 501: "No implementado",
    502: "Bad gateway", 503: "Servicio no disponible", 504: "Timeout del servidor/gateway",
    505: "Versión no soportada", 513: "Mensaje demasiado grande", 580: "Precondición fallida",
    600: "Ocupado en todas partes", 603: "Rechazada", 604: "No existe en ninguna parte",
    606: "No aceptable",
}
Q850_ES = {
    1: "Número no asignado", 2: "Sin ruta a la red", 3: "Sin ruta al destino", 6: "Canal inaceptable",
    16: "Liberación normal", 17: "Usuario ocupado", 18: "Usuario no responde",
    19: "Sin respuesta (alertando)", 20: "Abonado ausente", 21: "Llamada rechazada",
    22: "Número cambiado", 27: "Destino fuera de servicio", 28: "Formato de número inválido",
    29: "Facilidad rechazada", 31: "Normal, sin especificar", 34: "No hay circuito/canal disponible",
    38: "Red fuera de servicio", 41: "Fallo temporal", 42: "Congestión del equipo de conmutación",
    44: "Canal solicitado no disponible", 47: "Recurso no disponible", 50: "Facilidad no suscrita",
    57: "Capacidad portadora no autorizada", 58: "Capacidad portadora no disponible",
    65: "Capacidad portadora no implementada", 79: "Servicio no implementado",
    88: "Destino incompatible", 95: "Mensaje inválido", 102: "Expiración de temporizador",
    111: "Error de protocolo", 127: "Interworking, sin especificar",
}


_PRIV_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_private(ip):
    """Direcciones no enrutables en Internet que delatan NAT (RFC1918, CGNAT, link-local, ULA)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _PRIV_NETS)


def fmt_utc(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def ep(ip, port):
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"


# --------------------------------------------------------------------------------------
# Lectura de capturas
# --------------------------------------------------------------------------------------
def open_any(path):
    with open(path, "rb") as fh:
        magic = fh.read(2)
    return gzip.open(path, "rb") if magic == b"\x1f\x8b" else open(path, "rb")


def iter_frames(path, info):
    """Genera (n, ts, linktype, data, orig_len)."""
    f = open_any(path)
    head = f.read(4)
    if len(head) < 4:
        raise ValueError("Archivo vacío o demasiado corto")
    if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, ns = "<", head == b"\x4d\x3c\xb2\xa1"
    elif head in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, ns = ">", head == b"\xa1\xb2\x3c\x4d"
    elif head == b"\x0a\x0d\x0d\x0a":
        info["format"] = "pcapng"
        yield from _iter_pcapng(f, info)
        return
    else:
        raise ValueError("Formato no reconocido (no es pcap ni pcapng). Si es .cap de otro "
                         "producto, conviértelo con editcap -F pcap.")
    info["format"] = "pcap" + (" (ns)" if ns else "")
    rest = f.read(20)
    _, _, _, _, snap, lt = struct.unpack(endian + "HHiIII", rest)
    lt &= 0xFFFF
    info["snaplen"] = snap
    div = 1e9 if ns else 1e6
    n = 0
    while True:
        h = f.read(16)
        if len(h) < 16:
            if h:
                info["warnings"].append("La última trama está truncada (captura cortada).")
            break
        ts_s, ts_f, incl, orig = struct.unpack(endian + "IIII", h)
        if incl > 0x4000000:
            info["warnings"].append(f"Registro corrupto tras la trama {n}; se detiene la lectura.")
            break
        data = f.read(incl)
        if len(data) < incl:
            info["warnings"].append("La última trama está truncada (captura cortada).")
            break
        n += 1
        yield n, ts_s + ts_f / div, lt, data, orig


def _iter_pcapng(f, info):
    endian = "<"
    ifaces = []
    n = 0
    last_ts = 0.0
    first = True
    while True:
        if first:
            hdr = b"\x0a\x0d\x0d\x0a" + f.read(4)
            first = False
        else:
            hdr = f.read(8)
        if len(hdr) < 8:
            break
        if hdr[:4] == b"\x0a\x0d\x0d\x0a":
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", hdr[4:8])[0]
            f.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", hdr)
        if blen < 12:
            info["warnings"].append("Bloque pcapng corrupto; se detiene la lectura.")
            break
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            info["warnings"].append("La captura pcapng está truncada.")
            break
        c = body[:-4]
        if btype == 1:  # IDB
            lt, _, snap = struct.unpack(endian + "HHI", c[:8])
            div = 1e6
            o = 8
            while o + 4 <= len(c):
                code, ol = struct.unpack(endian + "HH", c[o:o + 4])
                if code == 0:
                    break
                val = c[o + 4:o + 4 + ol]
                if code == 9 and val:
                    v = val[0]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                o += 4 + ((ol + 3) & ~3)
            ifaces.append((lt, div))
            info["snaplen"] = snap
        elif btype in (6, 2):  # EPB / obsolete PB
            if btype == 6:
                iid, tsh, tsl, cap, orig = struct.unpack(endian + "IIIII", c[:20])
            else:
                iid, _, tsh, tsl, cap, orig = struct.unpack(endian + "HHIIII", c[:20])
            lt, div = ifaces[iid] if iid < len(ifaces) else (1, 1e6)
            last_ts = ((tsh << 32) | tsl) / div
            n += 1
            yield n, last_ts, lt, c[20:20 + cap], orig
        elif btype == 3:  # SPB
            orig = struct.unpack(endian + "I", c[:4])[0]
            lt, _ = ifaces[0] if ifaces else (1, 1e6)
            n += 1
            yield n, last_ts, lt, c[4:4 + orig], orig


def l2_to_ip(lt, d):
    """Devuelve el payload IP o None."""
    try:
        if lt == 1:
            et = struct.unpack("!H", d[12:14])[0]
            off = 14
            while et in (0x8100, 0x88A8, 0x9100):
                et = struct.unpack("!H", d[off + 2:off + 4])[0]
                off += 4
            if et in (0x8847, 0x8848):
                while off + 4 <= len(d):
                    bos = d[off + 2] & 1
                    off += 4
                    if bos:
                        break
                return d[off:]
            if et == 0x8864:  # PPPoE
                return d[off + 8:]
            if et in (0x0800, 0x86DD):
                return d[off:]
            return None
        if lt == 113:
            return d[16:]
        if lt == 276:
            return d[20:]
        if lt in (0, 108):
            return d[4:]
        if lt in (101, 12, 14, 228, 229):
            return d
    except (struct.error, IndexError):
        return None
    return None


# --------------------------------------------------------------------------------------
# Parsers SIP / SDP
# --------------------------------------------------------------------------------------
def _tag(v):
    m = re.search(r";\s*tag=([^;>\s,]+)", v or "", re.I)
    return m.group(1) if m else None


def _uri(v):
    if not v:
        return ""
    m = re.search(r"<([^>]*)>", v)
    if m:
        return m.group(1)
    return v.split(";")[0].strip()


def _user(uri):
    m = re.match(r"^(?:sips?|tel):([^@;>]+)", uri or "", re.I)
    return m.group(1) if m else ""


def _hostport(uri):
    m = re.match(r"^(?:sips?):(?:[^@]+@)?(\[[^\]]+\]|[^;:>?]+)(?::(\d+))?", uri or "", re.I)
    if not m:
        return None, None
    return m.group(1).strip("[]"), (int(m.group(2)) if m.group(2) else None)


def parse_sdp(body):
    sess_c, sess_dir, origin = None, None, None
    media = []
    for line in body.splitlines():
        line = line.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        k, v = line[0], line[2:].strip()
        cur = media[-1] if media else None
        if k == "o":
            origin = v
        elif k == "c":
            ip = v.split()[-1].split("/")[0] if v.split() else ""
            if cur:
                cur["c"] = ip
            else:
                sess_c = ip
        elif k == "m":
            p = v.split()
            if len(p) >= 3:
                try:
                    port = int(p[1].split("/")[0])
                except ValueError:
                    port = 0
                media.append({"type": p[0], "port": port, "proto": p[2], "fmts": p[3:],
                              "rtpmap": {}, "fmtp": {}, "dir": None, "c": None, "ptime": None,
                              "crypto": False, "dtls": False, "rtcp_mux": False, "ice": False})
        elif k == "a":
            name, _, val = v.partition(":")
            name = name.lower()
            if name in ("sendrecv", "sendonly", "recvonly", "inactive"):
                if cur:
                    cur["dir"] = name
                else:
                    sess_dir = name
            elif cur is None:
                continue
            elif name == "rtpmap":
                pt, _, enc = val.partition(" ")
                parts = enc.split("/")
                try:
                    cur["rtpmap"][pt.strip()] = (parts[0], int(parts[1]) if len(parts) > 1 else 8000)
                except ValueError:
                    pass
            elif name == "fmtp":
                pt, _, par = val.partition(" ")
                cur["fmtp"][pt.strip()] = par.strip()
            elif name == "ptime":
                cur["ptime"] = val.strip()
            elif name == "crypto":
                cur["crypto"] = True
            elif name == "fingerprint":
                cur["dtls"] = True
            elif name == "rtcp-mux":
                cur["rtcp_mux"] = True
            elif name == "candidate":
                cur["ice"] = True
    out = []
    for m in media:
        codecs = []
        for f in m["fmts"]:
            if f in m["rtpmap"]:
                nm, rate = m["rtpmap"][f]
            elif f.isdigit() and int(f) in STATIC_PT:
                nm, rate = STATIC_PT[int(f)]
            else:
                nm, rate = f"PT{f}", 8000
            codecs.append({"pt": int(f) if f.isdigit() else f, "name": nm, "rate": rate})
        out.append({"type": m["type"], "ip": m["c"] or sess_c, "port": m["port"],
                    "proto": m["proto"], "codecs": codecs,
                    "dir": m["dir"] or sess_dir or "sendrecv", "ptime": m["ptime"],
                    "srtp": ("SAVP" in m["proto"]) or m["crypto"] or m["dtls"],
                    "rtcp_mux": m["rtcp_mux"], "ice": m["ice"]})
    return {"origin": origin, "media": out}


def parse_sip(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    idx, sep = text.find("\r\n\r\n"), 4
    if idx < 0:
        idx, sep = text.find("\n\n"), 2
    head, body = (text, "") if idx < 0 else (text[:idx], text[idx + sep:])
    lines = re.split(r"\r?\n", head)
    first = lines[0].strip()
    headers = []
    for ln in lines[1:]:
        if ln[:1] in (" ", "\t") and headers:
            n, v = headers[-1]
            headers[-1] = (n, v + " " + ln.strip())
            continue
        if ":" not in ln:
            continue
        n, v = ln.split(":", 1)
        n = n.strip().lower()
        headers.append((COMPACT.get(n, n), v.strip()))
    H = defaultdict(list)
    for n, v in headers:
        H[n].append(v)
    m = {}
    if first.startswith("SIP/2.0"):
        p = first.split(" ", 2)
        try:
            m["status"] = int(p[1])
        except (IndexError, ValueError):
            return None
        m["type"], m["reason_phrase"] = "response", (p[2] if len(p) > 2 else "")
        m["first_line"] = f"{m['status']} {m['reason_phrase']}"
    else:
        p = first.split(" ")
        if len(p) < 3:
            return None
        m["type"], m["method"], m["ruri"] = "request", p[0], p[1]
        m["first_line"] = f"{p[0]} {p[1]}"
    g = lambda k: H[k][0] if H.get(k) else ""  # noqa: E731
    m["call_id"] = g("call-id")
    cs = g("cseq").split()
    m["cseq"] = int(cs[0]) if cs and cs[0].isdigit() else 0
    m["cseq_method"] = cs[1].upper() if len(cs) > 1 else ""
    m["from"], m["to"] = g("from"), g("to")
    m["from_tag"], m["to_tag"] = _tag(m["from"]), _tag(m["to"])
    m["from_user"], m["to_user"] = _user(_uri(m["from"])), _user(_uri(m["to"]))
    vias = []
    for v in H.get("via", []):
        vias.extend([x.strip() for x in v.split(",") if x.strip()])
    m["vias"] = vias
    top = vias[0] if vias else ""
    b = re.search(r";\s*branch=([^;,\s]+)", top, re.I)
    m["branch"] = b.group(1) if b else ""
    m["contact"] = _uri(g("contact"))
    m["user_agent"] = g("user-agent") or g("server")
    m["reason"] = H.get("reason", [])
    m["warning"] = H.get("warning", [])
    m["pai"] = g("p-asserted-identity")
    m["diversion"] = g("diversion")
    m["session_expires"] = g("session-expires")
    m["record_route"] = H.get("record-route", [])
    m["route"] = H.get("route", [])
    m["retry_after"] = g("retry-after")
    m["expires"] = g("expires")
    m["content_type"] = g("content-type").lower()
    m["x_headers"] = {n: v for n, v in headers if n.startswith("x-")}
    cl = g("content-length")
    m["content_length"] = int(cl) if cl.strip().isdigit() else None
    m["body_len"] = len(body.encode("utf-8", "replace"))
    m["truncated_body"] = m["content_length"] is not None and m["body_len"] < m["content_length"]
    m["sdp"] = None
    if body and ("sdp" in m["content_type"] or "multipart" in m["content_type"]):
        sdp_txt = body
        if "multipart" in m["content_type"]:
            i = body.find("v=0")
            if i >= 0:
                j = body.find("\n--", i)
                sdp_txt = body[i:j if j > 0 else None]
            else:
                sdp_txt = ""
        if "v=0" in sdp_txt:
            m["sdp"] = parse_sdp(sdp_txt)
    m["isup"] = "application/isup" in body.lower() or "isup" in m["content_type"]
    if m.get("method") == "INFO" and body:
        sig = re.search(r"Signal\s*=\s*(\S)", body)
        m["info_dtmf"] = sig.group(1) if sig else None
    m["headers_raw"] = head[:4000]
    return m


def parse_reason(values):
    out = []
    for v in values:
        proto = v.split(";")[0].strip()
        c = re.search(r"cause\s*=\s*(\d+)", v, re.I)
        t = re.search(r'text\s*=\s*"([^"]*)"', v, re.I)
        cause = int(c.group(1)) if c else None
        desc = ""
        if proto.upper() == "Q.850" and cause in Q850_ES:
            desc = Q850_ES[cause]
        elif proto.upper() == "SIP" and cause in SIP_CODES_ES:
            desc = SIP_CODES_ES[cause]
        out.append({"protocol": proto, "cause": cause, "text": t.group(1) if t else "", "desc_es": desc})
    return out


# --------------------------------------------------------------------------------------
# RTP
# --------------------------------------------------------------------------------------
class RtpStream:
    __slots__ = ("src", "sport", "dst", "dport", "ssrc", "arr", "seq", "rts", "pts", "marker",
                 "bytes", "first_frame", "last_frame", "events", "sizes", "ptarr", "lvl")

    def __init__(self, src, sport, dst, dport, ssrc):
        self.src, self.sport, self.dst, self.dport, self.ssrc = src, sport, dst, dport, ssrc
        self.arr, self.seq, self.rts = array("d"), array("H"), array("I")
        self.ptarr = array("B")
        self.lvl = []   # (t, rms_dbov, clip_ratio) por paquete G.711 (muestreado)
        self.pts = Counter()
        self.marker = 0
        self.bytes = 0
        self.first_frame = self.last_frame = 0
        self.events = []
        self.sizes = Counter()


def stream_stats(st, clock, codec_name):
    n = len(st.seq)
    res = {"packets": n}
    if n == 0:
        return res
    # Números de secuencia extendidos
    max_ext = None
    min_ext = None
    seen = set()
    dups = ooo = resets = 0
    gaps = []  # (t, perdidos)
    seg_expected = 0
    seg_min = None
    for i in range(n):
        s = st.seq[i]
        if max_ext is None:
            ext = s
            max_ext = min_ext = seg_min = ext
            seen.add(ext)
            continue
        base = (max_ext & ~0xFFFF) | s
        cands = (base - 65536, base, base + 65536)
        ext = min(cands, key=lambda x: abs(x - max_ext))
        if abs(ext - max_ext) > 3000:  # salto enorme => reinicio de secuencia
            resets += 1
            seg_expected += max_ext - seg_min + 1
            ext = s + ((max_ext // 65536) + 2) * 65536
            seg_min = ext
            max_ext = ext
            seen.add(ext)
            continue
        if ext in seen:
            dups += 1
            continue
        seen.add(ext)
        if ext > max_ext:
            if ext - max_ext > 1:
                gaps.append((st.arr[i], ext - max_ext - 1))
            max_ext = ext
        else:
            ooo += 1
        min_ext = min(min_ext, ext)
    expected = seg_expected + (max_ext - seg_min + 1)
    received = len(seen)
    lost = max(0, expected - received)
    loss_pct = 100.0 * lost / expected if expected else 0.0
    # Jitter RFC 3550 sobre el payload principal (los eventos DTMF comparten secuencia pero no reloj de audio).
    main_pt = st.pts.most_common(1)[0][0]
    J = 0.0
    jmax = 0.0
    ts_jumps = []
    deltas = []
    pairs = []
    prev = None
    for i in range(n):
        if st.ptarr[i] != main_pt:
            continue
        if prev is not None:
            da = st.arr[i] - st.arr[prev]
            dr = (st.rts[i] - st.rts[prev]) & 0xFFFFFFFF
            if dr > 0x7FFFFFFF:
                dr -= 0x100000000
            dseq = (st.seq[i] - st.seq[prev]) & 0xFFFF
            pairs.append((i, da, dr, dseq))
        prev = i
    # Paso "normal" por paquete: mediana de Δts por Δseq y de Δllegada por Δseq
    steps_r = sorted(dr / dseq for _, _, dr, dseq in pairs if 0 < dseq < 50)
    steps_a = sorted(da / dseq for _, da, _, dseq in pairs if 0 < dseq < 50)
    med_r = steps_r[len(steps_r) // 2] if steps_r else 160
    med_a = steps_a[len(steps_a) // 2] if steps_a else 0.02
    for i, da, dr, dseq in pairs:
        exp_r = med_r * dseq if 0 < dseq < 3000 else dr
        # Salto de timestamp: el reloj RTP se desvía >100 ms de lo esperado mientras la llegada es normal
        if clock and abs(dr - exp_r) > 0.1 * clock and da < 3 * med_a * max(dseq, 1):
            ts_jumps.append({"t": st.arr[i], "delta_rtp_ts": dr, "seq": st.seq[i]})
            continue
        D = da * clock - dr
        if clock and abs(D) > clock:
            ts_jumps.append({"t": st.arr[i], "delta_rtp_ts": dr, "seq": st.seq[i]})
            continue
        J += (abs(D) - J) / 16.0
        jmax = max(jmax, J)
    for i in range(1, n):
        deltas.append(st.arr[i] - st.arr[i - 1])
    jit_ms = J / clock * 1000 if clock else 0
    jmax_ms = jmax / clock * 1000 if clock else 0
    sd = sorted(deltas)
    hist = Counter(int(round(d * 1000 / 5.0)) * 5 for d in deltas)
    med = sd[len(sd) // 2] * 1000 if sd else 0
    maxd = sd[-1] * 1000 if sd else 0
    big = []
    thr = max(0.2, 3 * med / 1000) if med else 0.2
    for i, d in enumerate(deltas):
        if d >= thr:
            jump = (st.seq[i + 1] - st.seq[i]) & 0xFFFF
            kind = "pausa del emisor (secuencia continua)" if jump == 1 else (
                f"pérdida de {jump - 1} paquetes" if jump < 3000 else "salto de secuencia")
            big.append({"t": st.arr[i + 1], "gap_ms": round(d * 1000, 1), "kind": kind,
                        "lost_in_gap": jump - 1 if 1 < jump < 3000 else 0})
    big.sort(key=lambda x: -x["gap_ms"])
    dur = st.arr[-1] - st.arr[0]
    # MOS estimado (E-model simplificado, sin retardo de extremo a extremo conocido)
    ie, bpl = EMODEL.get((codec_name or "").upper(), (0, 25.1))
    ppl = loss_pct
    ie_eff = ie + (95 - ie) * ppl / (ppl + bpl) if (ppl + bpl) else ie
    eff_lat = jit_ms * 2 + 10
    idd = eff_lat / 40 if eff_lat < 160 else (eff_lat - 120) / 10
    R = 93.2 - idd - ie_eff
    R = max(0, min(100, R))
    mos = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
    if st.lvl:
        lv = [x[1] for x in st.lvl]
        silent = sum(1 for x in lv if x < -60)
        active = [x for x in lv if x >= -50]
        clip = [x[2] for x in st.lvl]
        # perfil por segundos: nivel medio en ventanas de 1 s para localizar tramos mudos
        prof = []
        t_start = st.lvl[0][0]
        win = defaultdict(list)
        for t_, l_, _ in st.lvl:
            win[int(t_ - t_start)].append(l_)
        mute_runs, run = [], None
        for sec in range(0, int(st.lvl[-1][0] - t_start) + 1):
            vals = win.get(sec)
            m = max(vals) if vals else -99
            prof.append(round(m, 1))
            if m < -60:
                run = [sec, sec] if run is None else [run[0], sec]
            else:
                if run and run[1] - run[0] >= 2:
                    mute_runs.append((t_start + run[0], run[1] - run[0] + 1))
                run = None
        if run and run[1] - run[0] >= 2:
            mute_runs.append((t_start + run[0], run[1] - run[0] + 1))
        res["audio"] = {
            "silent_pct": round(100 * silent / len(lv), 1),
            "active_level_dbov": round(sum(active) / len(active), 1) if active else None,
            "peak_level_dbov": round(max(lv), 1),
            "clipping_pct": round(100 * sum(1 for c in clip if c > 0.02) / len(clip), 2),
            "mute_runs": [{"t": t_, "dur_s": d_} for t_, d_ in mute_runs[:10]],
            "profile_1s_max_dbov": prof[:600],
        }
    res.update({
        "expected": expected, "lost": lost, "loss_pct": round(loss_pct, 2),
        "duplicates": dups, "out_of_order": ooo, "seq_resets": resets,
        "loss_events": len(gaps), "max_burst_lost": max((g[1] for g in gaps), default=0),
        "jitter_ms": round(jit_ms, 2), "jitter_max_ms": round(jmax_ms, 2),
        "median_delta_ms": round(med, 2), "max_delta_ms": round(maxd, 1),
        "delta_hist_ms": {str(k): v for k, v in sorted(hist.items()) if v >= max(3, 0.005 * len(deltas))},
        "big_gaps": big[:8], "big_gaps_count": len(big),
        "pauses": sum(1 for g in big if g["kind"].startswith("pausa")),
        "ts_jumps": ts_jumps[:10], "ts_jumps_count": len(ts_jumps),
        "duration_s": round(dur, 3), "mos_est": round(mos, 2), "r_factor": round(R, 1),
    })
    return res


# --------------------------------------------------------------------------------------
# Analizador
# --------------------------------------------------------------------------------------
ACDR_RX_TP = {0, 4, 18, 20, 27, 35}       # Net2Dsp, Net2Host, DspDecoder, VoipDecoder, ...
ACDR_TX_TP = {1, 5, 17, 19, 21, 22, 28}   # Dsp2Net, Host2Net, P2P, DspEncoder, VoipEncoder, NetEncoder, ...


class Analyzer:
    def __init__(self, sip_ports, acdr_ports=(925,), vxlan_ports=(4789, 8472)):
        self.acdr_ports = set(acdr_ports)
        self.vxlan_ports = set(vxlan_ports)
        self.ttl = defaultdict(Counter)
        self.encap = set()
        self.encap_src = set()
        self.acdr_types = Counter()
        self.acdr_tp_seen = defaultdict(set)
        self.acdr_pref = {}
        self.sip_ports = set(sip_ports)
        self.sip_msgs = []
        self.rtp = {}
        self.rtcp = []
        self.icmp = []
        self.tcp = defaultdict(list)
        self.tls = Counter()
        self.frags = {}
        self.stats = Counter()
        self.linktypes = Counter()
        self.first_ts = self.last_ts = None
        self.ip_pk = Counter()
        self.info = {"warnings": [], "format": None, "snaplen": None}

    # ---------------- IP ----------------
    def decode_ip(self, buf):
        if not buf:
            return None
        v = buf[0] >> 4
        if v == 4 and len(buf) >= 20:
            ihl = (buf[0] & 15) * 4
            tot = struct.unpack("!H", buf[2:4])[0] or len(buf)
            pkt = buf[ihl:tot]
            ident = struct.unpack("!H", buf[4:6])[0]
            ff = struct.unpack("!H", buf[6:8])[0]
            mf, off = ff & 0x2000, (ff & 0x1FFF) * 8
            proto = buf[9]
            src, dst = socket.inet_ntop(socket.AF_INET, buf[12:16]), socket.inet_ntop(socket.AF_INET, buf[16:20])
            if mf or off:
                return self._frag((src, dst, ident, proto), off, mf, pkt, src, dst, proto)
            return src, dst, proto, pkt
        if v == 6 and len(buf) >= 40:
            plen = struct.unpack("!H", buf[4:6])[0]
            nh = buf[6]
            src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
            pkt = buf[40:40 + plen] if plen else buf[40:]
            while nh in (0, 43, 60, 44) and len(pkt) >= 8:
                if nh == 44:
                    nnh = pkt[0]
                    fo = struct.unpack("!H", pkt[2:4])[0]
                    ident = struct.unpack("!I", pkt[4:8])[0]
                    return self._frag((src, dst, ident, 44), fo & 0xFFF8, fo & 1, pkt[8:], src, dst, nnh)
                hl = (pkt[1] + 1) * 8
                nh, pkt = pkt[0], pkt[hl:]
            return src, dst, nh, pkt
        return None

    def _frag(self, key, off, mf, data, src, dst, proto):
        self.stats["ip_fragments"] += 1
        ent = self.frags.setdefault(key, {"parts": {}, "total": None})
        ent["parts"][off] = data
        if not mf:
            ent["total"] = off + len(data)
        if ent["total"] is None:
            return None
        buf = bytearray()
        for o in sorted(ent["parts"]):
            if o > len(buf):
                return None
            buf[o:o + len(ent["parts"][o])] = ent["parts"][o]
        if len(buf) < ent["total"]:
            return None
        del self.frags[key]
        self.stats["ip_reassembled"] += 1
        return src, dst, proto, bytes(buf[:ent["total"]])

    # ---------------- Bucle principal ----------------
    def run(self, path):
        for n, ts, lt, data, orig in iter_frames(path, self.info):
            self.stats["frames"] += 1
            self.linktypes[lt] += 1
            if self.first_ts is None:
                self.first_ts = ts
            self.last_ts = ts
            ipb = l2_to_ip(lt, data)
            if ipb is None:
                self.stats["non_ip"] += 1
                continue
            self.process_ip(n, ts, ipb, orig > len(data), 0)
        self.reassemble_tcp()

    def process_ip(self, n, ts, ipb, trunc, depth):
        """Procesa un paquete IP; depth>0 cuando viene desencapsulado (VXLAN, GRE, ACDR)."""
        if not ipb or depth > 3:
            return
        r = self.decode_ip(ipb)
        if r is None:
            return
        src, dst, proto, pkt = r
        if (ipb[0] >> 4) == 4 and len(ipb) >= 9:
            self.ttl[(src, depth > 0)][ipb[8]] += 1
        elif (ipb[0] >> 4) == 6 and len(ipb) >= 8:
            self.ttl[(src, depth > 0)][ipb[7]] += 1
        try:
            if proto == 17 and len(pkt) >= 8:
                sp, dp, ul = struct.unpack("!HHH", pkt[:6])
                pl = pkt[8:ul] if 8 <= ul <= len(pkt) else pkt[8:]
                if self.decap_udp(n, ts, src, sp, dst, dp, pl, trunc, depth):
                    return
                self.udp(n, ts, src, sp, dst, dp, pl, trunc)
            elif proto == 6 and len(pkt) >= 20:
                sp, dp, seq = struct.unpack("!HHI", pkt[:8])
                off = (pkt[12] >> 4) * 4
                pl = pkt[off:]
                self.tcp_seg(n, ts, src, sp, dst, dp, seq, pkt[13], pl)
            elif proto in (1, 58) and len(pkt) >= 8:
                self.icmp_pkt(n, ts, src, dst, proto, pkt)
            elif proto == 47 and len(pkt) >= 4:
                self.gre(n, ts, src, dst, pkt, trunc, depth)
        except (struct.error, IndexError):
            self.stats["decode_errors"] += 1

    # ---------------- Encapsulaciones ----------------
    def decap_udp(self, n, ts, src, sp, dst, dp, pl, trunc, depth):
        """VXLAN / GENEVE (port mirroring en la nube) y AudioCodes Debug Recording. True si lo consumió."""
        if dp in self.vxlan_ports and len(pl) >= 16 and (pl[0] & 0x08):
            self.stats["vxlan"] += 1
            self.encap.add(f"VXLAN (UDP {dp}) desde {src}")
            self.encap_src.add(f"{src} (origen VXLAN)")
            ipb = l2_to_ip(1, pl[8:])
            if ipb:
                self.process_ip(n, ts, ipb, trunc, depth + 1)
            return True
        if dp == 6081 and len(pl) >= 8:
            self.stats["geneve"] += 1
            self.encap.add(f"GENEVE (UDP 6081) desde {src}")
            self.encap_src.add(f"{src} (origen GENEVE)")
            ol = (pl[0] & 0x3F) * 4
            ptype = struct.unpack("!H", pl[2:4])[0]
            inner = pl[8 + ol:]
            ipb = l2_to_ip(1, inner) if ptype == 0x6558 else inner
            if ipb:
                self.process_ip(n, ts, ipb, trunc, depth + 1)
            return True
        if (dp in self.acdr_ports or sp in self.acdr_ports) and pl and (pl[0] >> 4) == 0 and 2 <= (pl[0] & 0xF) <= 9:
            self.acdr(n, ts, src, pl, trunc, depth)
            return True
        return False

    def gre(self, n, ts, src, dst, pkt, trunc, depth):
        flags, ptype = struct.unpack("!HH", pkt[:4])
        off = 4 + (4 if flags & 0x8000 else 0) + (4 if flags & 0x2000 else 0) + (4 if flags & 0x1000 else 0)
        inner = pkt[off:]
        self.stats["gre"] += 1
        self.encap_src.add(f"{src} (origen GRE/ERSPAN)")
        if ptype == 0x88BE:      # ERSPAN tipo II
            self.encap.add(f"ERSPAN II desde {src}")
            ipb = l2_to_ip(1, inner[8:])
        elif ptype == 0x22EB:    # ERSPAN tipo III
            self.encap.add(f"ERSPAN III desde {src}")
            ipb = l2_to_ip(1, inner[12:])
        elif ptype == 0x6558:
            self.encap.add(f"GRE Ethernet desde {src}")
            ipb = l2_to_ip(1, inner)
        elif ptype in (0x0800, 0x86DD):
            self.encap.add(f"GRE IP desde {src}")
            ipb = inner
        else:
            return
        if ipb:
            self.process_ip(n, ts, ipb, trunc, depth + 1)

    def acdr(self, n, ts, sbc, pl, trunc, depth):
        """AudioCodes Debug Recording (Mediant SBC/GW), formato según packet-acdr.c de Wireshark."""
        v = pl[0] & 0xF
        hb = 15 if v < 5 else 19 if v < 7 else 23 if v == 7 else 24 if v == 8 else 28
        cid = 4 if v >= 9 else 2
        o = 1 + (6 if v <= 3 else 4) + (2 if v >= 4 else 0) + 2 * cid
        if len(pl) < hb:
            return
        extra, tp, mt = pl[o], pl[o + 1], pl[o + 2]
        ext = pl[o + 3] if v >= 5 else 0
        mii = v >= 3 and (extra & 0x01) and extra != 0xAA
        added = bool(extra & 0x08) and extra != 0xAA
        ipv6 = bool(extra & 0x02)
        po = hb + ext + (4 if mii else 0)
        payload = pl[po:]
        e = pl[hb:hb + ext]
        self.stats["acdr"] += 1
        self.acdr_types[(tp, mt)] += 1
        self.encap.add(f"AudioCodes Debug Recording (ACDR v{v}) desde {sbc}")
        self.encap_src.add(f"{sbc} (SBC AudioCodes)")
        al = 16 if ipv6 else 4
        fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        if mt in (1, 2, 27, 28) or 51 <= mt <= 60:
            if tp not in ACDR_RX_TP and tp not in ACDR_TX_TP:
                return
            if len(e) < al + 4 or not payload:
                return
            rip = socket.inet_ntop(fam, e[:al])
            p1, p2 = struct.unpack("!HH", e[al:al + 4])
            if tp in ACDR_RX_TP:   # recibido de la red: src=remoto
                s, sp, d, dp = rip, p1, sbc, p2
            else:                  # enviado a la red: dst=remoto
                s, sp, d, dp = sbc, p2, rip, p1
            self.acdr_tp_seen[(s, sp, d, dp)].add(tp)
            if mt in (2, 28):
                self.rtcp_pkt(n, ts, s, sp, d, dp, payload)
            else:
                self.rtp_pkt(n, ts, s, sp, d, dp, payload, tag=tp)
            return
        if mt in (10, 11, 12, 37):   # SIP / señalización
            if added:
                self.process_ip(n, ts, payload, trunc, depth + 1)
            elif len(e) >= 12:
                s, d = socket.inet_ntop(socket.AF_INET, e[0:4]), socket.inet_ntop(socket.AF_INET, e[4:8])
                sp, dp = struct.unpack("!HH", e[8:12])
                if SIP_START.match(payload[:300]):
                    self.add_sip(payload, n, ts, s, sp, d, dp, "ACDR")
            return
        # mt 5 (syslog/Info) duplica la señalización en texto: se ignora para no contar dos veces.

    def udp(self, n, ts, src, sp, dst, dp, pl, trunc):
        self.stats["udp"] += 1
        if pl[:4] == b"HEP3":
            self.hep3(n, ts, pl)
            return
        if SIP_START.match(pl[:300]):
            if trunc:
                self.stats["sip_truncated_snaplen"] += 1
            self.add_sip(pl, n, ts, src, sp, dst, dp, "UDP")
            return
        if pl.strip(b"\r\n\x00") == b"" and len(pl) <= 4:
            self.stats["sip_keepalive"] += 1
            return
        if sp in NON_RTP_PORTS or dp in NON_RTP_PORTS or sp in self.sip_ports or dp in self.sip_ports:
            return
        if len(pl) >= 8 and (pl[0] >> 6) == 2:
            pt = pl[1]
            if 192 <= pt <= 223:
                self.rtcp_pkt(n, ts, src, sp, dst, dp, pl)
            elif len(pl) >= 12:
                if trunc:
                    self.stats["rtp_truncated"] += 1
                self.rtp_pkt(n, ts, src, sp, dst, dp, pl)

    def rtp_pkt(self, n, ts, src, sp, dst, dp, pl, tag=None):
        if len(pl) < 12 or (pl[0] >> 6) != 2:
            return
        if tag is not None:
            # ACDR puede registrar el mismo paquete en varios trace points: usar solo el primero visto.
            k = (src, sp, dst, dp, pl[8:12])
            first = self.acdr_pref.setdefault(k, tag)
            if first != tag:
                return
        b0, b1 = pl[0], pl[1]
        cc, x, p = b0 & 15, (b0 >> 4) & 1, (b0 >> 5) & 1
        seq, rts, ssrc = struct.unpack("!HII", pl[2:12])
        hl = 12 + cc * 4
        if x and len(pl) >= hl + 4:
            hl += 4 + struct.unpack("!H", pl[hl + 2:hl + 4])[0] * 4
        plen = len(pl) - hl - (pl[-1] if p and pl else 0)
        if plen < 0:
            return
        key = (src, sp, dst, dp, ssrc)
        st = self.rtp.get(key)
        if st is None:
            if len(self.rtp) > 20000:
                return
            st = self.rtp[key] = RtpStream(src, sp, dst, dp, ssrc)
            st.first_frame = n
        st.last_frame = n
        st.arr.append(ts)
        st.seq.append(seq)
        st.rts.append(rts)
        pt = b1 & 0x7F
        st.ptarr.append(pt)
        st.pts[pt] += 1
        st.marker += b1 >> 7
        st.bytes += plen
        st.sizes[plen] += 1
        if pt >= 96 and plen == 4 and len(st.events) < 5000:
            st.events.append((ts, pt, rts, pl[hl:hl + 4]))
        if pt in G711_SQ and plen >= 40 and (len(st.seq) % 2 == 0 or len(st.seq) < 30000) and len(st.lvl) < 30000:
            body = pl[hl:hl + plen]
            sq = G711_SQ[pt]
            ab = G711_ABS[pt]
            e = sum(sq[x] for x in body) / plen
            clip = sum(1 for x in body if ab[x] >= 30000) / plen
            st.lvl.append((ts, 10 * math.log10(e / (32768.0 ** 2)) if e > 0 else -99.0, clip))

    def rtcp_pkt(self, n, ts, src, sp, dst, dp, pl):
        self.stats["rtcp"] += 1
        o = 0
        while o + 8 <= len(pl):
            if (pl[o] >> 6) != 2:
                break
            rc, pt = pl[o] & 31, pl[o + 1]
            ln = (struct.unpack("!H", pl[o + 2:o + 4])[0] + 1) * 4
            blk = pl[o:o + ln]
            if pt in (200, 201) and len(blk) >= 8:
                rep = struct.unpack("!I", blk[4:8])[0]
                q = 28 if pt == 200 else 8
                for _ in range(rc):
                    if q + 24 > len(blk):
                        break
                    about, = struct.unpack("!I", blk[q:q + 4])
                    fl = blk[q + 4]
                    cum = int.from_bytes(blk[q + 5:q + 8], "big", signed=True)
                    _, jit, lsr, dlsr = struct.unpack("!IIII", blk[q + 8:q + 24])
                    self.rtcp.append({"frame": n, "ts": ts, "src": src, "sport": sp, "dst": dst, "dport": dp,
                                      "type": "SR" if pt == 200 else "RR", "reporter_ssrc": f"0x{rep:08X}",
                                      "about_ssrc": f"0x{about:08X}", "fraction_lost_pct": round(fl * 100 / 256, 1),
                                      "cum_lost": cum, "jitter_ts": jit})
                    q += 24
            o += ln
            if ln == 0:
                break

    def hep3(self, n, ts, pl):
        self.stats["hep3"] += 1
        o = 6
        f = {}
        while o + 6 <= len(pl):
            _, t, ln = struct.unpack("!HHH", pl[o:o + 6])
            if ln < 6:
                break
            f[t] = pl[o + 6:o + ln]
            o += ln
        try:
            fam = f.get(1, b"\x02")[0]
            if fam == 2 and 3 in f:
                s, d = socket.inet_ntop(socket.AF_INET, f[3]), socket.inet_ntop(socket.AF_INET, f[4])
            else:
                s, d = socket.inet_ntop(socket.AF_INET6, f[5]), socket.inet_ntop(socket.AF_INET6, f[6])
            sp, dp = struct.unpack("!H", f[7])[0], struct.unpack("!H", f[8])[0]
            hts = struct.unpack("!I", f[9])[0] + struct.unpack("!I", f[10])[0] / 1e6 if 9 in f else ts
            body = f.get(15, b"")
            tr = {6: "TCP", 17: "UDP"}.get(f.get(2, b"\x11")[0], "UDP")
        except (KeyError, IndexError, struct.error, ValueError):
            return
        if SIP_START.match(body[:300]):
            self.add_sip(body, n, hts, s, sp, d, dp, f"HEP/{tr}")

    def tcp_seg(self, n, ts, src, sp, dst, dp, seq, flags, pl):
        self.stats["tcp"] += 1
        key = (src, sp, dst, dp)
        if flags & 0x04 and (sp in self.sip_ports or dp in self.sip_ports):
            self.stats["tcp_rst_sip"] += 1
        if not pl:
            return
        if pl[0] == 0x16 and pl[1:2] == b"\x03" or (dp == 5061 or sp == 5061) and not SIP_START.match(pl[:300]):
            self.tls[key] += 1
            return
        if key in self.tcp or sp in self.sip_ports or dp in self.sip_ports or SIP_START.match(pl[:300]):
            self.tcp[key].append((seq, ts, n, bytes(pl)))

    def reassemble_tcp(self):
        for key, segs in self.tcp.items():
            src, sp, dst, dp = key
            base = segs[0][0]
            segs2 = sorted(((s - base) & 0xFFFFFFFF, ts, n, pl) for s, ts, n, pl in segs)
            chunks = []
            buf, marks, nxt = bytearray(), [], None
            for rel, ts, n, pl in segs2:
                if nxt is not None and rel + len(pl) <= nxt:
                    continue
                if nxt is not None and rel < nxt:
                    pl = pl[nxt - rel:]
                    rel = nxt
                if nxt is not None and rel > nxt:
                    chunks.append((bytes(buf), marks))
                    buf, marks = bytearray(), []
                    self.stats["tcp_gaps"] += 1
                marks.append((len(buf), ts, n))
                buf += pl
                nxt = rel + len(pl)
            chunks.append((bytes(buf), marks))
            for data, marks in chunks:
                offs = [m[0] for m in marks]
                pos = 0
                while True:
                    mm = SIP_START_SEARCH.search(data, pos)
                    if not mm:
                        break
                    s = mm.start()
                    he = data.find(b"\r\n\r\n", s)
                    if he < 0:
                        break
                    hdr = data[s:he]
                    cl = re.search(rb"\r\n(?:Content-Length|l)\s*:\s*(\d+)", hdr, re.I)
                    end = he + 4 + (int(cl.group(1)) if cl else 0)
                    i = max(0, bisect.bisect_right(offs, min(end, len(data)) - 1) - 1)
                    _, ts, n = marks[i]
                    self.add_sip(data[s:end], n, ts, src, sp, dst, dp, "TCP")
                    pos = end if end > s else s + 1

    def icmp_pkt(self, n, ts, src, dst, proto, pkt):
        t, c = pkt[0], pkt[1]
        unreachable = (proto == 1 and t == 3) or (proto == 58 and t == 1)
        if not unreachable:
            return
        inner = self.decode_ip(pkt[8:]) if proto == 1 else None
        if proto == 58 and len(pkt) >= 48:
            inner = self.decode_ip(pkt[8:])
        rec = {"frame": n, "ts": ts, "from": src, "to": dst, "code": c}
        if inner:
            isrc, idst, ipr, ip = inner
            rec.update({"orig_src": isrc, "orig_dst": idst, "orig_proto": ipr})
            if len(ip) >= 4:
                rec["orig_sport"], rec["orig_dport"] = struct.unpack("!HH", ip[:4])
        codes = {0: "red inalcanzable", 1: "host inalcanzable", 3: "puerto inalcanzable",
                 10: "prohibido administrativamente", 13: "prohibido administrativamente"}
        rec["desc"] = codes.get(c, f"código {c}")
        self.icmp.append(rec)

    def add_sip(self, raw, n, ts, src, sp, dst, dp, transport):
        m = parse_sip(raw)
        if not m:
            return
        m.update({"frame": n, "ts": ts, "src": src, "sport": sp, "dst": dst, "dport": dp,
                  "transport": transport})
        self.sip_msgs.append(m)
        self.stats["sip"] += 1
        self.ip_pk[src] += 1
        self.ip_pk[dst] += 1


# --------------------------------------------------------------------------------------
# Análisis de llamadas
# --------------------------------------------------------------------------------------
def finding(code, sev, title, detail, call_id=None, evidence=None, suspect=None, hint=None):
    return {"code": code, "severity": sev, "title": title, "detail": detail, "call_id": call_id,
            "evidence": evidence or [], "suspect": suspect, "hint": hint}


def build_calls(an):
    calls = OrderedDict()
    for m in sorted(an.sip_msgs, key=lambda x: (x["ts"], x["frame"])):
        calls.setdefault(m["call_id"] or f"(sin Call-ID #{m['frame']})", []).append(m)
    return calls


def side_label(owner):
    return "llamante (A)" if owner == "A" else "llamado (B)"


def analyze_invite_call(cid, msgs, t0, an):
    F = []
    rel = lambda t: round(t - t0, 3) if t is not None else None  # noqa: E731
    ev = lambda m, d="": {"frame": m["frame"], "t": rel(m["ts"]), "msg": m["first_line"][:80],  # noqa: E731
                          "src": ep(m["src"], m["sport"]), "dst": ep(m["dst"], m["dport"]), "note": d}
    invs = [m for m in msgs if m["type"] == "request" and m.get("method") == "INVITE"]
    init = next((m for m in invs if not m["to_tag"]), invs[0])
    a_tag = init["from_tag"]
    A = {"ip": init["src"], "port": init["sport"]}
    B = {"ip": init["dst"], "port": init["dport"]}

    def owner_of(m):
        if m["type"] == "request":
            return "A" if m["from_tag"] == a_tag else "B"
        return "B" if m["from_tag"] == a_tag else "A"

    for m in msgs:
        m["owner"] = owner_of(m)
    ua = {"A": None, "B": None}
    for m in msgs:
        if m["user_agent"] and not ua[m["owner"]]:
            ua[m["owner"]] = m["user_agent"]
    hops = sorted({(m["src"], m["dst"]) for m in invs if not m["to_tag"]})

    # Retransmisiones
    keyc = Counter()
    first_of = {}
    for m in msgs:
        if m["type"] == "request":
            k = ("Q", m["method"], m["cseq"], m["branch"], m["src"], m["sport"], m["dst"], m["dport"])
        else:
            k = ("R", m["status"], m["cseq"], m["cseq_method"], m["to_tag"], m["src"], m["sport"], m["dst"], m["dport"])
        keyc[k] += 1
        m["retrans"] = keyc[k] > 1
        first_of.setdefault(k, m)
    retrans = {f"{k[1]} (CSeq {k[2]}) {ep(k[-4], k[-3])}->{ep(k[-2], k[-1])}": c - 1 for k, c in keyc.items() if c > 1}

    init_cseqs = sorted({m["cseq"] for m in invs if not m["to_tag"]})
    last_cseq = init_cseqs[-1]
    inv_resp = [m for m in msgs if m["type"] == "response" and m["cseq_method"] == "INVITE"]
    init_resp = [m for m in inv_resp if m["cseq"] in init_cseqs]
    t_inv = init["ts"]
    r100 = next((m for m in init_resp if m["status"] == 100), None)
    r18x = next((m for m in init_resp if 180 <= m["status"] < 200), None)
    finals = [m for m in init_resp if m["status"] >= 200 and m["cseq"] == last_cseq]
    final = finals[0] if finals else None
    auths = [m for m in init_resp if m["status"] in (401, 407)]
    ok = final is not None and 200 <= final["status"] < 300
    acks = [m for m in msgs if m["type"] == "request" and m.get("method") == "ACK" and m["cseq"] == last_cseq]
    ack2xx = [a for a in acks if ok and a["ts"] >= final["ts"]]
    byes = [m for m in msgs if m["type"] == "request" and m.get("method") == "BYE"]
    bye = byes[0] if byes else None
    bye_resp = next((m for m in msgs if m["type"] == "response" and m["cseq_method"] == "BYE"), None)
    cancel = next((m for m in msgs if m["type"] == "request" and m.get("method") == "CANCEL"), None)
    reinv = [m for m in invs if m["to_tag"] and not m["retrans"]]
    updates = [m for m in msgs if m["type"] == "request" and m.get("method") == "UPDATE" and not m["retrans"]]

    summary = OrderedDict()
    summary["call_id"] = cid
    summary["from_user"], summary["to_user"] = init["from_user"], init["to_user"]
    summary["ruri"] = init["ruri"]
    summary["A"], summary["B"] = {**A, "user_agent": ua["A"]}, {**B, "user_agent": ua["B"]}
    summary["hops"] = [f"{s} -> {d}" for s, d in hops]
    summary["start_utc"] = fmt_utc(t_inv)
    summary["t_invite"] = rel(t_inv)
    summary["t_100_ms"] = round((r100["ts"] - t_inv) * 1000, 1) if r100 else None
    summary["pdd_s"] = round(r18x["ts"] - t_inv, 3) if r18x else None
    summary["first_18x"] = r18x["status"] if r18x else None
    summary["final_status"] = final["status"] if final else None
    summary["final_reason_phrase"] = final["reason_phrase"] if final else None
    summary["final_from"] = side_label(final["owner"]) + f" {final['src']}" if final else None
    summary["final_reason_hdr"] = parse_reason(final["reason"]) if final else []
    summary["answered"] = ok
    summary["t_answer_s"] = round(final["ts"] - t_inv, 3) if ok else None
    summary["ack_for_2xx"] = bool(ack2xx) if ok else None
    summary["auth_challenges"] = len(auths)
    summary["reinvites"] = len(reinv)
    summary["updates"] = len(updates)
    summary["retransmissions"] = retrans
    summary["isup_in_body"] = any(m["isup"] for m in msgs)
    summary["session_expires"] = next((m["session_expires"] for m in msgs if m["session_expires"]), "")
    if bye:
        summary["bye_by"] = side_label(bye["owner"])
        summary["bye_src"] = ep(bye["src"], bye["sport"])
        summary["bye_reason"] = parse_reason(bye["reason"])
        summary["bye_response"] = bye_resp["status"] if bye_resp else None
        summary["duration_s"] = round(bye["ts"] - final["ts"], 3) if ok else None
    elif cancel:
        summary["cancel_by"] = side_label(cancel["owner"])
        summary["cancel_after_s"] = round(cancel["ts"] - t_inv, 3)
        summary["cancel_reason"] = parse_reason(cancel["reason"])
    if ok and not bye:
        summary["duration_s"] = round(an.last_ts - final["ts"], 3)
        summary["note"] = "Sin BYE en la captura (llamada en curso al terminar la captura o BYE no capturado)."
    summary["info_dtmf"] = "".join(m.get("info_dtmf") or "" for m in msgs if m.get("info_dtmf"))

    # ----------------- Detectores de señalización -----------------
    if final is None and not cancel:
        inv_re = keyc[("Q", "INVITE", last_cseq, init["branch"], init["src"], init["sport"], init["dst"], init["dport"])]
        if not init_resp:
            F.append(finding("INVITE_SIN_RESPUESTA", "critico", "INVITE sin ninguna respuesta",
                             f"El INVITE hacia {ep(B['ip'], B['port'])} se envió {inv_re} vez/veces y no se vio "
                             "ninguna respuesta (ni 100 Trying). El destino no recibe el INVITE o su respuesta no vuelve.",
                             cid, [ev(init)], suspect=f"camino hacia {B['ip']} / {B['ip']}",
                             hint="Comprobar alcanzabilidad IP/puerto, firewall/ACL del destino, IP de señalización "
                                  "autorizada en el carrier, DNS/NAPTR, y si hay ICMP unreachable en la captura."))
        else:
            F.append(finding("SIN_RESPUESTA_FINAL", "alto", "La llamada no recibió respuesta final",
                             "Hay respuestas provisionales pero ninguna final ni CANCEL en la captura.", cid,
                             [ev(init_resp[-1])], hint="Puede que la captura termine antes; si no, timeout del lado B."))
    if r100 is None and init_resp and final is not None and final["ts"] - t_inv > 0.5 and init["transport"] == "UDP":
        F.append(finding("SIN_100_TRYING", "bajo", "No se ve 100 Trying",
                         "El INVITE por UDP no recibió 100 Trying; provoca retransmisiones innecesarias.", cid,
                         [ev(init)], suspect=side_label("B")))
    if final is not None and final["status"] >= 300:
        st = final["status"]
        reasons = parse_reason(final["reason"])
        rtxt = "; ".join(f"{r['protocol']} cause={r['cause']} {r['text'] or r['desc_es']}" for r in reasons)
        if st == 487 and cancel:
            sev, title = "info", "Llamada cancelada por el llamante (487 tras CANCEL)"
        elif st in (486, 600, 603) or (st == 480 and r18x):
            sev, title = "info", f"Rechazo de usuario/destino: {st} {SIP_CODES_ES.get(st, '')}"
        elif st in (401, 407):
            sev, title = "alto", f"Autenticación no superada ({st})"
        else:
            sev = "critico" if st >= 500 or st in (403, 404, 408, 488, 415, 420, 421, 484) else "alto"
            title = f"Llamada rechazada con {st} {final['reason_phrase']} ({SIP_CODES_ES.get(st, '')})"
        F.append(finding("RESPUESTA_FALLO", sev, title,
                         f"Respuesta final {st} enviada por {side_label(final['owner'])} desde {ep(final['src'], final['sport'])}"
                         f" (User-Agent/Server: {final['user_agent'] or 'n/d'}). "
                         + (f"Reason: {rtxt}. " if rtxt else "")
                         + (f"Warning: {'; '.join(final['warning'])}. " if final["warning"] else "")
                         + (f"Retry-After: {final['retry_after']}. " if final["retry_after"] else ""),
                         cid, [ev(init), ev(final)],
                         suspect=(f"{side_label('A')} (credenciales/realm o IP no autorizada)" if st in (401, 407)
                                  else f"{side_label(final['owner'])} ({final['src']}) o lo que haya detrás")))
    if len(auths) >= 2 and not ok:
        F.append(finding("BUCLE_AUTH", "alto", "Desafíos de autenticación repetidos",
                         f"{len(auths)} respuestas 401/407: las credenciales o el realm no son aceptados.", cid,
                         [ev(a) for a in auths[:3]], suspect=side_label("A"),
                         hint="Revisar usuario/contraseña/realm del gateway y si el carrier autentica por IP en lugar de digest."))
    if ok and not ack2xx:
        ok_rt = sum(1 for m in finals if m["status"] < 300)
        bye_t = (bye["ts"] - final["ts"]) if bye else None
        det = (f"El 200 OK (desde {ep(final['src'], final['sport'])}) se retransmitió {ok_rt - 1} veces y no se vio ACK. ")
        if bye_t is not None and 28 <= bye_t <= 40:
            det += f"El {bye['method']} llega a los {bye_t:.1f}s del 200 OK: patrón clásico de corte a los 32 s (Timer H/64*T1). "
        ct_ip, _ = _hostport(final["contact"])
        if ct_ip and is_private(ct_ip) and not is_private(final["src"]):
            det += f"El Contact del 200 OK anuncia IP privada {ct_ip} aunque el mensaje sale de {final['src']}: el ACK se enruta a una IP inalcanzable. "
        if final["record_route"]:
            det += f"El 200 lleva Record-Route ({final['record_route'][0][:80]}); comprobar que el ACK sigue la ruta. "
        F.append(finding("SIN_ACK_200", "critico", "200 OK sin ACK (la llamada se cae ~32 s)", det, cid,
                         [ev(final)] + ([ev(bye)] if bye else []),
                         suspect=f"camino del ACK: {side_label('A')} -> {side_label('B')}",
                         hint="El ACK lo genera el llamante y se envía al Contact/Route del 200. Causas típicas: Contact con IP "
                              "privada (NAT del lado B sin corregir), Record-Route mal formado, firewall en el camino de vuelta, "
                              "ALG SIP. Mirar si el ACK sale del lado A en una captura en ese extremo."))
    if bye and bye_resp is None:
        F.append(finding("BYE_SIN_RESPUESTA", "medio", "BYE sin respuesta",
                         "El BYE no recibió 200 OK; el otro extremo puede quedar con la llamada colgada (canal zombi).",
                         cid, [ev(bye)], suspect=side_label("B" if bye["owner"] == "A" else "A")))
    elif bye_resp is not None and bye_resp["status"] == 481:
        F.append(finding("BYE_481", "medio", "BYE respondido con 481 (diálogo inexistente)",
                         "El receptor del BYE ya no conocía el diálogo: tags/Call-ID alterados por un B2BUA/SBC o la llamada ya estaba liberada.",
                         cid, [ev(bye), ev(bye_resp)]))
    se = summary["session_expires"]
    se_val = int(re.match(r"\d+", se).group()) if se and re.match(r"\d+", se) else None
    if ok and bye and se_val:
        d = bye["ts"] - final["ts"]
        if abs(d - se_val) <= max(2, se_val * 0.05) or abs(d - se_val / 2) <= 2:
            F.append(finding("SESSION_TIMER", "alto", "El corte coincide con el Session-Expires",
                             f"BYE a los {d:.1f}s con Session-Expires={se_val}: el refresco (re-INVITE/UPDATE) no se hizo o falló.",
                             cid, [ev(bye)], hint="Ver si hubo re-INVITE/UPDATE de refresco y su respuesta; revisar 'refresher'."))
    for m in reinv + updates:
        resp = next((r for r in msgs if r["type"] == "response" and r["cseq"] == m["cseq"]
                     and r["cseq_method"] == m["method"] and r["status"] >= 200), None)
        if resp is None or resp["status"] >= 300:
            F.append(finding("REINVITE_FALLIDO", "medio",
                             f"{m['method']} en diálogo {'sin respuesta' if resp is None else 'rechazado con ' + str(resp['status'])}",
                             f"{m['method']} enviado por {side_label(m['owner'])}"
                             f"{' (posible hold/cambio de medios)' if m['sdp'] else ''}.",
                             cid, [ev(m)] + ([ev(resp)] if resp else []),
                             suspect=side_label("B" if m["owner"] == "A" else "A")))
    for r in summary.get("bye_reason", []):
        if r["cause"] and r["cause"] not in (16, 31) or (r["protocol"].upper() == "SIP" and r["cause"] not in (None, 200)):
            F.append(finding("BYE_CAUSA_ANORMAL", "medio", f"BYE con causa {r['protocol']} {r['cause']} ({r['desc_es'] or r['text']})",
                             f"El BYE de {summary['bye_by']} indica una causa distinta de liberación normal.", cid, [ev(bye)],
                             suspect=summary["bye_by"]))
    if any(m["truncated_body"] for m in msgs):
        F.append(finding("SIP_TRUNCADO", "medio", "Mensajes SIP con cuerpo truncado",
                         "El Content-Length es mayor que el cuerpo capturado: snaplen corto o fragmentación no capturada.", cid))

    # ----------------- SDP -----------------
    sdps = []
    for m in msgs:
        if m["sdp"] and not m["retrans"]:
            for md in m["sdp"]["media"]:
                sdps.append({"owner": m["owner"], "frame": m["frame"], "t": rel(m["ts"]), "msg": m["first_line"][:40],
                             "sig_src": m["src"], **md})
    summary["sdp"] = sdps
    for s in sdps:
        if s["type"] == "audio" and s["ip"] and is_private(s["ip"]) and not is_private(s["sig_src"]):
            F.append(finding("SDP_IP_PRIVADA", "alto",
                             f"SDP de {side_label(s['owner'])} anuncia IP privada {s['ip']}",
                             f"El mensaje #{s['frame']} ({s['msg']}) sale de la IP pública {s['sig_src']} pero su SDP dice "
                             f"c={s['ip']} puerto {s['port']}. Sin corrección NAT (SBC/rtpengine/latching) el otro extremo "
                             "enviará el audio a una IP inalcanzable -> audio unidireccional o sin audio.",
                             cid, suspect=f"{side_label(s['owner'])}: NAT sin resolver",
                             hint="Activar NAT traversal en el equipo que anuncia la IP privada (ext-rtp-ip, nat=force_rport/comedia, "
                                  "fix_nated_sdp en Kamailio) o desactivar el ALG SIP del router."))
            break
    offer = next((s for s in sdps if s["type"] == "audio" and s["owner"] == "A"), None)
    answer = next((s for s in sdps if s["type"] == "audio" and s["owner"] == "B"), None)
    if offer and answer:
        on = {c["name"].upper() for c in offer["codecs"]}
        an_ = {c["name"].upper() for c in answer["codecs"]}
        if not (on & an_ - {"TELEPHONE-EVENT", "CN"}) and answer["port"] != 0:
            F.append(finding("CODEC_INCOMPATIBLE", "alto", "La respuesta SDP no contiene ningún códec de la oferta",
                             f"Oferta: {sorted(on)}; respuesta: {sorted(an_)}.", cid))
        if "TELEPHONE-EVENT" in on and "TELEPHONE-EVENT" not in an_:
            F.append(finding("DTMF_NO_NEGOCIADO", "bajo", "telephone-event (RFC 2833) no aceptado en la respuesta",
                             "Los DTMF por RFC 2833 no funcionarán; se necesitará inband o SIP INFO.", cid,
                             suspect=side_label("B")))
        if answer["port"] == 0:
            F.append(finding("MEDIA_RECHAZADA", "alto", "La respuesta SDP rechaza el audio (puerto 0)", "", cid))
        if offer["srtp"] != answer["srtp"]:
            F.append(finding("SRTP_DESIGUAL", "medio", "Discrepancia SRTP/RTP entre oferta y respuesta", "", cid))
    holds = [s for s in sdps if s["dir"] in ("sendonly", "inactive", "recvonly") or s["ip"] == "0.0.0.0"]
    summary["hold_events"] = [{"owner": h["owner"], "frame": h["frame"], "dir": h["dir"]} for h in holds]

    end_t = bye["ts"] if bye else (cancel["ts"] if cancel else (final["ts"] if final and not ok else an.last_ts))
    return summary, F, sdps, (t_inv, end_t, final["ts"] if ok else None)


def analyze_other_dialog(cid, msgs, t0):
    req = next((m for m in msgs if m["type"] == "request"), msgs[0])
    method = req.get("method") or req.get("cseq_method")
    resp = [m for m in msgs if m["type"] == "response"]
    final = next((m for m in resp if m["status"] >= 200), None)
    return {"call_id": cid, "method": method, "src": ep(req["src"], req["sport"]), "dst": ep(req["dst"], req["dport"]),
            "from_user": req["from_user"], "to_user": req["to_user"], "t": round(req["ts"] - t0, 3),
            "requests": sum(1 for m in msgs if m["type"] == "request"),
            "final_status": final["status"] if final else None,
            "rtt_ms": round((final["ts"] - req["ts"]) * 1000, 1) if final else None,
            "user_agent": req["user_agent"]}


def match_media(calls_info, an, t0):
    """Asocia streams RTP a llamadas usando SDP (IP:puerto) y ventana temporal."""
    stream_owner = {}
    for ci in calls_info:
        sdps = [s for s in ci["sdps"] if s["type"] in ("audio", "video") and s["port"]]
        t_start, t_end, _ = ci["window"]
        by_ipport = {}
        by_port = {}
        for s in sdps:
            by_ipport[(s["ip"], s["port"])] = s
            by_port.setdefault(s["port"], s)
        for key, st in an.rtp.items():
            if key in stream_owner:
                continue
            if st.arr[-1] < t_start - 1 or st.arr[0] > (t_end or an.last_ts) + 5:
                continue
            m = None
            if (st.dst, st.dport) in by_ipport:
                m = ("to", by_ipport[(st.dst, st.dport)], "exacto")
            elif (st.src, st.sport) in by_ipport:
                m = ("from", by_ipport[(st.src, st.sport)], "exacto")
            elif st.dport in by_port:
                m = ("to", by_port[st.dport], "solo puerto (NAT/SBC)")
            elif st.sport in by_port:
                m = ("from", by_port[st.sport], "solo puerto (NAT/SBC)")
            if m:
                rel_, s, how = m
                sender = ("B" if s["owner"] == "A" else "A") if rel_ == "to" else s["owner"]
                stream_owner[key] = (ci["summary"]["call_id"], sender, how)
    return stream_owner


def stream_findings(x, who, t0, cid=None, holds=(), t_end=None, t_ans=None):
    """Hallazgos de calidad de un flujo RTP. who = etiqueta del emisor (lado o IP)."""
    F = []
    st = x["stats"]
    if st["packets"] < 20:
        return F
    evs = [{"frame": x["first_frame"], "t": round(x["start"] - t0, 3), "msg": f"RTP {x['flow']}", "note": ""}]
    if st["loss_pct"] >= 1:
        sev = "alto" if st["loss_pct"] >= 3 else "medio"
        F.append(finding("PERDIDA_RTP", sev, f"Pérdida RTP {st['loss_pct']}% en el audio enviado por {who}",
                         f"{st['lost']} de {st['expected']} paquetes perdidos (saltos de secuencia) en {st['loss_events']} "
                         f"eventos, ráfaga máx {st['max_burst_lost']}. Flujo {x['flow']}. MOS estimado {st['mos_est']}. "
                         f"La pérdida ocurrió ENTRE {who} y el punto de captura.", cid, evs,
                         suspect=f"red entre {who} ({x['src']}) y el punto de captura"))
    if st["jitter_ms"] >= 30 or st["jitter_max_ms"] >= 60:
        F.append(finding("JITTER_ALTO", "alto" if st["jitter_max_ms"] >= 100 else "medio",
                         f"Jitter alto en el audio de {who}: medio {st['jitter_ms']} ms, máx {st['jitter_max_ms']} ms",
                         f"Flujo {x['flow']}. Variación de retardo generada entre {who} y el punto de captura "
                         "(los saltos de timestamp se excluyen del cálculo).", cid, evs,
                         suspect=f"red/host entre {who} y el punto de captura"))
    gaps = [g for g in st.get("big_gaps", []) if g["gap_ms"] >= 300]
    if gaps and not holds:
        pauses = [g for g in gaps if g["kind"].startswith("pausa")]
        losses = [g for g in gaps if not g["kind"].startswith("pausa")]
        cn = 13 in x["pts"]
        if losses:
            g = losses[0]
            F.append(finding("CORTE_RTP_CON_PERDIDA", "alto",
                             f"Corte de audio de {g['gap_ms']} ms con {g['lost_in_gap']} paquetes perdidos en el flujo de {who}",
                             f"t={round(g['t'] - t0, 3)}s. La secuencia RTP salta: los paquetes se enviaron y se perdieron entre "
                             f"{who} y el punto de captura ({len(losses)} cortes así).", cid, evs,
                             suspect=f"red entre {who} y el punto de captura"))
        if pauses:
            g = pauses[0]
            F.append(finding("PAUSA_EMISOR_RTP", "bajo" if cn else "medio",
                             f"{who} deja de enviar RTP {g['gap_ms']} ms (secuencia continua: no es pérdida de red)",
                             f"t={round(g['t'] - t0, 3)}s; {len(pauses)} pausas >=300 ms. Con la secuencia continua el emisor "
                             "simplemente no transmitió (silencio/VAD, cambio de locución, procesamiento de DTMF, CPU). "
                             + ("Hay paquetes CN: supresión de silencios, probablemente normal." if cn else ""),
                             cid, evs, suspect=f"{who} (equipo emisor)"))
    if st.get("ts_jumps_count"):
        j = st["ts_jumps"][0]
        F.append(finding("SALTO_TIMESTAMP_RTP", "medio",
                         f"Salto de timestamp RTP sin cambio de SSRC en el flujo de {who} ({st['ts_jumps_count']} veces)",
                         f"Primero en t={round(j['t'] - t0, 3)}s (Δts={j['delta_rtp_ts']}). Suele deberse a un cambio de fuente "
                         "de medios en el emisor (locución, bridge, transferencia). Algunos jitter buffers recortan audio en ese "
                         "momento. En FreeSWITCH: rtp_rewrite_timestamps=true.", cid, evs, suspect=f"{who} (equipo emisor)"))
    dev = x.get("dtmf_events", [])
    offs = sorted(abs(d["ts_offset_ms"]) for d in dev if d.get("ts_offset_ms") is not None)
    if offs and offs[len(offs) // 2] > 60:
        med = offs[len(offs) // 2]
        F.append(finding("DTMF_TIMESTAMP_DESFASADO", "alto",
                         f"Los DTMF RFC 2833 de {who} llevan el timestamp RTP desfasado ~{med} ms respecto a la voz",
                         f"{len(offs)} eventos; mediana del desfase {med} ms (debería ser ~0: RFC 4733 usa el mismo reloj que el "
                         "audio). Los receptores con jitter buffer pueden descartar el evento, retrasarlo o detectarlo mal, y "
                         "tras el evento la voz puede saltar de base de tiempo (ver SALTO_TIMESTAMP_RTP).", cid, evs,
                         suspect=f"{who} (generador de DTMF/RTP)",
                         hint="Pedir al emisor que corrija la generación RFC 2833, o en el receptor pasar a DTMF inband/SIP INFO "
                              "como prueba; en FreeSWITCH probar rtp_rewrite_timestamps y revisar 'dtmf_type'."))
    digits = "".join(d["digit"] for d in dev)
    rep = None
    for L in range(len(digits) // 2, 3, -1):
        for i in range(0, len(digits) - 2 * L + 1):
            if digits[i:i + L] in digits[i + L:]:
                rep = digits[i:i + L]
                break
        if rep:
            break
    if rep:
        F.append(finding("DTMF_SECUENCIA_REPETIDA", "medio",
                         f"{who} marca dos veces la secuencia '{rep}'",
                         f"Dígitos en orden: {digits}. Repetir una secuencia larga suele indicar que el IVR no aceptó la primera "
                         "entrada (dígitos no reconocidos, perdidos o con timeout).", cid, evs))
    over = [d for d in dev if d["voice_pkts_during"] >= 2]
    if over:
        F.append(finding("DTMF_CON_VOZ", "medio",
                         f"{who} envía DTMF RFC 2833 y voz a la vez ({len(over)} dígitos)",
                         "Durante el evento DTMF siguen saliendo paquetes de audio: si el receptor también detecta DTMF en "
                         "banda puede contar el dígito dos veces, o el tono se oye en la locución.", cid, evs,
                         suspect=f"{who} (debe silenciar la voz mientras envía el evento)"))
    au = st.get("audio")
    if au and st["packets"] >= 100:
        if au["silent_pct"] >= 95:
            F.append(finding("AUDIO_SILENCIO_DIGITAL", "alto",
                             f"El audio enviado por {who} es silencio casi total ({au['silent_pct']}% de paquetes < -60 dBov)",
                             f"Flujo {x['flow']}: llegan paquetes RTP pero sin voz. Para el usuario equivale a 'no se oye nada' "
                             "aunque la red esté perfecta: micrófono/fuente muda, mute, codificador o transcodificación que "
                             "entrega silencio.", cid, evs, suspect=f"{who} (fuente de audio)"))
        elif [r for r in au["mute_runs"] if not t_ans or r["t"] >= t_ans]:
            runs = [r for r in au["mute_runs"] if not t_ans or r["t"] >= t_ans]
            m = max(runs, key=lambda r: r["dur_s"])
            F.append(finding("AUDIO_TRAMOS_MUDOS", "medio",
                             f"Tramos mudos en el audio de {who} (el más largo {m['dur_s']} s)",
                             f"El más largo en t={round(m['t'] - t0, 3)}s; {len(runs)} tramos >= 3 s con nivel < -60 dBov "
                             "mientras los paquetes siguen llegando. Puede ser silencio natural (espera, nadie habla) o audio "
                             "perdido en la fuente.", cid, evs, suspect=f"{who} (fuente de audio)"))
        if au["active_level_dbov"] is not None and au["active_level_dbov"] < -35:
            F.append(finding("AUDIO_NIVEL_BAJO", "medio", f"Nivel de voz muy bajo en el audio de {who}: {au['active_level_dbov']} dBov",
                             "Habitual -20..-26 dBov. Se percibe como 'se oye muy bajo/lejano'.", cid, evs,
                             suspect=f"{who} (ganancia/codificación)"))
        if au["clipping_pct"] >= 1:
            F.append(finding("AUDIO_SATURADO", "medio", f"Saturación (clipping) en el audio de {who}: {au['clipping_pct']}% de paquetes",
                             "Muestras al máximo de la escala: distorsión, voz 'rota'. Ganancia excesiva en el emisor.", cid, evs,
                             suspect=f"{who} (ganancia)"))
    flow_end = x.get("flow_end", x["end"])
    if t_end and t_ans and flow_end < t_end - 3 and (t_end - t_ans) > 6 and not holds:
        F.append(finding("RTP_SE_DETIENE", "alto", f"El RTP de {who} se detiene {t_end - flow_end:.1f}s antes del fin",
                         f"El último paquete de {x['flow']} es en t={round(flow_end - t0, 3)}s y el fin de llamada en "
                         f"t={round(t_end - t0, 3)}s. El usuario probablemente dejó de oír y colgó.", cid, evs,
                         suspect=f"{who} o la red"))
    if x.get("match") not in (None, "exacto"):
        F.append(finding("RTP_DIRECCION_DISTINTA_SDP", "info",
                         f"RTP de {who} con IP/puerto distinto al SDP ({x['flow']})",
                         "Asociado solo por puerto: indica NAT o un SBC/media relay en el camino. Normal si hay latching.",
                         cid, evs))
    if x.get("unexpected_pt"):
        F.append(finding("PT_NO_NEGOCIADO", "medio", f"RTP con payload type no negociado {x['unexpected_pt']}",
                         f"El flujo de {who} usa PT que no aparece en ningún SDP de la llamada.", cid, evs, suspect=who))
    return F


def media_findings(ci, streams, an, t0, rtcp):
    F = []
    s = ci["summary"]
    cid = s["call_id"]
    t_inv, t_end, t_ans = ci["window"]
    audio = [x for x in streams if x["media"] != "video"]
    dirs = {x["sender"] for x in audio if x["stats"]["packets"] >= 10}
    talk = (t_end - t_ans) if t_ans and t_end else 0
    holds = s.get("hold_events", [])
    if t_ans and talk >= 3:
        if not audio:
            F.append(finding("SIN_RTP", "critico", "Llamada contestada sin RTP en la captura",
                             f"Conversación de {talk:.1f}s sin ningún flujo RTP asociado. Puede ser ausencia real de audio o que el "
                             "punto de captura no ve el plano de medios (RTP por otro interfaz/SBC).", cid,
                             hint="Confirmar que la captura incluye el tráfico de medios (filtro 'udp' completo, interfaz correcta)."))
        elif len(dirs) == 1:
            only = dirs.pop()
            miss = "B" if only == "A" else "A"
            sdp_miss = next((x for x in ci["sdps"] if x["owner"] == miss and x["type"] == "audio"), None)
            sdp_only = next((x for x in ci["sdps"] if x["owner"] == only and x["type"] == "audio"), None)
            det = (f"Solo se ve RTP enviado por {side_label(only)}. No llega/no se ve RTP de {side_label(miss)} "
                   f"durante {talk:.1f}s de conversación. ")
            if sdp_only and sdp_only["ip"] and is_private(sdp_only["ip"]):
                det += (f"{side_label(only)} anuncia IP privada {sdp_only['ip']} en su SDP: {side_label(miss)} probablemente "
                        "le envía el audio a esa IP inalcanzable (o no lo envía a la IP pública). ")
            if holds:
                det += "Hay re-INVITEs de hold/sendonly que podrían explicarlo parcialmente. "
            F.append(finding("AUDIO_UNIDIRECCIONAL", "critico", "Audio unidireccional", det, cid,
                             suspect=f"{side_label(miss)} no envía o su RTP no llega al punto de captura"
                                     + (f"; NAT de {side_label(only)}" if sdp_only and sdp_only['ip'] and is_private(sdp_only['ip']) else ""),
                             hint="Contrastar con captura en el otro extremo. Si B envía pero no llega aquí: firewall/NAT en el camino. "
                                  "Si B no envía: B no recibió SDP válido o espera RTP primero (comedia/symmetric RTP)."))
    byflow = defaultdict(list)
    for x in audio:
        byflow[(x["sender"], x["flow"])].append(x)
    for (snd, flow), xs in byflow.items():
        fe = max(y["end"] for y in xs)
        for y in xs:
            y["flow_end"] = fe
        if len(xs) > 1:
            xs_sorted = sorted(xs, key=lambda y: y["start"])
            F.append(finding("CAMBIO_SSRC", "info", f"{side_label(snd)} cambia de SSRC {len(xs) - 1} vez/veces en {flow}",
                             "Cambio de fuente de medios en el emisor (p. ej. early media del 183 → audio tras el 200, "
                             "transferencia, cambio de locución). Normal si no coincide con la queja; si el receptor no "
                             "re-sincroniza puede haber un breve corte.", cid,
                             [{"frame": y["first_frame"], "t": round(y["start"] - t0, 3), "msg": f"SSRC {y['ssrc']}", "note": ""}
                              for y in xs_sorted[1:4]]))
    for x in audio:
        F += stream_findings(x, side_label(x["sender"]), t0, cid, holds, t_end, t_ans)
    # El RTP de un lado muere justo cuando empieza el del otro: firma de latching/NAT simétrico
    for (snd, flow), xs in byflow.items():
        fe = max(y["end"] for y in xs)
        others = [y for (s2, _), ys in byflow.items() if s2 != snd for y in ys]
        if not others or not t_end:
            continue
        ostart = min(y["start"] for y in others)
        if -0.05 <= fe - ostart <= 0.15 and t_end - fe > 5:
            F.append(finding("RTP_CORTADO_AL_RECIBIR", "critico",
                             f"El RTP de {side_label(snd)} se corta {round((fe - ostart) * 1000)} ms después de que llegue el primer "
                             f"RTP del otro lado",
                             f"Último paquete de {flow} en t={round(fe - t0, 3)}s; el otro sentido empieza en t={round(ostart - t0, 3)}s "
                             f"y la llamada sigue {t_end - fe:.1f}s más. Que el emisor deje de enviar justo al recibir medios es la "
                             "firma de symmetric RTP / latching: el equipo remoto (o un SBC/firewall intermedio) pasa a enviar a la "
                             "IP:puerto ORIGEN desde la que recibió nuestro RTP; si un NAT reescribe ese origen de forma distinta al SDP "
                             "(otra IP pública, puerto aleatorio) el audio se va a una dirección que no vuelve.", cid,
                             [{"frame": xs[0]["first_frame"], "t": round(fe - t0, 3), "msg": f"último RTP {flow}", "note": ""}],
                             suspect="NAT/firewall de nuestro lado (origen público del RTP saliente ≠ SDP) o latching del equipo remoto",
                             hint="Comprobar con qué IP:puerto públicos sale nuestro RTP (captura en el borde o traza del remoto) y "
                                  "compararlo con el c=/m= del SDP; en AWS, confirmar que el tráfico sale por la EIP del SDP y no por un "
                                  "NAT Gateway; en el remoto desactivar latching o fijar la dirección del SDP."))
    # RTCP: pérdida reportada por el extremo remoto
    ssrcs = {x["ssrc"]: x for x in audio}
    for r in rtcp:
        x = ssrcs.get(r["about_ssrc"])
        if x and r["fraction_lost_pct"] >= 3:
            F.append(finding("RTCP_PERDIDA_REMOTA", "medio",
                             f"RTCP informa {r['fraction_lost_pct']}% de pérdida sobre el audio de {side_label(x['sender'])}",
                             f"Informe {r['type']} #{r['frame']} de {r['src']}: pérdida medida en el receptor, después del punto de "
                             "captura si aquí no se ve pérdida.", cid))
            break
    return F


# --------------------------------------------------------------------------------------
# Informe
# --------------------------------------------------------------------------------------
def analyze(path, sip_ports, local_ips, acdr_ports=(925,), vxlan_ports=(4789, 8472)):
    an = Analyzer(sip_ports, acdr_ports, vxlan_ports)
    an.run(path)
    t0 = an.first_ts or 0
    calls = build_calls(an)
    calls_info, others, findings = [], [], []
    for cid, msgs in calls.items():
        if any(m["type"] == "request" and m.get("method") == "INVITE" for m in msgs):
            summ, F, sdps, window = analyze_invite_call(cid, msgs, t0, an)
            calls_info.append({"summary": summ, "findings": F, "sdps": sdps, "window": window, "msgs": msgs})
        else:
            others.append(analyze_other_dialog(cid, msgs, t0))

    owner = match_media(calls_info, an, t0)
    streams_all = []
    by_call = defaultdict(list)
    for key, st in an.rtp.items():
        if len(st.seq) < 5:
            continue
        cid, sender, how = owner.get(key, (None, None, None))
        ci = next((c for c in calls_info if c["summary"]["call_id"] == cid), None)
        pt = st.pts.most_common(1)[0][0]
        codec, clock, media, negotiated = None, 8000, "audio", set()
        if ci:
            for s in ci["sdps"]:
                for c in s["codecs"]:
                    negotiated.add(c["pt"])
                    if c["pt"] == pt and codec is None:
                        codec, clock, media = c["name"], c["rate"], s["type"]
        if codec is None and pt in STATIC_PT:
            codec, clock = STATIC_PT[pt]
        if cid is None:
            # descartar falsos positivos: exigir secuencia mayoritariamente consecutiva
            ok_seq = sum(1 for i in range(1, len(st.seq)) if (st.seq[i] - st.seq[i - 1]) & 0xFFFF == 1)
            if ok_seq < 0.8 * (len(st.seq) - 1):
                continue
        stats = stream_stats(st, clock, codec)
        te_pts = set()
        if ci:
            for s in ci["sdps"]:
                te_pts |= {c["pt"] for c in s["codecs"] if c["name"].lower() == "telephone-event"}
        if not te_pts:
            # Sin SDP: un PT dinámico cuyos paquetes son casi todos de 4 bytes es telephone-event (RFC 4733).
            evc = Counter(e[1] for e in st.events)
            te_pts = {p for p, c in evc.items() if c >= 0.8 * st.pts[p]}
        groups = OrderedDict()
        for ts_, ept, rts, p4 in st.events:
            if ept in te_pts:
                g = groups.setdefault(rts, {"digit": "0123456789*#ABCD"[p4[0]] if p4[0] < 16 else "?",
                                            "t0": ts_, "t1": ts_, "end": False, "dur": 0})
                g["t1"] = ts_
                g["end"] |= bool(p4[1] & 0x80)
                g["dur"] = max(g["dur"], struct.unpack("!H", p4[2:4])[0])
        main_pt = st.pts.most_common(1)[0][0]
        dtmf_events = []
        for ev_rts, g in groups.items():
            lo, hi = bisect.bisect_left(st.arr, g["t0"]), bisect.bisect_right(st.arr, g["t1"])
            voice = sum(1 for i in range(lo, hi) if st.ptarr[i] == main_pt and main_pt not in te_pts)
            # desfase del timestamp del evento respecto al reloj de la voz (RFC 4733: mismo reloj que el audio)
            off_ms = None
            j = lo - 1
            while j >= 0 and st.ptarr[j] != main_pt:
                j -= 1
            if j >= 0 and main_pt not in te_pts and clock:
                exp = st.rts[j] + (g["t0"] - st.arr[j]) * clock
                d = (ev_rts - int(exp)) & 0xFFFFFFFF
                if d > 0x7FFFFFFF:
                    d -= 0x100000000
                off_ms = round(d / clock * 1000)
            dtmf_events.append({"digit": g["digit"], "t": round(g["t0"] - t0, 3), "utc": fmt_utc(g["t0"]),
                                "dur_ms": round(g["dur"] / (clock or 8000) * 1000), "end_seen": g["end"],
                                "voice_pkts_during": voice, "ts_offset_ms": off_ms})
        digits = "".join(d["digit"] for d in dtmf_events)
        unexpected = sorted(p for p in st.pts if negotiated and p not in negotiated and p != 13)
        rec = {"call_id": cid, "sender": sender, "match": how, "media": media,
               "flow": f"{ep(st.src, st.sport)} -> {ep(st.dst, st.dport)}", "src": st.src, "dst": st.dst,
               "ssrc": f"0x{st.ssrc:08X}", "codec": codec, "clock": clock, "pts": dict(st.pts),
               "unexpected_pt": unexpected, "start": st.arr[0], "end": st.arr[-1],
               "first_frame": st.first_frame, "last_frame": st.last_frame, "dtmf_rfc2833": digits,
               "dtmf_events": dtmf_events, "stats": stats}
        streams_all.append(rec)
        if cid:
            by_call[cid].append(rec)
        an.ip_pk[st.src] += len(st.seq)
        an.ip_pk[st.dst] += len(st.seq)

    for ci in calls_info:
        cid = ci["summary"]["call_id"]
        ci["findings"] += media_findings(ci, by_call.get(cid, []), an, t0, an.rtcp)
        findings += ci["findings"]

    # Flujos RTP sin llamada (no hay SIP o no se capturó): calidad, emparejamiento y sentido ausente
    unmatched = [x for x in streams_all if not x["call_id"]]
    for x in unmatched:
        findings += stream_findings(x, f"{x['src']}", t0)
    eps = {(x["src"], int(x["flow"].split(" -> ")[0].rsplit(":", 1)[1])): x for x in unmatched}
    for x in unmatched:
        dst_ep = x["flow"].split(" -> ")[1]
        dip, dport = dst_ep.rsplit(":", 1)
        dip = dip.strip("[]")
        if (dip, int(dport)) not in eps and x["stats"]["packets"] >= 50:
            findings.append(finding("SENTIDO_RTP_NO_CAPTURADO", "medio",
                                    f"Solo se ve un sentido del flujo {x['flow']}",
                                    f"No hay RTP de vuelta desde {dst_ep} hacia {x['src']} en la captura. Puede ser audio "
                                    "unidireccional real o un filtro de captura que solo recoge un sentido (p. ej. 'dst host'), "
                                    "o que el retorno sale por otro puerto/interfaz.", None,
                                    [{"frame": x["first_frame"], "t": round(x["start"] - t0, 3), "msg": "RTP", "note": x["flow"]}],
                                    suspect=f"{dip} o el filtro de captura"))

    # Hallazgos globales
    icmp_g = OrderedDict()
    for r in an.icmp:
        k = (r["from"], r["desc"], r.get("orig_src"), r.get("orig_dst"), r.get("orig_dport"))
        icmp_g.setdefault(k, []).append(r)
    for (frm, desc, osrc, odst, odp), rs in list(icmp_g.items())[:10]:
        r = rs[0]
        findings.append(finding("ICMP_UNREACHABLE", "alto",
                                f"ICMP {desc} de {frm} ({len(rs)} veces) para tráfico hacia {odst}:{odp}",
                                f"Respuesta a paquetes {osrc}:{r.get('orig_sport')} -> {odst}:{odp} (primera trama ICMP "
                                f"#{r['frame']}). {frm} {'es el propio destino' if frm == odst else 'es un equipo intermedio'}: "
                                "el puerto está cerrado o un firewall lo rechaza; suele explicar INVITEs/OPTIONS/RTP que no llegan.",
                                None, [{"frame": x["frame"], "t": round(x["ts"] - t0, 3), "msg": "ICMP", "note": desc} for x in rs[:3]],
                                suspect=odst))
    if an.tls:
        findings.append(finding("SIP_TLS_CIFRADO", "info", "Hay SIP sobre TLS cifrado que no se puede analizar",
                                f"{sum(an.tls.values())} segmentos TLS en {len(an.tls)} flujos. Para verlo, capturar en claro "
                                "(siptrace/HEP en el proxy) o exportar claves.", None))
    if an.stats["rtp_truncated"]:
        findings.append(finding("RTP_TRUNCADO", "info", "RTP capturado sin payload completo (snaplen / longitud de mirror corta)",
                                f"{an.stats['rtp_truncated']} paquetes RTP truncados: pérdida, jitter y pausas son fiables (van en "
                                "las cabeceras), pero no se puede analizar el contenido del audio (silencio, nivel, saturación).",
                                None, hint="Capturar con -s 0 o subir la longitud de paquete de la sesión de mirror."))
    if an.stats["sip_truncated_snaplen"]:
        findings.append(finding("SNAPLEN_CORTO", "medio", "Paquetes SIP truncados por snaplen",
                                f"{an.stats['sip_truncated_snaplen']} paquetes SIP capturados incompletos. Capturar con -s 0.", None))
    if an.stats["sip"] == 0 and streams_all:
        findings.append(finding("SOLO_RTP", "info", "La captura solo contiene medios (RTP), sin señalización SIP",
                                "Se puede medir calidad (pérdida, jitter, pausas, DTMF), pero no cómo empezó/terminó la llamada, "
                                "quién colgó ni la negociación SDP. Si el SIP va por un puerto no estándar, repetir con --sip-port.",
                                None, hint="Capturar SIP y RTP juntos: tcpdump -i any -s 0 -w llamada.pcap 'udp or tcp port 5060'"))
    elif an.stats["sip"] == 0:
        findings.append(finding("SIN_SIP", "alto", "No se encontró señalización SIP ni RTP",
                                "Puede estar en puertos no estándar (usar --sip-port), cifrada (TLS), encapsulada en un formato no "
                                "soportado o la captura no contiene VoIP.", None))
    if an.stats["tcp_rst_sip"]:
        findings.append(finding("TCP_RST_SIP", "medio", "Resets TCP en conexiones SIP",
                                f"{an.stats['tcp_rst_sip']} segmentos RST en puertos SIP: conexiones rechazadas o cortadas.", None))
    opt = defaultdict(lambda: {"sent": 0, "answered": 0, "codes": Counter(), "rtt": []})
    for o in others:
        if o["method"] == "OPTIONS":
            k = f"{o['src']} -> {o['dst']}"
            opt[k]["sent"] += 1
            if o["final_status"]:
                opt[k]["answered"] += 1
                opt[k]["codes"][o["final_status"]] += 1
                opt[k]["rtt"].append(o["rtt_ms"])
    opt_sum = {k: {"sent": v["sent"], "answered": v["answered"], "codes": dict(v["codes"]),
                   "rtt_ms_avg": round(sum(v["rtt"]) / len(v["rtt"]), 1) if v["rtt"] else None} for k, v in opt.items()}
    for k, v in opt_sum.items():
        if v["sent"] >= 2 and v["answered"] < v["sent"]:
            findings.append(finding("OPTIONS_SIN_RESPUESTA", "alto" if v["answered"] == 0 else "medio",
                                    f"OPTIONS sin respuesta {k}: {v['sent'] - v['answered']}/{v['sent']}",
                                    "El keepalive SIP no obtiene respuesta: el trunk puede marcarse caído.", None, suspect=k.split(" -> ")[1]))
    reg = [o for o in others if o["method"] == "REGISTER"]
    reg_fail = [o for o in reg if o["final_status"] and o["final_status"] >= 300 and o["final_status"] not in (401, 407)]
    if reg_fail:
        findings.append(finding("REGISTER_FALLIDO", "alto", f"REGISTER rechazado ({Counter(o['final_status'] for o in reg_fail)})",
                                "El registro no se completa: las llamadas entrantes no llegarán.", None))

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["call_id"] or ""))
    # Hosts
    hosts = {}
    for ip, c in an.ip_pk.most_common(40):
        uas = sorted({m["user_agent"] for m in an.sip_msgs if m["src"] == ip and m["user_agent"]})[:3]
        hosts[ip] = {"packets_sip_rtp": c, "private": is_private(ip), "user_agents": uas,
                     "local": ip in local_ips}
    # Punto de captura: el host cuyos paquetes salen con TTL inicial intacto (64/128/255) está en el capturador
    # o en su mismo segmento. Si hay encapsulación (mirror/ACDR), el punto de captura real es el equipo que la emite.
    ttl_info = {}
    for (ip, inner), c in an.ttl.items():
        top, cnt = c.most_common(1)[0]
        ttl_info.setdefault(ip, {"ttl": top, "packets": cnt, "encapsulated": inner})
    local_ttl = sorted((ip for ip, v in ttl_info.items() if v["ttl"] in (64, 128, 255) and v["encapsulated"] == bool(an.encap)),
                       key=lambda ip: -ttl_info[ip]["packets"])
    total_pk = sum(x["stats"]["packets"] for x in streams_all) or 1
    hub = [ip for ip, c in an.ip_pk.most_common(3) if c >= 0.8 * (total_pk + an.stats["sip"])]
    if not an.encap_src and len(hub) == 1 and hub[0] not in local_ttl:
        local_ttl = hub + [ip for ip in local_ttl if ip != hub[0]]
    elif not an.encap_src and len(hub) > 1:
        local_ttl = [ip for ip in local_ttl if ip in hub] or local_ttl
    if an.encap_src:
        capture_host = ", ".join(sorted(an.encap_src))
        capture_basis = ("equipo que emite la traza encapsulada (mirror/ACDR): ve los paquetes tal como entran y salen de él"
                         + ("; en ACDR la IP 'local' de los flujos es la del SBC que envía la traza, no necesariamente su IP de medios"
                            if an.acdr_types else ""))
    elif local_ttl:
        capture_host = local_ttl[0]
        if capture_host in ttl_info and ttl_info[capture_host]["ttl"] in (64, 128, 255):
            capture_basis = f"TTL {ttl_info[capture_host]['ttl']} sin decrementar (origen local)"
        else:
            capture_basis = "participa en todos los flujos y no se le ve emitir (filtro de captura solo entrante)"
    else:
        capture_host = an.ip_pk.most_common(1)[0][0] if an.ip_pk else None
        capture_basis = "IP más presente (sin TTL inicial concluyente: captura en un punto intermedio o mirror)"
    for ip in hosts:
        if ip in ttl_info:
            hosts[ip]["ttl"] = ttl_info[ip]["ttl"]
    cap_ips = {c.split(" ")[0] for c in (capture_host or "").split(", ")}
    for x in streams_all:
        st = x["stats"]
        if x["src"] in cap_ips and st["packets"] >= 100 and st.get("jitter_ms", 0) >= 5:
            findings.append(finding("JITTER_EN_ORIGEN", "medio",
                                    f"El RTP sale ya con jitter desde {x['src']} (jitter {st['jitter_ms']} ms medido en el propio emisor)",
                                    f"Flujo {x['flow']}: se captura en el equipo que lo envía, así que no hay red de por medio; el "
                                    f"emisor no espacia los paquetes de forma regular (mediana {st['median_delta_ms']} ms, máx "
                                    f"{st['max_delta_ms']} ms; intervalos ms→paquetes {st.get('delta_hist_ms')}). Intervalos que alternan ~15/30 ms delatan el temporizador de "
                                    "Windows (15,6 ms); también CPU saturada o VM con planificación irregular. Grave para fax "
                                    "G.711 y DTMF inband.", x["call_id"],
                                    [{"frame": x["first_frame"], "t": round(x["start"] - t0, 3), "msg": "RTP", "note": x["flow"]}],
                                    suspect=f"{x['src']} (temporización del emisor)",
                                    hint="Windows: timeBeginPeriod(1)/resolución de temporizador alta en la app; fax: usar T.38."))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["call_id"] or ""))
    status_c = Counter(ci["summary"]["final_status"] for ci in calls_info)
    result = {
        "file": path, "format": an.info["format"], "frames": an.stats["frames"],
        "start_utc": fmt_utc(an.first_ts), "end_utc": fmt_utc(an.last_ts),
        "duration_s": round((an.last_ts or 0) - t0, 3), "linktypes": dict(an.linktypes),
        "snaplen": an.info["snaplen"], "warnings": an.info["warnings"], "stats": dict(an.stats),
        "probable_capture_host": capture_host, "capture_basis": capture_basis,
        "encapsulation": sorted(an.encap), "acdr_trace_points": {f"tp{k[0]}/mt{k[1]}": v for k, v in an.acdr_types.items()},
        "hosts": hosts, "local_ips": sorted(local_ips),
        "totals": {"invite_calls": len(calls_info), "answered": sum(1 for c in calls_info if c["summary"]["answered"]),
                   "final_status_counts": {str(k): v for k, v in status_c.items()},
                   "other_dialogs": dict(Counter(o["method"] for o in others)), "rtp_streams": len(streams_all),
                   "rtcp_reports": len(an.rtcp)},
        "findings": findings, "calls": [], "other_dialogs": others[:500], "options_summary": opt_sum,
        "rtp_streams": [], "rtcp": an.rtcp[:500], "icmp": an.icmp[:200],
    }
    for ci in calls_info:
        cid = ci["summary"]["call_id"]
        result["calls"].append({**ci["summary"], "findings": ci["findings"],
                                "media": [_strip_stream(x, t0) for x in by_call.get(cid, [])],
                                "ladder": [_ladder_row(m, t0) for m in ci["msgs"]]})
    result["rtp_streams"] = [_strip_stream(x, t0) for x in streams_all]
    return result


def _strip_stream(x, t0):
    y = dict(x)
    y["start"] = round(x["start"] - t0, 3)
    y["end"] = round(x["end"] - t0, 3)
    y["stats"] = dict(x["stats"])
    y["stats"]["big_gaps"] = [{**g, "t": round(g["t"] - t0, 3)} for g in x["stats"].get("big_gaps", [])]
    y["stats"]["ts_jumps"] = [{**j, "t": round(j["t"] - t0, 3)} for j in x["stats"].get("ts_jumps", [])]
    if "audio" in x["stats"]:
        y["stats"]["audio"] = {**x["stats"]["audio"],
                               "mute_runs": [{**m, "t": round(m["t"] - t0, 3)} for m in x["stats"]["audio"]["mute_runs"]]}
    return y


def _ladder_row(m, t0):
    sdp = ""
    if m["sdp"]:
        a = next((md for md in m["sdp"]["media"] if md["type"] == "audio"), None)
        if a:
            sdp = f"SDP {a['ip']}:{a['port']} {','.join(c['name'] for c in a['codecs'][:4])} {a['dir']}"
    extra = []
    if m["reason"]:
        extra.append("Reason: " + m["reason"][0][:70])
    if m["type"] == "request" and m.get("method") == "INVITE" and not m["to_tag"]:
        extra.append(f"R-URI {m['ruri'][:60]}")
    return {"t": round(m["ts"] - t0, 3), "frame": m["frame"], "src": ep(m["src"], m["sport"]),
            "dst": ep(m["dst"], m["dport"]), "transport": m["transport"], "msg": m["first_line"][:60],
            "cseq": f"{m['cseq']} {m['cseq_method']}", "owner": m.get("owner"), "retrans": m.get("retrans", False),
            "sdp": sdp, "extra": " | ".join(extra), "utc": fmt_utc(m["ts"])}


def _stream_extra(m):
    st = m["stats"]
    out = ""
    if st.get("pauses"):
        out += f" pausas={st['pauses']}"
    if st.get("ts_jumps_count"):
        out += f" saltos_ts={st['ts_jumps_count']}"
    gl = [g for g in st.get("big_gaps", []) if g["gap_ms"] >= 300][:3]
    if gl:
        out += " huecos=[" + "; ".join(f"t={g['t']}s {g['gap_ms']}ms {g['kind']}" for g in gl) + "]"
    au = st.get("audio")
    if au:
        out += (f" audio[silencio={au['silent_pct']}% nivel={au['active_level_dbov']}dBov pico={au['peak_level_dbov']}"
                f" clip={au['clipping_pct']}%" + (f" mudos={[(r['t'], r['dur_s']) for r in au['mute_runs'][:4]]}" if au['mute_runs'] else "")
                + "]")
    if m.get("dtmf_events"):
        out += " DTMF=[" + ", ".join(f"{d['digit']}@{d['t']}s/{d['dur_ms']}ms{' +voz' if d['voice_pkts_during'] >= 2 else ''}"
                                    f"{' Δts=' + str(d['ts_offset_ms']) + 'ms' if d.get('ts_offset_ms') not in (None, 0) and abs(d['ts_offset_ms']) > 60 else ''}"
                                    for d in m["dtmf_events"][:20]) + "]"
    return out


def print_report(r, ladder_all, only_call, max_calls):
    P = print
    P("=" * 100)
    P("RESUMEN DE LA CAPTURA")
    P("=" * 100)
    P(f"Archivo: {r['file']}  formato: {r['format']}  tramas: {r['frames']}  snaplen: {r['snaplen']}")
    P(f"Inicio: {r['start_utc']}   Fin: {r['end_utc']}   Duración: {r['duration_s']} s")
    t = r["totals"]
    P(f"Llamadas INVITE: {t['invite_calls']} (contestadas {t['answered']})  respuestas finales: {t['final_status_counts']}")
    P(f"Otros diálogos: {t['other_dialogs']}  Streams RTP: {t['rtp_streams']}  Informes RTCP: {t['rtcp_reports']}")
    s = r["stats"]
    P(f"SIP: {s.get('sip', 0)} msgs | UDP {s.get('udp', 0)} | TCP {s.get('tcp', 0)} | fragmentos IP {s.get('ip_fragments', 0)} "
      f"(reensamblados {s.get('ip_reassembled', 0)}) | HEP {s.get('hep3', 0)} | keepalives {s.get('sip_keepalive', 0)}")
    for w in r["warnings"]:
        P(f"AVISO: {w}")
    for e in r["encapsulation"]:
        P(f"Encapsulación desempaquetada: {e}")
    if r["acdr_trace_points"]:
        P(f"ACDR trace-point/media-type vistos: {r['acdr_trace_points']}")
    P(f"Posible host de captura: {r['probable_capture_host']} ({r['capture_basis']})")
    P("\nHosts:")
    for ip, h in list(r["hosts"].items())[:15]:
        P(f"  {ip:<40} paquetes={h['packets_sip_rtp']:<7} {'privada' if h['private'] else 'pública':<8} TTL={h.get('ttl', '-'):<4}"
          f"{' LOCAL' if h['local'] else ''} UA={'; '.join(h['user_agents']) or '-'}")

    P("\n" + "=" * 100)
    P("HALLAZGOS (por severidad)")
    P("=" * 100)
    fl = [f for f in r["findings"] if not only_call or f["call_id"] == only_call]
    if not fl:
        P("Sin anomalías detectadas automáticamente.")
    for f in fl[:60]:
        P(f"[{SEV_LABEL[f['severity']]}] {f['code']}: {f['title']}" + (f"  (Call-ID {f['call_id']})" if f["call_id"] else ""))
        if f["detail"]:
            P(f"    {f['detail']}")
        if f["suspect"]:
            P(f"    Sospechoso: {f['suspect']}")
        if f["hint"]:
            P(f"    Pista: {f['hint']}")
        for e in f["evidence"][:4]:
            P(f"    evidencia: #{e['frame']} t={e['t']}s {e.get('msg', '')} {e.get('src', '')}{' -> ' + e['dst'] if e.get('dst') else ''} {e.get('note', '')}")
    if len(fl) > 60:
        P(f"... {len(fl) - 60} hallazgos más en el JSON")

    calls = r["calls"]
    if only_call:
        calls = [c for c in calls if c["call_id"] == only_call]
    rank = lambda c: min([SEV_ORDER[f["severity"]] for f in c["findings"]] or [9])  # noqa: E731
    calls_sorted = sorted(calls, key=rank)
    P("\n" + "=" * 100)
    P(f"LLAMADAS ({len(calls)}; detalle de las {min(max_calls, len(calls))} más problemáticas)")
    P("=" * 100)
    if len(calls) > max_calls:
        P("Tabla resumen:")
        for c in calls_sorted[:200]:
            P(f"  t={c['t_invite']:<9} {c['from_user'][:18]:<18} -> {c['to_user'][:18]:<18} final={c['final_status']} "
              f"dur={c.get('duration_s')} BYE={c.get('bye_by', c.get('cancel_by', '-'))} sev={rank(c)} id={c['call_id'][:40]}")
    for c in calls_sorted[:max_calls]:
        P("-" * 100)
        P(f"Call-ID: {c['call_id']}")
        P(f"  {c['from_user']} -> {c['to_user']}  R-URI {c['ruri']}  inicio {c['start_utc']}")
        P(f"  A (llamante): {c['A']['ip']}:{c['A']['port']} UA={c['A']['user_agent']}")
        P(f"  B (llamado) : {c['B']['ip']}:{c['B']['port']} UA={c['B']['user_agent']}")
        if len(c["hops"]) > 1:
            P(f"  Saltos INVITE vistos: {c['hops']}")
        P(f"  100 Trying: {c['t_100_ms']} ms | PDD (->{c['first_18x']}): {c['pdd_s']} s | final: {c['final_status']} "
          f"{c['final_reason_phrase'] or ''} de {c['final_from']} | contestada en {c['t_answer_s']} s | ACK al 2xx: {c['ack_for_2xx']}")
        if c.get("bye_by"):
            P(f"  BYE por {c['bye_by']} ({c['bye_src']}) tras {c.get('duration_s')} s; respuesta {c['bye_response']}; "
              f"Reason {[(x['protocol'], x['cause'], x['text'] or x['desc_es']) for x in c['bye_reason']]}")
        if c.get("cancel_by"):
            P(f"  CANCEL por {c['cancel_by']} a los {c['cancel_after_s']} s")
        if c.get("note"):
            P(f"  Nota: {c['note']}")
        if c["retransmissions"]:
            P(f"  Retransmisiones: {c['retransmissions']}")
        if c["final_reason_hdr"]:
            P(f"  Reason en respuesta final: {c['final_reason_hdr']}")
        if c["info_dtmf"]:
            P(f"  DTMF por SIP INFO: {c['info_dtmf']}")
        for m in c["media"]:
            st = m["stats"]
            P(f"  RTP {side_label(m['sender']) if m['sender'] else '?'}: {m['flow']} {m['codec']} ssrc={m['ssrc']} "
              f"t={m['start']}-{m['end']}s pkts={st['packets']} pérdida={st.get('loss_pct')}% ({st.get('lost')}) "
              f"jitter={st.get('jitter_ms')}/{st.get('jitter_max_ms')}ms máxΔ={st.get('max_delta_ms')}ms "
              f"MOS≈{st.get('mos_est')} [{m['match']}]" + _stream_extra(m))
        if not c["media"]:
            P("  RTP: ninguno asociado")
        if ladder_all or only_call or len(calls) <= 5:
            P("  Escalera SIP:")
            for row in c["ladder"][:150]:
                P(f"    {row['t']:>9.3f}s #{row['frame']:<7} {row['src']:>22} -> {row['dst']:<22} {row['msg']:<36}"
                  f"{' [RETX]' if row['retrans'] else ''} {row['sdp']} {row['extra']}")
    unmatched = [x for x in r["rtp_streams"] if not x["call_id"]]
    if unmatched:
        P("\nStreams RTP sin llamada asociada (SDP no capturado o tráfico ajeno):")
        for m in unmatched[:20]:
            st = m["stats"]
            P(f"  {m['flow']} {m['codec']} PT={m['pts']} ssrc={m['ssrc']} t={m['start']}-{m['end']}s pkts={st['packets']} "
              f"pérdida={st.get('loss_pct')}% ({st.get('lost')}) jitter={st.get('jitter_ms')}/{st.get('jitter_max_ms')}ms "
              f"máxΔ={st.get('max_delta_ms')}ms MOS≈{st.get('mos_est')}" + _stream_extra(m))
    if r["options_summary"]:
        P("\nOPTIONS (keepalive):")
        for k, v in r["options_summary"].items():
            P(f"  {k}: enviados {v['sent']} respondidos {v['answered']} códigos {v['codes']} RTT medio {v['rtt_ms_avg']} ms")
    regs = [o for o in r["other_dialogs"] if o["method"] == "REGISTER"]
    if regs:
        P(f"\nREGISTER: {len(regs)} transacciones; finales {dict(Counter(o['final_status'] for o in regs))}")


def main():
    ap = argparse.ArgumentParser(description="Analizador VoIP de capturas pcap/pcapng (SIP/SDP/RTP/RTCP)")
    ap.add_argument("pcap")
    ap.add_argument("--json", help="Ruta para escribir el resultado completo en JSON")
    ap.add_argument("--ladder", action="store_true", help="Imprimir la escalera SIP de todas las llamadas detalladas")
    ap.add_argument("--call", help="Mostrar solo esta llamada (Call-ID)")
    ap.add_argument("--max-calls", type=int, default=10)
    ap.add_argument("--local-ip", action="append", default=[], help="IP propia (repetible) para etiquetar lado local")
    ap.add_argument("--sip-port", action="append", type=int, default=[], help="Puerto SIP adicional (repetible)")
    ap.add_argument("--acdr-port", action="append", type=int, default=[], help="Puerto AudioCodes Debug Recording (def. 925)")
    ap.add_argument("--vxlan-port", action="append", type=int, default=[], help="Puerto VXLAN adicional (def. 4789, 8472)")
    a = ap.parse_args()
    try:
        r = analyze(a.pcap, DEFAULT_SIP_PORTS | set(a.sip_port), set(a.local_ip),
                    {925} | set(a.acdr_port), {4789, 8472} | set(a.vxlan_port))
    except (ValueError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    print_report(r, a.ladder, a.call, a.max_calls)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(r, fh, ensure_ascii=False, indent=1, default=str)
        print(f"\nJSON completo: {a.json}")


if __name__ == "__main__":
    main()
