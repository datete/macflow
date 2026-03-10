"""MACFlow link parsers and subscription decoders.

All functions are pure (stateless) and depend only on standard library + requests.
"""
import base64
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from utils import validate_url_safe


# ── JSON helper ──

def json_or_dict(raw: Any) -> Dict:
    """Parse a value into a dict: pass-through dicts, decode JSON strings."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            try:
                return json.loads(base64.b64decode(raw).decode())
            except Exception:
                return {}
    return {}


# ── 3x-ui sync ──

def sync_3xui(base_url: str, username: str, password: str, verify_tls: bool = False) -> List[Dict]:
    """Login to a 3x-ui panel and return normalised node dicts."""
    validate_url_safe(base_url)
    sess = requests.Session()
    try:
        sess.verify = verify_tls
        base = base_url.rstrip("/")
        r = sess.post(f"{base}/login", data={"username": username, "password": password}, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"login failed: {r.status_code}")
        r2 = sess.get(f"{base}/panel/api/inbounds/list", timeout=20)
        if r2.status_code != 200:
            raise RuntimeError(f"list failed: {r2.status_code}")
        payload = r2.json()
        if not payload.get("success"):
            raise RuntimeError(payload.get("msg", "unknown error"))
        nodes: List[Dict] = []
        for item in payload.get("obj", []):
            nodes.extend(convert_inbound(item))
        return nodes
    finally:
        sess.close()


def convert_inbound(inbound: Dict) -> List[Dict]:
    """Convert a single 3x-ui inbound to a list of node dicts."""
    protocol = inbound.get("protocol", "")
    stream = json_or_dict(inbound.get("streamSettings", "{}"))
    settings = json_or_dict(inbound.get("settings", "{}"))
    remark = inbound.get("remark", f"inbound-{inbound.get('id', '?')}")
    transport = extract_transport(stream)
    listen = inbound.get("listen") or "127.0.0.1"
    port = inbound.get("port")

    if protocol in ("vmess", "vless"):
        return [{"type": protocol, "tag": f"{remark}-{protocol}-{i}",
                 "server": listen, "server_port": port, "uuid": c.get("id"),
                 **({"security": "auto"} if protocol == "vmess" else {"flow": c.get("flow", "")}),
                 "transport": transport}
                for i, c in enumerate(settings.get("clients", []))
                if c.get("id")]
    if protocol == "trojan":
        return [{"type": "trojan", "tag": f"{remark}-trojan-{i}",
                 "server": listen, "server_port": port, "password": c.get("password"), "transport": transport}
                for i, c in enumerate(settings.get("clients", []))
                if c.get("password")]
    if protocol == "shadowsocks":
        return [{"type": "shadowsocks", "tag": f"{remark}-ss",
                 "server": listen, "server_port": port,
                 "method": settings.get("method", "aes-128-gcm"), "password": settings.get("password", "")}]
    return [{"type": "unknown", "tag": f"{remark}-?", "protocol": protocol}]


def extract_transport(stream: Dict) -> Dict:
    """Extract transport config from 3x-ui stream settings."""
    net = stream.get("network", "tcp")
    if net == "ws":
        ws = stream.get("wsSettings", {})
        return {"type": "ws", "path": ws.get("path", "/"), "headers": ws.get("headers", {})}
    if net == "grpc":
        return {"type": "grpc", "service_name": stream.get("grpcSettings", {}).get("serviceName", "")}
    return {"type": "tcp"}


# ── Link parsers ──

def parse_links(text: str) -> List[Dict]:
    """Parse multiple share links (one per line)."""
    results: List[Dict] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("ss://"):
                results.append(parse_ss(line))
            elif line.startswith("vmess://"):
                results.append(parse_vmess(line))
            elif line.startswith("vless://"):
                results.append(parse_vless(line))
            elif line.startswith("trojan://"):
                results.append(parse_trojan(line))
            elif line.startswith(("hysteria2://", "hy2://")):
                results.append(parse_hy2(line))
            elif line.startswith("tuic://"):
                results.append(parse_tuic(line))
        except Exception:
            continue
    return results


def parse_ss(link: str) -> Dict:
    """Parse ss:// share link."""
    link = link[5:]
    tag = ""
    if "#" in link:
        link, tag = link.rsplit("#", 1)
        tag = urllib.parse.unquote(tag)
    if "@" in link:
        userinfo, hostport = link.split("@", 1)
        try:
            decoded = base64.b64decode(userinfo + "==").decode()
        except Exception:
            decoded = userinfo
        method, password = decoded.split(":", 1) if ":" in decoded else (decoded, "")
        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            host = hostport[1:bracket_end]
            port = hostport[bracket_end + 2:] if bracket_end + 1 < len(hostport) and hostport[bracket_end + 1] == ":" else "443"
        else:
            host, port = hostport.split(":", 1) if ":" in hostport else (hostport, "443")
    else:
        try:
            decoded = base64.b64decode(link + "==").decode()
        except Exception:
            decoded = link
        parts = decoded.split("@")
        method, password = parts[0].split(":", 1) if ":" in parts[0] else (parts[0], "")
        hostport = parts[1] if len(parts) > 1 else ""
        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            host = hostport[1:bracket_end]
            port = hostport[bracket_end + 2:] if bracket_end + 1 < len(hostport) and hostport[bracket_end + 1] == ":" else "443"
        else:
            host, port = hostport.split(":", 1) if hostport and ":" in hostport else (hostport or "", "443")
    port = re.sub(r"[^0-9]", "", port.split("/")[0].split("?")[0])
    return {"type": "shadowsocks", "tag": tag or f"ss-{host}", "server": host,
            "server_port": int(port or 443), "method": method, "password": password}


def parse_vmess(link: str) -> Dict:
    """Parse vmess:// share link (base64-encoded JSON)."""
    raw = link[8:]
    try:
        data = json.loads(base64.b64decode(raw + "==").decode())
    except Exception:
        data = {}
    transport = {"type": data.get("net", "tcp")}
    if transport["type"] == "ws":
        transport["path"] = data.get("path", "/")
        host = data.get("host", "")
        if host:
            transport["headers"] = {"Host": host}
    elif transport["type"] == "grpc":
        transport["service_name"] = data.get("path", "")
    result = {"type": "vmess", "tag": data.get("ps", f"vmess-{data.get('add', '')}"),
              "server": data.get("add", ""), "server_port": int(data.get("port", 443)),
              "uuid": data.get("id", ""), "security": data.get("scy", "auto"),
              "alter_id": int(data.get("aid", 0) or 0),
              "transport": transport}
    if str(data.get("tls", "")).lower() == "tls":
        result["tls"] = {"enabled": True,
                         "server_name": data.get("sni", data.get("host", data.get("add", ""))),
                         "insecure": True}
    return result


def parse_vless(link: str) -> Dict:
    """Parse vless:// share link."""
    parsed = urllib.parse.urlparse(link)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless-{parsed.hostname}"
    transport = {"type": params.get("type", "tcp")}
    if transport["type"] == "ws":
        transport["path"] = params.get("path", "/")
        host = params.get("host", "")
        if host:
            transport["headers"] = {"Host": host}
    elif transport["type"] == "grpc":
        transport["service_name"] = params.get("serviceName", "")
    result = {"type": "vless", "tag": tag, "server": parsed.hostname or "",
              "server_port": parsed.port or 443, "uuid": parsed.username or "",
              "flow": params.get("flow", ""), "transport": transport}
    security = params.get("security", "")
    if security in ("tls", "reality"):
        tls = {"enabled": True, "server_name": params.get("sni", parsed.hostname or ""),
               "insecure": params.get("allowInsecure", "0") == "1"}
        alpn = params.get("alpn", "")
        if alpn:
            tls["alpn"] = alpn.split(",")
        fp = params.get("fp", "")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            pbk = params.get("pbk", "")
            sid = params.get("sid", "")
            if pbk:
                tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid}
        result["tls"] = tls
    return result


def parse_trojan(link: str) -> Dict:
    """Parse trojan:// share link."""
    parsed = urllib.parse.urlparse(link)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan-{parsed.hostname}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    transport = {"type": params.get("type", "tcp")}
    if transport["type"] == "ws":
        transport["path"] = params.get("path", "/")
        host = params.get("host", "")
        if host:
            transport["headers"] = {"Host": host}
    elif transport["type"] == "grpc":
        transport["service_name"] = params.get("serviceName", "")
    result = {"type": "trojan", "tag": tag, "server": parsed.hostname or "",
              "server_port": parsed.port or 443, "password": parsed.username or "",
              "transport": transport}
    sni = params.get("sni", parsed.hostname or "")
    tls = {"enabled": True, "server_name": sni,
           "insecure": params.get("allowInsecure", "0") == "1"}
    alpn = params.get("alpn", "")
    if alpn:
        tls["alpn"] = alpn.split(",")
    fp = params.get("fp", "")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    result["tls"] = tls
    return result


def parse_hy2(link: str) -> Dict:
    """Parse hysteria2:// / hy2:// share link."""
    parsed = urllib.parse.urlparse(link)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"hy2-{parsed.hostname}"
    result = {"type": "hysteria2", "tag": tag, "server": parsed.hostname or "",
              "server_port": parsed.port or 443, "password": parsed.username or ""}
    sni = params.get("sni", parsed.hostname or "")
    insecure = params.get("insecure", "0") == "1"
    tls = {"enabled": True, "server_name": sni, "insecure": insecure}
    alpn = params.get("alpn", "")
    if alpn:
        tls["alpn"] = alpn.split(",")
    result["tls"] = tls
    obfs_type = params.get("obfs", "")
    if obfs_type:
        result["obfs"] = {"type": obfs_type, "password": params.get("obfs-password", "")}
    return result


def parse_tuic(link: str) -> Dict:
    """Parse tuic:// share link."""
    parsed = urllib.parse.urlparse(link)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"tuic-{parsed.hostname}"
    return {"type": "tuic", "tag": tag, "server": parsed.hostname or "",
            "server_port": parsed.port or 443, "uuid": parsed.username or "",
            "password": parsed.password or ""}


def parse_subscription(text: str) -> List[Dict]:
    """Parse subscription content: base64, sing-box JSON, or plain links."""
    text = text.strip()
    try:
        decoded = base64.b64decode(text + "==").decode()
        return parse_links(decoded)
    except Exception:
        pass
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "outbounds" in data:
                valid: List[Dict] = []
                for o in data["outbounds"]:
                    if o.get("type") in ("direct", "block", "dns", "selector", "urltest"):
                        continue
                    if not o.get("tag") or not o.get("server"):
                        continue
                    valid.append(o)
                return valid
        except Exception:
            pass
    return parse_links(text)


def safe_node_summary(node: Optional[Dict]) -> Optional[Dict]:
    """Return a safe summary of a node dict for API responses."""
    if not node:
        return None
    return {"tag": node.get("tag"), "type": node.get("type"), "server": node.get("server"),
            "server_port": node.get("server_port"), "latency": node.get("latency"),
            "speed_mbps": node.get("speed_mbps"), "health_score": node.get("health_score"),
            "health_status": node.get("health_status")}
