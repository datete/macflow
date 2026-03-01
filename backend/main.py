#!/usr/bin/env python3
"""MACFlow backend - iStoreOS traffic splitting system v2.0"""
import base64
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
STATE_FILE = DATA_DIR / "state.json"
LOG_FILE = DATA_DIR / "audit.log"
WEB_DIR = ROOT / "web"
MAX_LOG_LINES = 1000

INITIAL_STATE: Dict[str, Any] = {
    "enabled": False,
    "default_policy": "whitelist",
    "failure_policy": "fail-close",
    "dns": {"enforce_redirect_port": 6053, "block_doh_doq": True, "servers": ["8.8.8.8", "1.1.1.1"], "force_redirect": True},
    "xui_sources": [],
    "subscriptions": [],
    "nodes": [],
    "devices": [],
    "last_sync": 0,
    "last_apply": 0,
    "policy_version": None,
    "rollback_version": None,
}

_lock = threading.Lock()
_state_lock = threading.RLock()

# ── Health state (in-memory, resets on restart) ──
_health_state: Dict[str, Any] = {
    "checks": {},
    "alerts": [],
    "overall_status": "unknown",
    "checked_at": 0,
    "probe_cycle": 0,
}
_EGRESS_SERVICES = [
    ("https://api.ipify.org?format=json", "json"),
    ("https://ifconfig.me/ip", "text"),
    ("https://icanhazip.com", "text"),
]
_PROBE_INTERVAL = 60


# ── state I/O (atomic write + migration) ──

def _ensure_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def read_state() -> Dict[str, Any]:
    _ensure_dir()
    if not STATE_FILE.exists():
        write_state(INITIAL_STATE)
        return dict(INITIAL_STATE)
    raw = json.loads(STATE_FILE.read_text("utf-8"))
    changed = False
    for k, v in INITIAL_STATE.items():
        if k not in raw:
            raw[k] = v
            changed = True
    if "xui_config" in raw:
        if not raw.get("xui_sources"):
            old = raw.pop("xui_config")
            if old.get("base_url"):
                raw["xui_sources"] = [{"id": "migrated", "name": "default", **old, "enabled": True}]
        else:
            raw.pop("xui_config", None)
        changed = True
    if "groups" in raw:
        raw.pop("groups", None)
        changed = True
    for d in raw.get("devices", []):
        if "node_tag" not in d:
            d["node_tag"] = d.pop("group", None) or None
            changed = True
        if "mark" not in d:
            d["mark"] = 0
            changed = True
    if changed:
        write_state(raw)
    return raw


def write_state(data: Dict[str, Any]) -> None:
    with _state_lock:
        _ensure_dir()
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
        tmp.replace(STATE_FILE)


def audit(action: str, detail: str = "", level: str = "info", component: str = "system") -> None:
    _ensure_dir()
    entry = json.dumps({
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "component": component,
        "event": action,
        "message": detail,
    }, ensure_ascii=False)
    with _lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
        if LOG_FILE.stat().st_size > 500_000:
            lines = LOG_FILE.read_text("utf-8").splitlines()
            LOG_FILE.write_text("\n".join(lines[-MAX_LOG_LINES:]) + "\n", "utf-8")


def _next_mark(state: Dict) -> int:
    used = {d.get("mark", 0) for d in state.get("devices", [])}
    m = 0x100
    while m in used:
        m += 1
    return m


def _gen_id() -> str:
    return hashlib.md5(f"{time.time()}{os.urandom(4).hex()}".encode()).hexdigest()[:8]


# ── Pydantic models ──

class SourceCreate(BaseModel):
    name: str
    base_url: str
    username: str
    password: str

class SourceUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enabled: Optional[bool] = None

class ManualNode(BaseModel):
    type: str
    tag: str
    server: str
    server_port: int
    password: Optional[str] = None
    uuid: Optional[str] = None
    method: Optional[str] = None
    flow: Optional[str] = None
    security: Optional[str] = None
    username: Optional[str] = None
    transport: Optional[Dict] = None
    tls: Optional[Dict] = None

class LinkImport(BaseModel):
    links: str

class SubCreate(BaseModel):
    name: str
    url: str

class DeviceCreate(BaseModel):
    name: str
    mac: str
    node_tag: Optional[str] = "direct"
    managed: bool = True
    remark: Optional[str] = None

class DeviceBatch(BaseModel):
    devices: List[DeviceCreate]

class DeviceNodeUpdate(BaseModel):
    node_tag: str

class DeviceRemarkUpdate(BaseModel):
    remark: str

class SettingsUpdate(BaseModel):
    default_policy: Optional[str] = None
    failure_policy: Optional[str] = None
    dns: Optional[Dict] = None

class ToggleReq(BaseModel):
    enabled: bool


# ── FastAPI app ──

app = FastAPI(title="macflowd", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/")
def index():
    return FileResponse(str(WEB_DIR / "index.html"))

@app.get("/captive")
def captive_page():
    p = WEB_DIR / "captive.html"
    if p.exists():
        return FileResponse(str(p))
    return HTMLResponse("<h1>Network Not Configured</h1><p>This device has no internet access. LAN only. Contact admin.</p>")


# ── Status ──

@app.get("/api/status")
def api_status():
    s = read_state()
    nodes = s.get("nodes", [])
    devs = s.get("devices", [])
    active_alerts = [a for a in _health_state.get("alerts", []) if a.get("status") == "active"]
    return {
        "version": "2.0.0",
        "enabled": s.get("enabled", False),
        "default_policy": s.get("default_policy", "whitelist"),
        "failure_policy": s.get("failure_policy", "fail-close"),
        "node_count": len(nodes),
        "node_enabled": sum(1 for n in nodes if n.get("enabled", True)),
        "device_count": len(devs),
        "managed_count": sum(1 for d in devs if d.get("managed")),
        "source_count": len(s.get("xui_sources", [])),
        "sub_count": len(s.get("subscriptions", [])),
        "last_sync": s.get("last_sync", 0),
        "last_apply": s.get("last_apply", 0),
        "policy_version": s.get("policy_version"),
        "rollback_version": s.get("rollback_version"),
        "overall_health": _health_state.get("overall_status", "unknown"),
        "active_alert_count": len(active_alerts),
        "critical_alert_count": sum(1 for a in active_alerts if a.get("severity") == "critical"),
        "last_probe_at": _health_state.get("checked_at", 0),
    }


# ── Health check helpers ──

def _run_check(cmd: List[str], timeout: int = 3) -> tuple:
    t = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        ms = int((time.time() - t) * 1000)
        return r.returncode, r.stdout, ms
    except Exception as e:
        ms = int((time.time() - t) * 1000)
        return -1, str(e), ms


def _extract_nft_counters(output: str, keyword: str) -> Dict[str, int]:
    counters = {"packets": 0, "bytes": 0}
    for line in output.splitlines():
        if keyword in line and "counter" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "packets" and i + 1 < len(parts):
                    try:
                        counters["packets"] += int(parts[i + 1])
                    except ValueError:
                        pass
                if p == "bytes" and i + 1 < len(parts):
                    try:
                        counters["bytes"] += int(parts[i + 1])
                    except ValueError:
                        pass
    return counters


def _check_singbox() -> Dict:
    rc, out, ms = _run_check(["pgrep", "sing-box"])
    ok = rc == 0
    return {
        "status": "ok" if ok else "critical",
        "status_legacy": "running" if ok else "stopped",
        "message": "sing-box process active" if ok else "sing-box not running",
        "latency_ms": ms,
    }


def _check_tun() -> Dict:
    rc, out, ms = _run_check(["ip", "link", "show", "singtun0"])
    up = rc == 0 and "UP" in out
    return {
        "status": "ok" if up else "critical",
        "status_legacy": "up" if up else "down",
        "message": "TUN interface UP" if up else "TUN interface down or missing",
        "latency_ms": ms,
    }


def _check_nftables() -> Dict:
    rc, out, ms = _run_check(["nft", "list", "table", "inet", "macflow"])
    loaded = rc == 0
    return {
        "status": "ok" if loaded else "critical",
        "status_legacy": "loaded" if loaded else "missing",
        "message": "macflow table loaded" if loaded else "macflow table not found",
        "latency_ms": ms,
    }


def _check_dns_guard() -> Dict:
    rc, out, ms = _run_check(["nft", "list", "chain", "inet", "macflow", "dns_guard"])
    if rc != 0:
        return {
            "status": "critical", "status_legacy": "missing",
            "message": "dns_guard chain not found", "latency_ms": ms,
            "details": {"chain_exists": False},
        }
    has_udp = "udp dport 53" in out and "redirect" in out
    has_tcp = "tcp dport 53" in out and "redirect" in out
    counters = _extract_nft_counters(out, "redirect")
    details = {
        "chain_exists": True, "udp53_redirect": has_udp,
        "tcp53_redirect": has_tcp, "redirect_packets": counters["packets"],
    }
    if has_udp and has_tcp:
        return {
            "status": "ok", "status_legacy": "loaded",
            "message": f"dns_guard active, {counters['packets']} pkts redirected",
            "latency_ms": ms, "details": details,
        }
    status = "critical" if not (has_udp or has_tcp) else "warn"
    return {
        "status": status, "status_legacy": "degraded",
        "message": "dns_guard partial or missing redirect rules",
        "latency_ms": ms, "details": details,
    }


def _check_leak_guard() -> Dict:
    rc, out, ms = _run_check(["nft", "list", "chain", "inet", "macflow", "forward_guard"])
    if rc != 0:
        return {
            "status": "critical", "status_legacy": "missing",
            "message": "leak_guard (forward_guard) chain not found", "latency_ms": ms,
            "details": {"chain_exists": False},
        }
    checks = {
        "doh_443_block": "dport 443" in out and "doh_ipv4" in out and "drop" in out,
        "dot_853_block": "dport 853" in out and "drop" in out,
        "doq_8853_block": "dport 8853" in out and "drop" in out,
        "stun_3478_block": "dport 3478" in out and "drop" in out,
    }
    all_ok = all(checks.values())
    return {
        "status": "ok" if all_ok else "warn",
        "status_legacy": "loaded" if all_ok else "degraded",
        "message": "leak_guard rules complete" if all_ok else "leak_guard missing some blocking rules",
        "latency_ms": ms, "details": {"chain_exists": True, **checks},
    }


def _check_ipv6_guard() -> Dict:
    rc, out, ms = _run_check(["nft", "list", "chain", "inet", "macflow", "ipv6_guard"])
    if rc != 0:
        return {
            "status": "warn", "status_legacy": "missing",
            "message": "ipv6_guard chain not found (optional)",
            "latency_ms": ms, "details": {"chain_exists": False},
        }
    has_drop = "ip6" in out and "drop" in out
    return {
        "status": "ok" if has_drop else "warn",
        "status_legacy": "loaded" if has_drop else "degraded",
        "message": "ipv6_guard active" if has_drop else "ipv6_guard chain exists but no drop rules",
        "latency_ms": ms, "details": {"chain_exists": True, "has_drop_rules": has_drop},
    }


def _run_health_checks() -> tuple:
    t0 = time.time()
    checks = {
        "singbox": _check_singbox(),
        "tun": _check_tun(),
        "nftables": _check_nftables(),
        "dns_guard": _check_dns_guard(),
        "leak_guard": _check_leak_guard(),
        "ipv6_guard": _check_ipv6_guard(),
    }
    statuses = [c["status"] for c in checks.values()]
    if "critical" in statuses:
        overall = "critical"
    elif "warn" in statuses:
        overall = "warn"
    elif all(s == "ok" for s in statuses):
        overall = "ok"
    else:
        overall = "degraded"

    now = int(t0)
    for name, check in checks.items():
        prev = _health_state["checks"].get(name, {})
        if check["status"] == "ok":
            check["consecutive_failures"] = 0
            check["last_ok_at"] = now
            check["last_fail_at"] = prev.get("last_fail_at", 0)
        else:
            check["consecutive_failures"] = prev.get("consecutive_failures", 0) + 1
            check["last_ok_at"] = prev.get("last_ok_at", 0)
            check["last_fail_at"] = now
        _health_state["checks"][name] = check

    _health_state["overall_status"] = overall
    _health_state["checked_at"] = now
    _update_alerts(checks, now)
    return checks, overall, now, int((time.time() - t0) * 1000)


def _update_alerts(checks: Dict, now: int) -> None:
    existing = {a["id"]: a for a in _health_state.get("alerts", [])}
    for name, c in checks.items():
        alert_id = f"health_{name}"
        consecutive = c.get("consecutive_failures", 0)
        if c["status"] in ("critical", "warn") and consecutive >= 2:
            severity = "critical" if c["status"] == "critical" else "warning"
            if alert_id in existing and existing[alert_id]["status"] == "active":
                existing[alert_id]["last_seen"] = now
                existing[alert_id]["severity"] = severity
                existing[alert_id]["message"] = c["message"]
            else:
                existing[alert_id] = {
                    "id": alert_id, "severity": severity,
                    "title": f"{name} check failed",
                    "message": c["message"],
                    "first_seen": now, "last_seen": now,
                    "status": "active", "recovered_at": None,
                }
        elif c["status"] == "ok" and alert_id in existing and existing[alert_id]["status"] == "active":
            existing[alert_id]["status"] = "resolved"
            existing[alert_id]["recovered_at"] = now
    _health_state["alerts"] = list(existing.values())


def _test_egress_ip(use_proxy: bool = True) -> List[Dict]:
    proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"} if use_proxy else None
    results = []
    for url, fmt in _EGRESS_SERVICES:
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "curl/8.0"}, proxies=proxies)
            if fmt == "json":
                ip = r.json().get("ip", "").strip()
            else:
                ip = r.text.strip()
            valid = bool(ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))
            results.append({"service": url, "ip": ip if valid else None, "ok": valid, "via_proxy": use_proxy})
        except Exception as e:
            if use_proxy:
                return _test_egress_ip(use_proxy=False)
            results.append({"service": url, "ip": None, "ok": False, "error": str(e)})
    return results


def _lookup_ip_geo(ip: str) -> Dict:
    if not ip:
        return {}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org&lang=zh-CN", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


@app.get("/api/health")
def api_health():
    checks, overall, now, total_ms = _run_health_checks()
    return {
        "overall_status": overall,
        "checked_at": now,
        "latency_ms": total_ms,
        "checks": checks,
        "active_alerts": [a for a in _health_state["alerts"] if a["status"] == "active"],
        "singbox": checks["singbox"]["status_legacy"],
        "tun": checks["tun"]["status_legacy"],
        "nftables": checks["nftables"]["status_legacy"],
        "dns_guard": checks["dns_guard"]["status_legacy"],
    }


# ── Egress IP detection ──

@app.get("/api/egress/node/{tag}")
def api_egress_node(tag: str):
    s = read_state()
    node = next((n for n in s.get("nodes", []) if n["tag"] == tag), None)
    if not node:
        raise HTTPException(404, "node not found")
    results = _test_egress_ip()
    ips = [r["ip"] for r in results if r.get("ok") and r["ip"]]
    unique = list(set(ips))
    consistent = len(unique) <= 1
    geo = _lookup_ip_geo(unique[0]) if unique else {}
    if not consistent:
        audit("egress_inconsistent", f"node={tag} ips={unique}", level="warn", component="egress")
    is_proxied = False
    try:
        r2 = requests.get(f"{_CLASH_API}/proxies", timeout=2)
        is_proxied = r2.status_code == 200
    except Exception:
        pass
    return {
        "tag": tag, "node_server": node.get("server"),
        "results": results, "detected_ip": unique[0] if unique else None,
        "consistent": consistent, "unique_ips": unique,
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": is_proxied,
        "note": "通过代理检测" if is_proxied else "本机直连检测（部署到 iStoreOS 后显示节点出口）",
    }


@app.get("/api/egress/device/{mac}")
def api_egress_device(mac: str):
    s = read_state()
    dev = next((d for d in s.get("devices", []) if d["mac"].upper() == mac.upper()), None)
    if not dev:
        raise HTTPException(404, "device not found")
    node_tag = dev.get("node_tag")
    node = next((n for n in s.get("nodes", []) if n["tag"] == node_tag), None) if node_tag else None
    results = _test_egress_ip()
    ips = [r["ip"] for r in results if r.get("ok") and r["ip"]]
    unique = list(set(ips))
    consistent = len(unique) <= 1
    geo = _lookup_ip_geo(unique[0]) if unique else {}
    is_proxied = False
    try:
        r2 = requests.get(f"{_CLASH_API}/proxies", timeout=2)
        is_proxied = r2.status_code == 200
    except Exception:
        pass
    return {
        "mac": mac, "device_name": dev.get("name"), "node_tag": node_tag,
        "node_server": node.get("server") if node else None,
        "results": results, "detected_ip": unique[0] if unique else None,
        "consistent": consistent, "unique_ips": unique,
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": is_proxied,
        "note": "通过代理检测" if is_proxied else "本机直连检测",
    }


@app.get("/api/egress/router")
def api_egress_router():
    results = _test_egress_ip()
    ips = [r["ip"] for r in results if r.get("ok") and r["ip"]]
    unique = list(set(ips))
    geo = _lookup_ip_geo(unique[0]) if unique else {}
    is_proxied = False
    try:
        r2 = requests.get(f"{_CLASH_API}/proxies", timeout=2)
        is_proxied = r2.status_code == 200
    except Exception:
        pass
    return {
        "results": results, "detected_ip": unique[0] if unique else None,
        "consistent": len(unique) <= 1, "unique_ips": unique,
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": is_proxied,
        "note": "通过代理检测" if is_proxied else "本机直连检测",
    }


# ── Alerts API ──

@app.get("/api/alerts")
def api_alerts():
    return _health_state.get("alerts", [])


@app.post("/api/alerts/{alert_id}/ack")
def api_alert_ack(alert_id: str):
    for a in _health_state.get("alerts", []):
        if a["id"] == alert_id:
            a["status"] = "acknowledged"
            audit("alert_ack", alert_id, component="alert")
            return {"ok": True}
    raise HTTPException(404, "alert not found")


# ── Probe scheduler (background thread) ──

def _probe_loop():
    while True:
        time.sleep(_PROBE_INTERVAL)
        try:
            _health_state["probe_cycle"] += 1
            checks, overall, now, _ = _run_health_checks()
            failed = [n for n, c in checks.items() if c["status"] != "ok"]
            if failed:
                audit("probe_fail",
                      f"cycle={_health_state['probe_cycle']} failed={failed}",
                      level="warn", component="probe")
        except Exception as e:
            audit("probe_error", str(e), level="error", component="probe")


@app.on_event("startup")
def _start_probe_scheduler():
    t = threading.Thread(target=_probe_loop, daemon=True, name="probe-scheduler")
    t.start()


# ── Settings ──

@app.get("/api/settings")
def api_settings():
    s = read_state()
    return {
        "enabled": s.get("enabled"),
        "default_policy": s.get("default_policy"),
        "failure_policy": s.get("failure_policy"),
        "dns": s.get("dns", {}),
    }

@app.put("/api/settings")
def api_settings_update(req: SettingsUpdate):
    s = read_state()
    if req.default_policy is not None:
        s["default_policy"] = req.default_policy
    if req.failure_policy is not None:
        s["failure_policy"] = req.failure_policy
    if req.dns is not None:
        s["dns"] = req.dns
    write_state(s)
    audit("settings", json.dumps(req.model_dump(exclude_none=True), ensure_ascii=False))
    return {"ok": True}

@app.post("/api/service/toggle")
def api_toggle(req: ToggleReq):
    s = read_state()
    s["enabled"] = req.enabled
    write_state(s)
    audit("toggle", f"enabled={req.enabled}")
    return {"ok": True, "enabled": req.enabled}


# ── Sources (multi 3x-ui) ──

@app.get("/api/sources")
def api_sources():
    s = read_state()
    out = []
    for src in s.get("xui_sources", []):
        safe = dict(src)
        safe["password"] = "***" if safe.get("password") else ""
        node_count = sum(1 for n in s.get("nodes", []) if n.get("source") == src["id"])
        safe["node_count"] = node_count
        out.append(safe)
    return out

@app.post("/api/sources")
def api_source_create(req: SourceCreate):
    s = read_state()
    src = {"id": _gen_id(), "name": req.name, "base_url": req.base_url,
           "username": req.username, "password": req.password, "enabled": True}
    s.setdefault("xui_sources", []).append(src)
    write_state(s)
    audit("source_add", req.name)
    return {"ok": True, "id": src["id"]}

@app.put("/api/sources/{sid}")
def api_source_update(sid: str, req: SourceUpdate):
    s = read_state()
    for src in s.get("xui_sources", []):
        if src["id"] == sid:
            for k in ("name", "base_url", "username", "password", "enabled"):
                v = getattr(req, k, None)
                if v is not None:
                    src[k] = v
            write_state(s)
            return {"ok": True}
    raise HTTPException(404, "source not found")

@app.delete("/api/sources/{sid}")
def api_source_delete(sid: str):
    s = read_state()
    s["xui_sources"] = [x for x in s.get("xui_sources", []) if x["id"] != sid]
    s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid]
    write_state(s)
    audit("source_del", sid)
    return {"ok": True}

@app.post("/api/sources/{sid}/sync")
def api_source_sync(sid: str):
    s = read_state()
    src = None
    for x in s.get("xui_sources", []):
        if x["id"] == sid:
            src = x
            break
    if not src:
        raise HTTPException(404, "source not found")
    try:
        new_nodes = _sync_3xui(src["base_url"], src["username"], src["password"])
    except Exception as e:
        raise HTTPException(400, str(e))
    panel_host = urllib.parse.urlparse(src["base_url"]).hostname or ""
    existing_tags = {n["tag"] for n in s.get("nodes", []) if n.get("source") != sid}
    added, updated, skipped = 0, 0, 0
    deduped = []
    seen_tags = set()
    for n in new_nodes:
        n["source"] = sid
        n["source_type"] = "3xui"
        n.setdefault("enabled", True)
        n.setdefault("latency", None)
        if n.get("server") in ("127.0.0.1", "0.0.0.0", "localhost", "::1", "") and panel_host:
            n["server"] = panel_host
        if n["tag"] in seen_tags:
            skipped += 1
            continue
        seen_tags.add(n["tag"])
        if n["tag"] in existing_tags:
            skipped += 1
            continue
        deduped.append(n)
        added += 1
    old_count = sum(1 for n in s.get("nodes", []) if n.get("source") == sid)
    s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid] + deduped
    s["last_sync"] = int(time.time())
    write_state(s)
    audit("source_sync", f"{src['name']} total={len(new_nodes)} added={added} skipped={skipped}")
    return {"ok": True, "count": len(deduped), "added": added, "skipped": skipped, "total_from_source": len(new_nodes)}

@app.post("/api/nodes/sync-all")
def api_sync_all():
    s = read_state()
    total = 0
    errors = []
    for src in s.get("xui_sources", []):
        if not src.get("enabled"):
            continue
        try:
            new_nodes = _sync_3xui(src["base_url"], src["username"], src["password"])
            for n in new_nodes:
                n["source"] = src["id"]
                n["source_type"] = "3xui"
                n.setdefault("enabled", True)
                n.setdefault("latency", None)
            s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != src["id"]] + new_nodes
            total += len(new_nodes)
        except Exception as e:
            errors.append(f"{src['name']}: {e}")
    s["last_sync"] = int(time.time())
    write_state(s)
    audit("sync_all", f"total={total} errors={len(errors)}")
    return {"ok": True, "total": total, "errors": errors}


# ── Nodes: manual / import / toggle / test ──

@app.get("/api/nodes")
def api_nodes():
    s = read_state()
    nodes = s.get("nodes", [])
    for n in nodes:
        n.setdefault("enabled", True)
        n.setdefault("latency", None)
        n.setdefault("source_type", "unknown")
    return nodes

@app.post("/api/nodes/manual")
def api_node_manual(node: ManualNode):
    s = read_state()
    for n in s.get("nodes", []):
        if n["tag"] == node.tag:
            raise HTTPException(400, f"tag '{node.tag}' already exists")
    entry = {k: v for k, v in node.model_dump().items() if v is not None}
    entry["source"] = "manual"
    entry["source_type"] = "manual"
    entry["enabled"] = True
    entry["latency"] = None
    s.setdefault("nodes", []).append(entry)
    write_state(s)
    audit("node_manual", node.tag)
    return {"ok": True, "tag": node.tag}

@app.post("/api/nodes/import-link/preview")
def api_node_import_preview(req: LinkImport):
    parsed = _parse_links(req.links)
    return {"nodes": parsed, "count": len(parsed)}


@app.post("/api/nodes/import-link")
def api_node_import_link(req: LinkImport):
    parsed = _parse_links(req.links)
    if not parsed:
        raise HTTPException(400, "no valid links found")
    s = read_state()
    existing_tags = {n["tag"] for n in s.get("nodes", [])}
    added = 0
    for n in parsed:
        if n["tag"] in existing_tags:
            n["tag"] = n["tag"] + "-" + _gen_id()[:4]
        n["source"] = "link"
        n["source_type"] = "link"
        n["enabled"] = True
        n["latency"] = None
        s["nodes"].append(n)
        existing_tags.add(n["tag"])
        added += 1
    write_state(s)
    audit("link_import", f"added={added}")
    return {"ok": True, "added": added}

@app.put("/api/nodes/{tag}")
def api_node_update(tag: str, node: ManualNode):
    s = read_state()
    for i, n in enumerate(s.get("nodes", [])):
        if n["tag"] == tag:
            entry = dict(n)
            for k, v in node.model_dump().items():
                if v is not None:
                    entry[k] = v
            if entry["tag"] != tag:
                for d in s.get("devices", []):
                    if d.get("node_tag") == tag:
                        d["node_tag"] = entry["tag"]
            s["nodes"][i] = entry
            write_state(s)
            audit("node_edit", f"{tag} -> {entry['tag']}")
            return {"ok": True, "tag": entry["tag"]}
    raise HTTPException(404, "node not found")

@app.delete("/api/nodes/{tag}")
def api_node_delete(tag: str):
    s = read_state()
    before = len(s.get("nodes", []))
    s["nodes"] = [n for n in s["nodes"] if n["tag"] != tag]
    if len(s["nodes"]) == before:
        raise HTTPException(404, "node not found")
    for d in s.get("devices", []):
        if d.get("node_tag") == tag:
            d["node_tag"] = None
    write_state(s)
    audit("node_del", tag)
    return {"ok": True}

@app.put("/api/nodes/{tag}/toggle")
def api_node_toggle(tag: str):
    s = read_state()
    for n in s.get("nodes", []):
        if n["tag"] == tag:
            n["enabled"] = not n.get("enabled", True)
            write_state(s)
            return {"ok": True, "enabled": n["enabled"]}
    raise HTTPException(404, "node not found")

@app.post("/api/nodes/{tag}/test")
def api_node_test(tag: str):
    s = read_state()
    node = next((n for n in s.get("nodes", []) if n["tag"] == tag), None)
    if not node:
        raise HTTPException(404, "node not found")
    server = node.get("server", "")
    port = node.get("server_port", 443)
    if not server or server in ("127.0.0.1", "0.0.0.0"):
        return {"ok": True, "tag": tag, "latency": -1}
    try:
        t0 = time.time()
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(5)
        sk.connect((server, port))
        sk.close()
        latency = int((time.time() - t0) * 1000)
    except Exception:
        latency = -1
    for n in s.get("nodes", []):
        if n["tag"] == tag:
            n["latency"] = latency
    write_state(s)
    return {"ok": True, "tag": tag, "latency": latency}


@app.post("/api/nodes/{tag}/speedtest")
def api_node_speedtest(tag: str):
    s = read_state()
    node = next((n for n in s.get("nodes", []) if n["tag"] == tag), None)
    if not node:
        raise HTTPException(404, "node not found")
    server = node.get("server", "")
    port = node.get("server_port", 443)
    if not server or server in ("127.0.0.1", "0.0.0.0"):
        return {"ok": True, "tag": tag, "latency_ms": -1, "speed_mbps": 0}
    latency = -1
    try:
        t0 = time.time()
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(5)
        sk.connect((server, port))
        sk.close()
        latency = int((time.time() - t0) * 1000)
    except Exception:
        pass
    speed_mbps = 0.0
    test_urls = [
        "https://www.google.com/generate_204",
        "https://cp.cloudflare.com/",
        "https://www.gstatic.com/generate_204",
    ]
    for test_url in test_urls:
        try:
            t0 = time.time()
            r = requests.get(test_url, timeout=10,
                             headers={"User-Agent": "Mozilla/5.0"},
                             allow_redirects=True)
            elapsed = time.time() - t0
            if elapsed > 0:
                size = len(r.content) if r.content else 0
                if size < 100:
                    size = int(r.headers.get("content-length", 0)) or 1000
                speed_mbps = round((size * 8) / (elapsed * 1_000_000), 2)
                break
        except Exception:
            continue
    for n in s.get("nodes", []):
        if n["tag"] == tag:
            n["latency"] = latency
            n["speed_mbps"] = speed_mbps
    write_state(s)
    audit("node_speedtest", f"{tag} latency={latency}ms speed={speed_mbps}Mbps")
    return {"ok": True, "tag": tag, "latency_ms": latency, "speed_mbps": speed_mbps}


# ── Subscriptions ──

@app.get("/api/subscriptions")
def api_subs():
    s = read_state()
    out = []
    for sub in s.get("subscriptions", []):
        safe = dict(sub)
        safe["node_count"] = sum(1 for n in s.get("nodes", []) if n.get("source") == sub["id"])
        out.append(safe)
    return out

@app.post("/api/subscriptions")
def api_sub_create(req: SubCreate):
    s = read_state()
    sub = {"id": _gen_id(), "name": req.name, "url": req.url, "last_sync": 0}
    s.setdefault("subscriptions", []).append(sub)
    write_state(s)
    audit("sub_add", req.name)
    return {"ok": True, "id": sub["id"]}

@app.delete("/api/subscriptions/{sid}")
def api_sub_delete(sid: str):
    s = read_state()
    s["subscriptions"] = [x for x in s.get("subscriptions", []) if x["id"] != sid]
    s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid]
    write_state(s)
    audit("sub_del", sid)
    return {"ok": True}

@app.post("/api/subscriptions/{sid}/sync")
def api_sub_sync(sid: str):
    s = read_state()
    sub = next((x for x in s.get("subscriptions", []) if x["id"] == sid), None)
    if not sub:
        raise HTTPException(404, "subscription not found")
    try:
        resp = requests.get(sub["url"], timeout=20)
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        raise HTTPException(400, f"fetch failed: {e}")
    parsed = _parse_subscription(text)
    if not parsed:
        raise HTTPException(400, "no nodes parsed from subscription")
    for n in parsed:
        n["source"] = sid
        n["source_type"] = "subscription"
        n["enabled"] = True
        n["latency"] = None
    s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid] + parsed
    sub["last_sync"] = int(time.time())
    s["last_sync"] = int(time.time())
    write_state(s)
    audit("sub_sync", f"{sub['name']} count={len(parsed)}")
    return {"ok": True, "count": len(parsed)}


# ── Devices (direct node binding, per-row apply) ──

@app.get("/api/devices")
def api_devices():
    s = read_state()
    node_map = {n["tag"]: n for n in s.get("nodes", [])}
    devs = s.get("devices", [])
    for d in devs:
        tag = d.get("node_tag")
        d["node_detail"] = _safe_node_summary(node_map.get(tag)) if tag and tag != "direct" else None
    return devs

@app.post("/api/devices")
def api_device_upsert(item: DeviceCreate):
    with _state_lock:
        s = read_state()
        devs = s.get("devices", [])
        found = False
        for i, d in enumerate(devs):
            if d["mac"].upper() == item.mac.upper():
                devs[i].update({"name": item.name, "node_tag": item.node_tag, "managed": item.managed})
                found = True
                break
        if not found:
            devs.append({"name": item.name, "mac": item.mac.upper(), "node_tag": item.node_tag,
                          "managed": item.managed, "mark": _next_mark(s), "remark": item.remark or ""})
        s["devices"] = devs
        write_state(s)
    audit("device_upsert", f"{item.mac} -> {item.node_tag}")
    return {"ok": True}

@app.post("/api/devices/batch")
def api_device_batch(req: DeviceBatch):
    with _state_lock:
        s = read_state()
        devs = s.get("devices", [])
        idx = {d["mac"].upper(): i for i, d in enumerate(devs)}
        count = 0
        for item in req.devices:
            mac = item.mac.upper()
            if mac in idx:
                devs[idx[mac]].update({"name": item.name, "node_tag": item.node_tag, "managed": item.managed})
            else:
                devs.append({"name": item.name, "mac": mac, "node_tag": item.node_tag,
                              "managed": item.managed, "mark": _next_mark(s)})
                idx[mac] = len(devs) - 1
            count += 1
        s["devices"] = devs
        write_state(s)
    audit("device_batch", f"count={count}")
    return {"ok": True, "count": count}

@app.put("/api/devices/{mac}/node")
def api_device_set_node(mac: str, req: DeviceNodeUpdate):
    with _state_lock:
        s = read_state()
        if req.node_tag and req.node_tag != "direct":
            if not any(n["tag"] == req.node_tag for n in s.get("nodes", [])):
                raise HTTPException(400, f"node '{req.node_tag}' not found")
        for d in s.get("devices", []):
            if d["mac"].upper() == mac.upper():
                d["node_tag"] = req.node_tag
                d["managed"] = True
                if d.get("mark", 0) == 0:
                    d["mark"] = _next_mark(s)
                write_state(s)
                # 热更新 nftables（iStoreOS 上生效，Windows 上静默失败）
                try:
                    mark = d.get("mark", 0)
                    if mark:
                        subprocess.run(
                            ["nft", "add", "element", "inet", "macflow", "mac_to_mark",
                             "{", mac.upper(), ":", f"0x{mark:x}", "}"],
                            capture_output=True, timeout=3
                        )
                except Exception:
                    pass
                audit("device_apply", f"{mac} -> {req.node_tag}")
                return {"ok": True, "mac": mac, "node_tag": req.node_tag, "applied": True}
    raise HTTPException(404, "device not found")

@app.put("/api/devices/{mac}/remark")
def api_device_remark(mac: str, req: DeviceRemarkUpdate):
    s = read_state()
    for d in s.get("devices", []):
        if d["mac"].upper() == mac.upper():
            d["remark"] = req.remark
            write_state(s)
            audit("device_remark", f"{mac}: {req.remark}")
            return {"ok": True}
    raise HTTPException(404, "device not found")

@app.delete("/api/devices/{mac}")
def api_device_delete(mac: str):
    s = read_state()
    before = len(s.get("devices", []))
    deleted = [d for d in s["devices"] if d["mac"].upper() == mac.upper()]
    s["devices"] = [d for d in s["devices"] if d["mac"].upper() != mac.upper()]
    write_state(s)
    for d in deleted:
        try:
            subprocess.run(
                ["nft", "delete", "element", "inet", "macflow", "mac_to_mark",
                 "{", d["mac"], "}"],
                capture_output=True, timeout=3
            )
        except Exception:
            pass
    audit("device_del", f"{mac} removed")
    return {"ok": True, "deleted": before - len(s["devices"])}


# ── System info ──

_BOOT_TIME = time.time()

@app.get("/api/system/info")
def api_system_info():
    import os
    uptime_sec = int(time.time() - _BOOT_TIME)
    h, rem = divmod(uptime_sec, 3600)
    m, s2 = divmod(rem, 60)
    try:
        import resource
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_mb = round(mem / 1024, 1)
    except Exception:
        try:
            pid = os.getpid()
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        mem_mb = round(int(line.split()[1]) / 1024, 1)
                        break
                else:
                    mem_mb = 0
        except Exception:
            mem_mb = 0
    return {
        "uptime_sec": uptime_sec,
        "uptime_str": f"{h}h {m}m {s2}s",
        "memory_mb": mem_mb,
        "pid": os.getpid(),
        "probe_cycle": _health_state.get("probe_cycle", 0),
        "boot_time": int(_BOOT_TIME),
    }

# ── Cloud Update (GitHub) ──

_GITHUB_REPO = "datete/macflow"
_GITHUB_RAW = f"https://raw.githubusercontent.com/{_GITHUB_REPO}/main"
_UPDATE_FILES = ["backend/main.py", "web/index.html", "web/captive.html",
                 "core/apply/atomic_apply.sh", "core/apply/device_patch.sh",
                 "core/dns/dns_leak_probe.sh", "core/rule-engine/render_policy.py"]


@app.get("/api/update/check")
def api_update_check():
    try:
        r = requests.get(f"https://api.github.com/repos/{_GITHUB_REPO}/commits/main",
                         timeout=10, headers={"Accept": "application/vnd.github.v3+json"})
        if r.status_code != 200:
            return {"available": False, "error": f"GitHub API {r.status_code}"}
        data = r.json()
        remote_sha = data.get("sha", "")[:8]
        remote_msg = data.get("commit", {}).get("message", "")
        remote_date = data.get("commit", {}).get("committer", {}).get("date", "")
        local_sha = ""
        try:
            lr = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                capture_output=True, timeout=5, text=True, cwd=str(ROOT))
            local_sha = lr.stdout.strip()
        except Exception:
            pass
        return {
            "available": remote_sha != local_sha and bool(remote_sha),
            "local_version": local_sha or "unknown",
            "remote_version": remote_sha,
            "remote_message": remote_msg,
            "remote_date": remote_date,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.post("/api/update/apply")
def api_update_apply():
    errors = []
    updated = []
    for fpath in _UPDATE_FILES:
        try:
            r = requests.get(f"{_GITHUB_RAW}/{fpath}", timeout=15)
            if r.status_code == 200:
                target = ROOT / fpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(r.content)
                updated.append(fpath)
            else:
                errors.append(f"{fpath}: HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"{fpath}: {e}")

    need_restart = "backend/main.py" in updated
    audit("cloud_update", f"updated={updated} errors={errors}", component="update")

    if need_restart:
        try:
            subprocess.Popen(["sh", "-c", "sleep 2 && killall python3 && cd /opt/macflow && python3 backend/main.py > /var/log/macflow.log 2>&1 &"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    return {"ok": True, "updated": updated, "errors": errors, "restart_scheduled": need_restart}


# ── Traffic stats (sing-box Clash API) ──

_CLASH_API = "http://127.0.0.1:9090"
_last_traffic: Dict[str, Any] = {"up": 0, "down": 0, "ts": 0}

def _poll_traffic_once() -> Dict:
    try:
        r = requests.get(f"{_CLASH_API}/traffic", stream=True, timeout=3)
        for line in r.iter_lines():
            if line:
                data = json.loads(line)
                _last_traffic["up"] = data.get("up", 0)
                _last_traffic["down"] = data.get("down", 0)
                _last_traffic["ts"] = int(time.time())
                r.close()
                return _last_traffic
    except Exception:
        pass
    return _last_traffic


@app.get("/api/traffic/realtime")
def api_traffic_realtime():
    data = _poll_traffic_once()
    return {
        "up_bytes": data["up"],
        "down_bytes": data["down"],
        "up_str": _fmt_bytes(data["up"]) + "/s",
        "down_str": _fmt_bytes(data["down"]) + "/s",
        "ts": data["ts"],
    }


@app.get("/api/traffic/connections")
def api_traffic_connections():
    try:
        r = requests.get(f"{_CLASH_API}/connections", timeout=3)
        if r.status_code == 200:
            data = r.json()
            conns = data.get("connections") or []
            return {
                "count": len(conns),
                "upload_total": data.get("uploadTotal", 0),
                "download_total": data.get("downloadTotal", 0),
                "upload_total_str": _fmt_bytes(data.get("uploadTotal", 0)),
                "download_total_str": _fmt_bytes(data.get("downloadTotal", 0)),
            }
    except Exception:
        pass
    return {"count": 0, "upload_total": 0, "download_total": 0,
            "upload_total_str": "0 B", "download_total_str": "0 B"}


def _fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


@app.post("/api/logs/clear")
def api_logs_clear():
    if LOG_FILE.exists():
        LOG_FILE.write_text("", "utf-8")
    audit("logs_clear", "all logs cleared")
    return {"ok": True}


# ── DHCP discover ──

@app.get("/api/dhcp/discover")
def api_dhcp():
    leases = []
    for p in ("/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"):
        fp = pathlib.Path(p)
        if fp.exists():
            for line in fp.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    leases.append({"mac": parts[1].upper(), "ip": parts[2], "hostname": parts[3]})
            break
    if not leases:
        leases = [
            {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.101", "hostname": "demo-phone"},
            {"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.1.102", "hostname": "demo-laptop"},
            {"mac": "AA:BB:CC:DD:EE:03", "ip": "192.168.1.103", "hostname": "demo-tv"},
            {"mac": "AA:BB:CC:DD:EE:04", "ip": "192.168.1.104", "hostname": "demo-tablet"},
            {"mac": "AA:BB:CC:DD:EE:05", "ip": "192.168.1.105", "hostname": "demo-cam"},
        ]
    s = read_state()
    dev_map = {d["mac"].upper(): d for d in s.get("devices", [])}
    for l in leases:
        d = dev_map.get(l["mac"].upper())
        l["managed"] = d is not None and d.get("managed", False)
        l["node_tag"] = d.get("node_tag") if d else None
        l["device_name"] = d.get("name") if d else None
    return leases


# ── Apply / Rollback ──

@app.post("/api/apply")
def api_apply():
    s = read_state()
    version = time.strftime("v%Y%m%d%H%M%S")
    s["rollback_version"] = s.get("policy_version")
    s["policy_version"] = version
    s["last_apply"] = int(time.time())
    managed = [d for d in s.get("devices", []) if d.get("managed")]
    write_state(s)

    results = {}

    try:
        config = _build_singbox_full(s)
        SINGBOX_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SINGBOX_CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), "utf-8")
        results["singbox_config"] = "written"
    except Exception as e:
        results["singbox_config"] = f"error: {e}"

    nft_result = _apply_nftables(s)
    results["nftables"] = nft_result

    try:
        subprocess.run(["service", "sing-box", "restart"], capture_output=True, timeout=15)
        time.sleep(3)
        r = subprocess.run(["pgrep", "-f", "sing-box"], capture_output=True, timeout=3)
        results["singbox_reload"] = "ok" if r.returncode == 0 else "restart failed"
    except Exception as e:
        results["singbox_reload"] = f"error: {e}"

    iprule_result = _apply_ip_rules(s)
    results["ip_rules"] = iprule_result

    audit("apply", f"version={version} devices={len(managed)} results={results}",
          level="info", component="apply")
    return {"ok": True, "policy_version": version, "affected": len(managed), "results": results}

@app.post("/api/rollback")
def api_rollback():
    s = read_state()
    rv = s.get("rollback_version")
    if not rv:
        raise HTTPException(400, "no rollback version")
    s["policy_version"] = rv
    s["rollback_version"] = None
    s["last_apply"] = int(time.time())
    write_state(s)
    audit("rollback", f"to={rv}")
    return {"ok": True, "restored": rv}


# ── Logs ──

@app.get("/api/logs")
def api_logs(lines: int = 100, level: str = "", component: str = "", event: str = ""):
    if not LOG_FILE.exists():
        return []
    raw = LOG_FILE.read_text("utf-8").strip().splitlines()
    entries = []
    for line in raw:
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            entry = {"ts": "", "level": "info", "component": "system", "event": "legacy", "message": line}
        if level and entry.get("level") != level:
            continue
        if component and entry.get("component") != component:
            continue
        if event and entry.get("event") != event:
            continue
        entries.append(entry)
    return entries[-lines:]


# ── sing-box config preview ──

@app.get("/api/singbox/preview")
def api_singbox_preview():
    return _build_singbox_full(read_state())


# ── 3x-ui sync helper ──

def _sync_3xui(base_url: str, username: str, password: str) -> List[Dict]:
    sess = requests.Session()
    sess.verify = False
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
    nodes = []
    for item in payload.get("obj", []):
        nodes.extend(_convert_inbound(item))
    return nodes


def _convert_inbound(inbound: Dict) -> List[Dict]:
    protocol = inbound.get("protocol", "")
    stream = _j(inbound.get("streamSettings", "{}"))
    settings = _j(inbound.get("settings", "{}"))
    remark = inbound.get("remark", f"inbound-{inbound.get('id', '?')}")
    transport = _transport(stream)
    listen = inbound.get("listen") or "127.0.0.1"
    port = inbound.get("port")

    if protocol in ("vmess", "vless"):
        return [{"type": protocol, "tag": f"{remark}-{protocol}-{i}",
                 "server": listen, "server_port": port, "uuid": c.get("id"),
                 **({"security": "auto"} if protocol == "vmess" else {"flow": c.get("flow", "")}),
                 "transport": transport}
                for i, c in enumerate(settings.get("clients", []))]
    if protocol == "trojan":
        return [{"type": "trojan", "tag": f"{remark}-trojan-{i}",
                 "server": listen, "server_port": port, "password": c.get("password"), "transport": transport}
                for i, c in enumerate(settings.get("clients", []))]
    if protocol == "shadowsocks":
        return [{"type": "shadowsocks", "tag": f"{remark}-ss",
                 "server": listen, "server_port": port,
                 "method": settings.get("method", "aes-128-gcm"), "password": settings.get("password", "")}]
    return [{"type": "unknown", "tag": f"{remark}-?", "protocol": protocol}]


def _transport(stream: Dict) -> Dict:
    net = stream.get("network", "tcp")
    if net == "ws":
        ws = stream.get("wsSettings", {})
        return {"type": "ws", "path": ws.get("path", "/"), "headers": ws.get("headers", {})}
    if net == "grpc":
        return {"type": "grpc", "service_name": stream.get("grpcSettings", {}).get("serviceName", "")}
    return {"type": "tcp"}


# ── Link parser ──

def _parse_links(text: str) -> List[Dict]:
    results = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("ss://"):
                results.append(_parse_ss(line))
            elif line.startswith("vmess://"):
                results.append(_parse_vmess(line))
            elif line.startswith("vless://"):
                results.append(_parse_vless(line))
            elif line.startswith("trojan://"):
                results.append(_parse_trojan(line))
            elif line.startswith(("hysteria2://", "hy2://")):
                results.append(_parse_hy2(line))
            elif line.startswith("tuic://"):
                results.append(_parse_tuic(line))
        except Exception:
            continue
    return results


def _parse_ss(link: str) -> Dict:
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
        host, port = hostport.split(":", 1) if ":" in hostport else (hostport, "443")
    else:
        try:
            decoded = base64.b64decode(link + "==").decode()
        except Exception:
            decoded = link
        parts = decoded.split("@")
        method, password = parts[0].split(":", 1) if ":" in parts[0] else (parts[0], "")
        host, port = parts[1].split(":", 1) if len(parts) > 1 and ":" in parts[1] else ("", "443")
    port = re.sub(r"[^0-9]", "", port.split("/")[0].split("?")[0])
    return {"type": "shadowsocks", "tag": tag or f"ss-{host}", "server": host,
            "server_port": int(port or 443), "method": method, "password": password}


def _parse_vmess(link: str) -> Dict:
    raw = link[8:]
    try:
        data = json.loads(base64.b64decode(raw + "==").decode())
    except Exception:
        data = {}
    return {"type": "vmess", "tag": data.get("ps", f"vmess-{data.get('add','')}"),
            "server": data.get("add", ""), "server_port": int(data.get("port", 443)),
            "uuid": data.get("id", ""), "security": "auto",
            "transport": {"type": data.get("net", "tcp"), "path": data.get("path", "/")}}


def _parse_vless(link: str) -> Dict:
    parsed = urllib.parse.urlparse(link)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless-{parsed.hostname}"
    transport = {"type": params.get("type", "tcp")}
    if transport["type"] == "ws":
        transport["path"] = params.get("path", "/")
    return {"type": "vless", "tag": tag, "server": parsed.hostname or "",
            "server_port": parsed.port or 443, "uuid": parsed.username or "",
            "flow": params.get("flow", ""), "transport": transport}


def _parse_trojan(link: str) -> Dict:
    parsed = urllib.parse.urlparse(link)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan-{parsed.hostname}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    transport = {"type": params.get("type", "tcp")}
    return {"type": "trojan", "tag": tag, "server": parsed.hostname or "",
            "server_port": parsed.port or 443, "password": parsed.username or "",
            "transport": transport}


def _parse_hy2(link: str) -> Dict:
    parsed = urllib.parse.urlparse(link)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"hy2-{parsed.hostname}"
    return {"type": "hysteria2", "tag": tag, "server": parsed.hostname or "",
            "server_port": parsed.port or 443, "password": parsed.username or ""}


def _parse_tuic(link: str) -> Dict:
    parsed = urllib.parse.urlparse(link)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"tuic-{parsed.hostname}"
    return {"type": "tuic", "tag": tag, "server": parsed.hostname or "",
            "server_port": parsed.port or 443, "uuid": parsed.username or "",
            "password": parsed.password or ""}


def _parse_subscription(text: str) -> List[Dict]:
    text = text.strip()
    try:
        decoded = base64.b64decode(text + "==").decode()
        return _parse_links(decoded)
    except Exception:
        pass
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "outbounds" in data:
                return [o for o in data["outbounds"] if o.get("type") not in ("direct", "block", "dns")]
        except Exception:
            pass
    return _parse_links(text)


def _j(raw) -> Dict:
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


def _safe_node_summary(node: Optional[Dict]) -> Optional[Dict]:
    if not node:
        return None
    return {"tag": node.get("tag"), "type": node.get("type"), "server": node.get("server"),
            "server_port": node.get("server_port"), "latency": node.get("latency")}


def _build_singbox(state: Dict) -> Dict:
    nodes = [n for n in state.get("nodes", []) if n.get("enabled", True)]
    return {
        "log": {"level": "info"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "auto_route": False,
                       "sniff": True, "sniff_override_destination": True}],
        "outbounds": nodes + [{"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True},
    }


def _build_singbox_full(state: Dict) -> Dict:
    nodes = [n for n in state.get("nodes", []) if n.get("enabled", True)]
    dns_cfg = state.get("dns", {})
    dns_servers_ips = dns_cfg.get("servers", ["8.8.8.8", "1.1.1.1"])

    outbounds = []
    outbound_tags = []
    for n in nodes:
        ob = _node_to_outbound(n)
        if ob:
            outbounds.append(ob)
            outbound_tags.append(ob["tag"])

    outbound_tags.append("direct-out")
    outbounds.append({"type": "selector", "tag": "proxy-select",
                      "outbounds": outbound_tags,
                      "default": outbound_tags[0] if outbound_tags else "direct-out",
                      "interrupt_exist_connections": False})
    outbounds.append({"type": "direct", "tag": "direct-out"})

    dns_servers = []
    for ip in dns_servers_ips:
        dns_servers.append({"tag": f"dns-{ip}", "type": "udp", "server": ip, "server_port": 53,
                            "detour": "proxy-select"})
    dns_servers.append({"tag": "local-dns", "type": "local", "detour": "direct-out"})

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": dns_servers,
            "rules": [{"outbound": "any", "server": "local-dns"}],
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "singtun0",
             "address": ["172.19.0.1/30"], "auto_route": False,
             "stack": "gvisor", "sniff": True, "sniff_override_destination": True},
            {"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": 1080},
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}],
            "default_mark": 255,
        },
        "experimental": {
            "clash_api": {"external_controller": "0.0.0.0:9090", "external_ui": "", "secret": ""},
        },
    }


def _node_to_outbound(node: Dict) -> Optional[Dict]:
    t = node.get("type", "")
    tag = node.get("tag", "")
    server = node.get("server", "")
    port = node.get("server_port", 443)
    if not server or not tag:
        return None

    ob: Dict[str, Any] = {"type": t, "tag": tag, "server": server, "server_port": port}

    if t == "shadowsocks":
        ob["method"] = node.get("method", "aes-256-gcm")
        ob["password"] = node.get("password", "")
    elif t == "vmess":
        ob["uuid"] = node.get("uuid", "")
        ob["security"] = node.get("security", "auto")
    elif t == "vless":
        ob["uuid"] = node.get("uuid", "")
        flow = node.get("flow", "")
        if flow:
            ob["flow"] = flow
    elif t == "trojan":
        ob["password"] = node.get("password", "")
    elif t == "hysteria2":
        ob["password"] = node.get("password", "")
    elif t == "tuic":
        ob["uuid"] = node.get("uuid", "")
        ob["password"] = node.get("password", "")
    elif t in ("socks", "http"):
        username = node.get("username", "")
        password = node.get("password", "")
        if username:
            ob["username"] = username
        if password:
            ob["password"] = password
    else:
        return None

    transport = node.get("transport")
    if transport and isinstance(transport, dict) and transport.get("type") != "tcp":
        ob["transport"] = transport

    tls = node.get("tls")
    if tls and isinstance(tls, dict) and tls.get("enabled"):
        ob["tls"] = {"enabled": True}
        if tls.get("server_name"):
            ob["tls"]["server_name"] = tls["server_name"]
        if tls.get("utls"):
            ob["tls"]["utls"] = tls["utls"]
        if tls.get("alpn"):
            ob["tls"]["alpn"] = tls["alpn"]
        ob["tls"]["insecure"] = True

    return ob


SINGBOX_CONFIG_PATH = pathlib.Path("/etc/sing-box/config.json")
NFT_TABLE = "inet macflow"


def _apply_nftables(state: Dict) -> str:
    managed = [d for d in state.get("devices", []) if d.get("managed") and d.get("mark", 0) > 0]
    dns_cfg = state.get("dns", {})
    dns_port = dns_cfg.get("enforce_redirect_port", 6053)
    doh_ips = dns_cfg.get("servers", ["8.8.8.8", "1.1.1.1"])

    mac_elements = ", ".join(f'{d["mac"]} : 0x{d["mark"]:x}' for d in managed) if managed else "00:00:00:00:00:00 : 0x0"
    managed_macs = ", ".join(d["mac"] for d in managed) if managed else "00:00:00:00:00:00"
    doh_elements = ", ".join(doh_ips) if doh_ips else "127.0.0.1"

    nft_script = f"""
flush table {NFT_TABLE}
table {NFT_TABLE} {{
  map mac_to_mark {{
    type ether_addr : mark
    elements = {{ {mac_elements} }}
  }}
  set managed_macs {{
    type ether_addr
    elements = {{ {managed_macs} }}
  }}
  set doh_ipv4 {{
    type ipv4_addr
    elements = {{ {doh_elements} }}
  }}
  chain prerouting_mark {{
    type filter hook prerouting priority mangle; policy accept;
    meta mark set ct mark
    meta mark set 0x0
    ct state new ether saddr @managed_macs meta mark set ether saddr map @mac_to_mark
    ct mark set meta mark
  }}
  chain dns_guard {{
    type nat hook prerouting priority dstnat; policy accept;
    meta mark != 0x0 udp dport 53 counter redirect to :{dns_port}
    meta mark != 0x0 tcp dport 53 counter redirect to :{dns_port}
  }}
  chain forward_guard {{
    type filter hook forward priority filter; policy accept;
    meta mark != 0x0 ip daddr @doh_ipv4 tcp dport 443 counter drop
    meta mark != 0x0 ip daddr @doh_ipv4 udp dport 443 counter drop
    meta mark != 0x0 tcp dport 853 counter drop
    meta mark != 0x0 udp dport 853 counter drop
    meta mark != 0x0 udp dport 8853 counter drop
    meta mark != 0x0 udp dport 3478 counter drop
    meta mark != 0x0 udp dport 5349 counter drop
    meta mark != 0x0 tcp dport 3478 counter drop
  }}
  chain ipv6_guard {{
    type filter hook forward priority filter; policy accept;
    meta mark != 0x0 ip6 daddr != fe80::/10 ip6 daddr != ::1 counter drop
  }}
}}
"""
    try:
        r = subprocess.run(["nft", "-f", "-"], input=nft_script.encode(),
                           capture_output=True, timeout=10)
        if r.returncode != 0:
            return f"nft error: {r.stderr.decode()}"
        return "ok"
    except Exception as e:
        return f"nft exception: {e}"


def _apply_ip_rules(state: Dict) -> str:
    managed = [d for d in state.get("devices", []) if d.get("managed") and d.get("mark", 0) > 0]
    errors = []

    try:
        r = subprocess.run(["ip", "-4", "rule", "show"], capture_output=True, timeout=5, text=True)
        for line in r.stdout.splitlines():
            if "macflow" in line or "lookup" in line:
                parts = line.split()
                if "fwmark" in parts:
                    pref = parts[0].rstrip(":")
                    try:
                        subprocess.run(["ip", "-4", "rule", "del", "pref", pref],
                                       capture_output=True, timeout=3)
                    except Exception:
                        pass
    except Exception:
        pass

    marks_seen = set()
    pref = 20000
    for d in managed:
        mark = d["mark"]
        if mark in marks_seen:
            continue
        marks_seen.add(mark)
        table = 100 + (mark - 0x100)

        try:
            subprocess.run(
                ["ip", "-4", "rule", "add", "pref", str(pref),
                 "fwmark", f"0x{mark:x}", "lookup", str(table)],
                capture_output=True, timeout=3
            )
        except Exception as e:
            errors.append(f"rule {mark}: {e}")

        try:
            subprocess.run(
                ["ip", "-4", "route", "replace", "table", str(table),
                 "default", "dev", "singtun0"],
                capture_output=True, timeout=3
            )
        except Exception as e:
            errors.append(f"route {table}: {e}")

        pref += 10

    return "ok" if not errors else "; ".join(errors)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=18080)
