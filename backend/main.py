#!/usr/bin/env python3
"""MACFlow backend - iStoreOS traffic splitting system v2.0"""
import asyncio
import base64
import contextlib
import concurrent.futures
import hashlib
import hmac
import html as _html_mod
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socket
try:
    import resource as _resource_mod
except ImportError:
    _resource_mod = None  # Windows / non-POSIX
import shutil
import subprocess
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, Body, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, field_validator

# ── Extracted modules ──
from utils import (
    ROOT, DATA_DIR, STATE_FILE, LOG_FILE, WEB_DIR, MAX_LOG_LINES,
    LISTEN_PORT as _LISTEN_PORT, _MAC_RE, MARK_TABLE_BASE,
    validate_mac as _validate_mac,
    validate_ip_str as _validate_ip_str,
    validate_url_safe as _validate_url_safe,
    detect_lan_iface as _detect_lan_iface,
    normalize_ipv4 as _normalize_ipv4,
    resolve_mac_to_ip as _resolve_mac_to_ip,
    resolve_device_ipv4 as _resolve_device_ipv4,
    refresh_device_ip_cache as _refresh_device_ip_cache,
    mark_to_table as _mark_to_table,
    gen_id as _gen_id,
    fmt_bytes as _fmt_bytes,
    split_ip_versions as _split_ip_versions,
    audit,
)
from auth import (
    load_auth as _load_auth,
    save_auth as _save_auth,
    verify_password as _verify_password,
    hash_password as _hash_password,
    create_session as _create_session,
    validate_session as _validate_session,
    is_path_public as _is_path_public,
    check_rate_limit as _check_rate_limit,
    record_auth_attempt as _record_auth_attempt,
    cleanup_expired_sessions as _cleanup_expired_sessions,
    clear_sessions as _clear_sessions,
    delete_session as _delete_session,
    SESSION_TTL,
)
from state import (
    INITIAL_STATE,
    state_lock as _state_lock,
    read_state,
    write_state,
    next_mark as _next_mark,
)
from health import (
    health_lock as _health_lock,
    health_state as _health_state,
    fail_close_guard as _fail_close_guard,
    PROBE_INTERVAL as _PROBE_INTERVAL,
    node_set_defaults as _node_set_defaults,
    node_health_score_value as _node_health_score_value,
    compute_node_health_score as _compute_node_health_score,
    recompute_node_health as _recompute_node_health,
    mark_node_probe as _mark_node_probe,
    node_selector_healthy as _node_selector_healthy,
    node_sort_key as _node_sort_key,
    collect_health_checks as _collect_health_checks,
    apply_health_results as _apply_health_results,
    run_health_checks as _run_health_checks,
    is_fail_close_applicable as _is_fail_close_applicable,
    set_fail_close_guard as _set_fail_close_guard,
    guarded_runtime_state as _guarded_runtime_state,
)
from models import (
    SourceCreate, SourceUpdate, ManualNode, LinkImport, SubCreate,
    DeviceCreate, DeviceBatch, NodeBatchAction, DeviceNodeUpdate,
    DeviceRemarkUpdate, DeviceIpUpdate, SettingsUpdate, ToggleReq,
    LoginRequest, SetPasswordRequest,
)
from parsers import (
    parse_links as _parse_links,
    parse_ss as _parse_ss,
    parse_vmess as _parse_vmess,
    parse_vless as _parse_vless,
    parse_trojan as _parse_trojan,
    parse_hy2 as _parse_hy2,
    parse_tuic as _parse_tuic,
    parse_subscription as _parse_subscription,
    sync_3xui as _sync_3xui,
    convert_inbound as _convert_inbound,
    extract_transport as _transport,
    json_or_dict as _j,
    safe_node_summary as _safe_node_summary,
)
_apply_lock = threading.Lock()
_egress_lock = threading.Lock()
_selector_lock = threading.Lock()
_selector_guard: Dict[str, Any] = {
    "last_switch_at": 0,
    "cooldown_sec": 45,
}

_EGRESS_SERVICES = [
    ("https://api.ipify.org?format=json", "json"),
    ("https://ifconfig.me/ip", "text"),
    ("https://icanhazip.com", "text"),
]
_EGRESS_SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=6000000",
    "https://cachefly.cachefly.net/5mb.test",
    "https://proof.ovh.net/files/1Mb.dat",
]
_MIXED_PROXY = os.environ.get("MACFLOW_MIXED_PROXY", "http://127.0.0.1:1080")
_COMMON_DOH_IPV4 = [
    "1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8",
    "9.9.9.9", "149.112.112.112",
    "94.140.14.14", "94.140.15.15",
    "208.67.220.220", "208.67.222.222",
]
_COMMON_DOH_IPV6 = [
    "2606:4700:4700::1001", "2606:4700:4700::1111",
    "2001:4860:4860::8844", "2001:4860:4860::8888",
    "2620:fe::9", "2620:fe::fe",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    "2620:119:35::35", "2620:119:53::53",
]


# ── FastAPI app ──


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: run startup tasks, then yield for request handling."""
    _init_panel_hosts()
    _start_probe_scheduler()
    _start_sse_loops()
    yield


app = FastAPI(title="macflowd", version="2.0.0", lifespan=lifespan)
# CORS: Allow same-origin and common local network origins
_CORS_ORIGINS = [o for o in os.environ.get("MACFLOW_CORS_ORIGINS", "").split(",") if o.strip()] if os.environ.get("MACFLOW_CORS_ORIGINS") else []
if not _CORS_ORIGINS:
    # Default: restrict to common local network origins instead of wildcard
    _CORS_ORIGINS = [
        "http://192.168.1.1:18080",
        "http://192.168.1.1",
        "http://localhost:18080",
        "http://localhost",
        "http://127.0.0.1:18080",
        "http://127.0.0.1",
    ]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Auth-Token", "Authorization"],
    allow_credentials=True,
    )

_PANEL_HOSTS: set = set()


def _init_panel_hosts():
    _PANEL_HOSTS.update({"127.0.0.1", "localhost", "0.0.0.0"})
    try:
        r = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip = line.split()[1].split("/")[0]
                _PANEL_HOSTS.add(ip)
    except Exception:
        pass
    _PANEL_HOSTS.add("192.168.1.1")


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def captive_portal_middleware(request: Request, call_next):
    host = (request.headers.get("host") or "").split(":")[0]
    path = request.url.path
    if host and host not in _PANEL_HOSTS and not path.startswith(("/api/", "/captive")):
        client_ip = request.client.host if request.client else ""
        if client_ip:
            is_captive = await asyncio.to_thread(_is_captive_candidate, client_ip)
            if is_captive:
                return RedirectResponse(f"{_panel_url()}/captive?ip={client_ip}", status_code=302)
    return await call_next(request)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Check authentication for API routes when auth is enabled."""
    path = request.url.path
    # Skip auth check for public paths
    if _is_path_public(path):
        return await call_next(request)
    # Skip if auth is not enabled
    auth = _load_auth()
    if not auth.get("auth_enabled"):
        return await call_next(request)
    # Allow /api/auth/setup when no password is set yet (first-time setup)
    if path == "/api/auth/setup" and not auth.get("password_hash"):
        return await call_next(request)
    # Check session token from header or cookie
    token = request.headers.get("X-Auth-Token", "")
    if not token:
        token = request.cookies.get("macflow_token", "")
    if not token:
        # Try Bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if _validate_session(token):
        return await call_next(request)
    return JSONResponse(
        status_code=401,
        content={"detail": "认证失败，请重新登录", "auth_required": True},
    )


def _is_captive_candidate(client_ip: str) -> bool:
    """Check if this IP belongs to a non-managed device."""
    s = read_state()
    if not s.get("enabled", False):
        return False
    mac_to_ip = _resolve_mac_to_ip()
    ip_to_mac = {v: k for k, v in mac_to_ip.items()}
    mac = ip_to_mac.get(client_ip)
    if not mac:
        return True
    managed_macs = {d["mac"].upper() for d in s.get("devices", []) if d.get("managed")}
    return mac.upper() not in managed_macs


def _get_panel_ip() -> str:
    for ip in _PANEL_HOSTS:
        if ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
            return ip
    return "192.168.1.1"


def _panel_url() -> str:
    """Return the admin panel base URL using detected IP and configured port."""
    return f"http://{_get_panel_ip()}:{_LISTEN_PORT}"


def _resolve_captive_identity(ip: str = "", mac: str = "") -> Dict[str, str]:
    fixed_ip = _normalize_ipv4(ip)
    fixed_mac = str(mac or "").strip().upper()

    mac_to_ip = _resolve_mac_to_ip()
    ip_to_mac = {v: k for k, v in mac_to_ip.items()}

    if fixed_ip and not fixed_mac:
        fixed_mac = str(ip_to_mac.get(fixed_ip, "")).upper()
    if fixed_mac and not fixed_ip:
        fixed_ip = _normalize_ipv4(mac_to_ip.get(fixed_mac, ""))

    return {
        "ip": fixed_ip or "",
        "mac": fixed_mac or "unknown",
    }


def _find_device_by_identity(state: Dict[str, Any], ip: str = "", mac: str = "") -> Optional[Dict[str, Any]]:
    target_ip = _normalize_ipv4(ip)
    target_mac = str(mac or "").strip().upper()

    for d in state.get("devices", []):
        dmac = str(d.get("mac", "")).strip().upper()
        if target_mac and dmac == target_mac:
            return d

    if target_ip:
        for d in state.get("devices", []):
            if _normalize_ipv4(d.get("ip")) == target_ip:
                return d
            if _normalize_ipv4(d.get("last_ip")) == target_ip:
                return d

    return None


@app.get("/")
def index():
    return FileResponse(str(WEB_DIR / "index.html"))


@app.get("/captive")
def captive_page(ip: str = ""):
    state = read_state()
    identity = _resolve_captive_identity(ip=ip)
    device = _find_device_by_identity(state, ip=identity["ip"], mac=identity["mac"])
    device_name = _html_mod.escape(str(device.get("name", "未知设备")) if device else "未知设备")
    safe_mac = _html_mod.escape(identity["mac"])
    safe_ip = _html_mod.escape(identity["ip"] or "unknown")
    panel_url = _panel_url()
    safe_panel = _html_mod.escape(panel_url)
    p = WEB_DIR / "captive.html"
    if p.exists():
        html = p.read_text("utf-8")
        html = html.replace("{{MAC}}", safe_mac)
        html = html.replace("{{IP}}", safe_ip)
        html = html.replace("{{DEVICE_NAME}}", device_name)
        html = html.replace("{{PANEL_URL}}", safe_panel)
        return HTMLResponse(html)
    return HTMLResponse(f"""<h1>Network Not Configured</h1>
<p>Device: {safe_mac} ({safe_ip})</p>
<p>This device has no internet access. Contact admin.</p>
<p>Admin panel: <a href="{safe_panel}">{safe_panel}</a></p>""")


@app.get("/api/captive/status")
def api_captive_status(ip: str = "", mac: str = ""):
    state = read_state()
    identity = _resolve_captive_identity(ip=ip, mac=mac)
    device = _find_device_by_identity(state, ip=identity["ip"], mac=identity["mac"])

    service_enabled = bool(state.get("enabled", False))
    managed = bool(device and device.get("managed"))
    internet_allowed = (not service_enabled) or managed

    if not service_enabled:
        reason = "service-disabled"
        message = "MACFlow 当前未启用，设备不受拦截策略影响。"
    elif managed:
        reason = "managed"
        message = "设备已纳入策略管理，请等待 1-3 秒后重试联网。"
    elif device:
        reason = "pending-apply"
        message = "设备已录入但策略尚未生效，请管理员在面板执行应用。"
    else:
        reason = "unmanaged"
        message = "设备尚未纳管，请管理员在设备分流页添加并分配节点。"

    return {
        "ip": identity["ip"],
        "mac": identity["mac"],
        "device_name": str(device.get("name", "")) if device else "",
        "node_tag": str(device.get("node_tag", "")) if device else "",
        "managed": managed,
        "service_enabled": service_enabled,
        "internet_allowed": internet_allowed,
        "reason": reason,
        "message": message,
        "panel_url": _panel_url(),
        "updated_at": int(time.time()),
    }


# ── Status ──

@app.get("/api/status")
def api_status():
    s = read_state()
    nodes = s.get("nodes", [])
    devs = s.get("devices", [])
    with _health_lock:
        active_alerts = [a for a in _health_state.get("alerts", []) if a.get("status") == "active"]
        overall_health = _health_state.get("overall_status", "unknown")
        last_probe_at = _health_state.get("checked_at", 0)
        fc_active = _fail_close_guard.get("active", False)
        fc_since = _fail_close_guard.get("since", 0)
        fc_reason = _fail_close_guard.get("reason", "")
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
        "overall_health": overall_health,
        "active_alert_count": len(active_alerts),
        "critical_alert_count": sum(1 for a in active_alerts if a.get("severity") == "critical"),
        "last_probe_at": last_probe_at,
        "fail_close_active": fc_active,
        "fail_close_since": fc_since,
        "fail_close_reason": fc_reason,
    }


# ── Authentication endpoints ──

@app.get("/api/auth/status")
def api_auth_status(request: Request):
    """Check if auth is required and current session validity."""
    auth = _load_auth()
    # Check if the caller has a valid session
    token = request.headers.get("X-Auth-Token", "")
    if not token:
        token = request.cookies.get("macflow_token", "")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    valid = _validate_session(token) if token else False
    return {
        "auth_enabled": auth.get("auth_enabled", False),
        "password_set": bool(auth.get("password_hash", "")),
        "valid_session": valid,
    }

@app.post("/api/auth/login")
def api_auth_login(req: LoginRequest, request: Request, response: Response):
    """Authenticate and get session token."""
    client_ip = request.client.host if request.client else ""
    # Rate limiting
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="登录尝试过于频繁，请稍后再试")
    auth = _load_auth()
    if not auth.get("auth_enabled") or not auth.get("password_hash"):
        return {"ok": True, "message": "认证未启用", "token": ""}
    if not _verify_password(req.password, auth["password_hash"]):
        _record_auth_attempt(client_ip)
        raise HTTPException(status_code=401, detail="密码错误")
    token = _create_session(client_ip)
    _is_secure = request.url.scheme == "https" if hasattr(request, 'url') else False
    response.set_cookie(
        key="macflow_token",
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=_is_secure,
    )
    return {"ok": True, "message": "登录成功", "token": token}

@app.post("/api/auth/logout")
def api_auth_logout(request: Request, response: Response):
    """Invalidate current session."""
    token = request.headers.get("X-Auth-Token", "") or request.cookies.get("macflow_token", "")
    _delete_session(token)
    response.delete_cookie("macflow_token")
    return {"ok": True, "message": "已登出"}

@app.post("/api/auth/setup")
def api_auth_setup(req: SetPasswordRequest, request: Request):
    """Set or change password. First-time setup or password change."""
    auth = _load_auth()
    # If auth is already enabled, verify current password
    if auth.get("auth_enabled") and auth.get("password_hash"):
        if not _verify_password(req.password, auth["password_hash"]):
            raise HTTPException(status_code=401, detail="当前密码错误")
        new_pw = req.new_password
        if not new_pw or len(new_pw) < 8:
            raise HTTPException(status_code=400, detail="新密码至少 8 位")
    else:
        # First-time setup
        new_pw = req.password
        if not new_pw or len(new_pw) < 8:
            raise HTTPException(status_code=400, detail="密码至少 8 位")
    auth["password_hash"] = _hash_password(new_pw)
    auth["auth_enabled"] = True
    _save_auth(auth)
    # Clear all existing sessions
    _clear_sessions()
    # Create new session for the user
    token = _create_session()
    return {"ok": True, "message": "密码已设置", "token": token}

@app.post("/api/auth/disable")
def api_auth_disable(req: LoginRequest):
    """Disable authentication (requires current password)."""
    auth = _load_auth()
    if auth.get("auth_enabled") and auth.get("password_hash"):
        if not _verify_password(req.password, auth["password_hash"]):
            raise HTTPException(status_code=401, detail="密码错误")
    auth["auth_enabled"] = False
    _save_auth(auth)
    _clear_sessions()
    return {"ok": True, "message": "认证已关闭"}


def _extract_ip_from_text(raw: str) -> str:
    if not raw:
        return ""
    for tok in re.split(r"[,\s]+", raw.strip()):
        token = tok.strip().strip("[]")
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
            return token
        except Exception:
            continue
    return ""


def _extract_ip_from_response(resp: requests.Response, fmt: str) -> str:
    candidates: List[str] = []
    if fmt == "json":
        try:
            payload = resp.json()
            for key in ("ip", "query", "origin"):
                v = payload.get(key)
                if isinstance(v, str):
                    candidates.append(v)
        except Exception:
            candidates.append(resp.text)
    else:
        candidates.append(resp.text)

    for cand in candidates:
        ip = _extract_ip_from_text(cand)
        if ip:
            return ip
    return ""


def _egress_error_rows(reason: str, use_proxy: bool = True) -> List[Dict[str, Any]]:
    return [
        {
            "service": url,
            "ip": None,
            "ok": False,
            "via_proxy": use_proxy,
            "error": reason,
        }
        for url, _ in _EGRESS_SERVICES
    ]


def _test_egress_ip(use_proxy: bool = True, timeout: int = 8, allow_direct_fallback: bool = True) -> List[Dict]:
    proxies = {"http": _MIXED_PROXY, "https": _MIXED_PROXY} if use_proxy else None

    def _check_one(url_fmt):
        url, fmt = url_fmt
        item: Dict[str, Any] = {"service": url, "ip": None, "ok": False, "via_proxy": use_proxy}
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "curl/8.0"}, proxies=proxies)
            r.raise_for_status()
            ip = _extract_ip_from_response(r, fmt)
            if ip:
                item["ip"] = ip
                item["ok"] = True
            else:
                item["error"] = "ip parse failed"
        except Exception as e:
            item["error"] = str(e)
        return item

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_EGRESS_SERVICES)) as pool:
        results = list(pool.map(_check_one, _EGRESS_SERVICES))

    ok_count = sum(1 for r in results if r.get("ok"))

    if use_proxy and ok_count == 0 and allow_direct_fallback:
        proxy_attempts = list(results)
        fallback = _test_egress_ip(use_proxy=False, timeout=timeout, allow_direct_fallback=False)
        for idx, row in enumerate(fallback):
            row["proxy_fallback"] = True
            if idx < len(proxy_attempts) and proxy_attempts[idx].get("error"):
                row["proxy_error"] = proxy_attempts[idx].get("error")
        return fallback
    return results


def _summarize_egress(results: List[Dict]) -> Dict[str, Any]:
    ips = [r.get("ip") for r in results if r.get("ok") and r.get("ip")]
    unique = list(dict.fromkeys(ips))
    return {
        "detected_ip": unique[0] if unique else None,
        "unique_ips": unique,
        "consistent": len(unique) <= 1,
        "proxied": any(r.get("ok") and r.get("via_proxy") for r in results),
        "proxy_fallback": any(r.get("proxy_fallback") for r in results),
    }


def _clash_get_selector_state() -> tuple:
    try:
        r = requests.get(f"{_CLASH_API}/proxies/proxy-select", timeout=3)
        if r.status_code != 200:
            return "", [], f"clash selector http={r.status_code}"
        data = r.json()
        now = data.get("now", "")
        options = data.get("all") or []
        return now, options, ""
    except Exception as e:
        return "", [], str(e)


def _clash_set_selector(tag: str) -> bool:
    try:
        r = requests.put(f"{_CLASH_API}/proxies/proxy-select", json={"name": tag}, timeout=4)
        return r.status_code in (200, 204)
    except Exception:
        return False


def _choose_best_selector_tag(state: Dict[str, Any], options: List[str]) -> str:
    if not options:
        return ""
    nodes = [dict(n) for n in state.get("nodes", []) if n.get("enabled", True) and n.get("tag") in options]
    if not nodes:
        return ""
    for n in nodes:
        _recompute_node_health(n)
    healthy = [n for n in nodes if _node_selector_healthy(n)]
    pool = healthy if healthy else nodes
    pool.sort(key=_node_sort_key)
    return str(pool[0].get("tag", "")) if pool else ""


def _auto_heal_selector(state: Dict[str, Any]) -> None:
    if not state.get("enabled", False):
        return
    current, options, err = _clash_get_selector_state()
    if err or not options:
        return
    best = _choose_best_selector_tag(state, options)
    if not best or best == current:
        return

    node_map = {n.get("tag"): dict(n) for n in state.get("nodes", []) if n.get("enabled", True)}
    current_node = node_map.get(current)
    if current_node:
        _recompute_node_health(current_node)
    should_switch = False
    if current_node is None:
        should_switch = True
    else:
        failures = int(current_node.get("health_failures", 0)) if str(current_node.get("health_failures", "")).isdigit() else 0
        unhealthy = not _node_selector_healthy(current_node)
        should_switch = unhealthy and failures >= 2
    if not should_switch:
        return

    now = int(time.time())
    with _selector_lock:
        cooldown = int(_selector_guard.get("cooldown_sec", 45))
        last_switch = int(_selector_guard.get("last_switch_at", 0))
        if now - last_switch < cooldown:
            return

        if _clash_set_selector(best):
            _selector_guard["last_switch_at"] = now
            audit("selector_auto_switch", f"{current or '-'} -> {best}", level="warn", component="probe")


def _test_egress_for_selector(tag: str, strict_proxy: bool = True) -> tuple:
    with _egress_lock:
        prev, options, err = _clash_get_selector_state()
        if err:
            if strict_proxy:
                return _egress_error_rows(f"selector unavailable: {err}"), "代理出口检测失败（selector 状态不可用）"
            results = _test_egress_ip(use_proxy=True, allow_direct_fallback=True)
            return results, "代理出口检测（selector 状态不可用）"

        if tag not in options:
            if strict_proxy:
                return _egress_error_rows("target not in selector"), f"代理出口检测失败（目标节点 {tag} 不在 selector）"
            results = _test_egress_ip(use_proxy=True, allow_direct_fallback=True)
            return results, f"代理出口检测（目标节点 {tag} 不在 selector）"

        switched = False
        if prev and prev != tag:
            if _clash_set_selector(tag):
                switched = True
                time.sleep(0.25)
            else:
                if strict_proxy:
                    return _egress_error_rows("selector switch failed"), f"代理出口检测失败（selector 切换到 {tag} 失败）"
                results = _test_egress_ip(use_proxy=True, allow_direct_fallback=True)
                return results, f"代理出口检测（selector 切换到 {tag} 失败）"

        try:
            results = _test_egress_ip(use_proxy=True, allow_direct_fallback=not strict_proxy)
            if strict_proxy and not any(r.get("ok") and r.get("via_proxy") for r in results):
                return results, f"通过 selector={tag} 检测失败（代理链路不可用）"
            return results, f"通过 selector={tag} 检测"
        finally:
            if switched and prev:
                _clash_set_selector(prev)


def _clash_proxy_delay_ms(tag: str, timeout_ms: int = 8000) -> int:
    encoded = urllib.parse.quote(tag, safe="")
    urls = [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/",
        "https://www.google.com/generate_204",
    ]
    for test_url in urls:
        try:
            r = requests.get(
                f"{_CLASH_API}/proxies/{encoded}/delay",
                params={"url": test_url, "timeout": timeout_ms},
                timeout=max(5, timeout_ms // 1000 + 2),
            )
            if r.status_code != 200:
                continue
            delay = int(r.json().get("delay", -1))
            if delay >= 0:
                return delay
        except Exception:
            continue
    return -1


def _measure_speed_via_selector(tag: str) -> tuple:
    with _egress_lock:
        prev, options, err = _clash_get_selector_state()
        if err:
            return 0.0, "selector unavailable"
        if tag not in options:
            return 0.0, "target not in selector"

        switched = False
        if prev and prev != tag:
            if not _clash_set_selector(tag):
                return 0.0, "selector switch failed"
            switched = True
            time.sleep(0.25)

        try:
            proxies = {"http": _MIXED_PROXY, "https": _MIXED_PROXY}
            last_err = ""
            for test_url in _EGRESS_SPEED_URLS:
                try:
                    t0 = time.time()
                    total = 0
                    with requests.get(
                        test_url,
                        timeout=12,
                        proxies=proxies,
                        stream=True,
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"},
                    ) as r:
                        r.raise_for_status()
                        for chunk in r.iter_content(65536):
                            if not chunk:
                                continue
                            total += len(chunk)
                            elapsed = time.time() - t0
                            if elapsed >= 5 or total >= 3_000_000:
                                break
                    elapsed = max(time.time() - t0, 0.001)
                    if total >= 256_000:
                        speed = round((total * 8) / (elapsed * 1_000_000), 2)
                        return speed, "ok"
                except Exception as e:
                    last_err = str(e)
                    continue
            return 0.0, last_err or "download probe failed"
        finally:
            if switched and prev:
                _clash_set_selector(prev)


def _lookup_ip_geo(ip: str) -> Dict:
    if not ip:
        return {}
    # Validate IP to prevent SSRF
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return {}
    except ValueError:
        return {}

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org&lang=zh-CN", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("country"):
                return data
    except Exception:
        pass

    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("success", True):
                return {
                    "country": data.get("country", ""),
                    "countryCode": data.get("country_code", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("connection", {}).get("isp", ""),
                    "org": data.get("connection", {}).get("org", ""),
                }
    except Exception:
        pass

    return {}


@app.get("/api/health")
def api_health():
    with _health_lock:
        checks, overall, now, total_ms = _run_health_checks(_is_singbox_running)
        active_alerts = [a for a in _health_state["alerts"] if a["status"] == "active"]
        fc_active = _fail_close_guard.get("active", False)
        fc_since = _fail_close_guard.get("since", 0)
        fc_reason = _fail_close_guard.get("reason", "")
    return {
        "overall_status": overall,
        "checked_at": now,
        "latency_ms": total_ms,
        "checks": checks,
        "active_alerts": active_alerts,
        "fail_close_active": fc_active,
        "fail_close_since": fc_since,
        "fail_close_reason": fc_reason,
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
    if not node.get("enabled", True):
        results = _egress_error_rows("node disabled")
        note = f"节点 {tag} 已禁用，无法检测代理出口"
    else:
        results, note = _test_egress_for_selector(tag, strict_proxy=True)
    summary = _summarize_egress(results)
    geo = _lookup_ip_geo(summary["detected_ip"] or "") if summary["detected_ip"] else {}
    if not summary["consistent"]:
        audit("egress_inconsistent", f"node={tag} ips={summary['unique_ips']}", level="warn", component="egress")
    if not summary["detected_ip"]:
        audit("egress_node_fail", f"node={tag} note={note}", level="warn", component="egress")
    return {
        "tag": tag, "node_server": node.get("server"),
        "results": results, "detected_ip": summary["detected_ip"],
        "consistent": summary["consistent"], "unique_ips": summary["unique_ips"],
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": summary["proxied"],
        "note": note,
    }


@app.get("/api/egress/device/{mac}")
def api_egress_device(mac: str):
    s = read_state()
    dev = next((d for d in s.get("devices", []) if d["mac"].upper() == mac.upper()), None)
    if not dev:
        raise HTTPException(404, "device not found")
    node_tag = dev.get("node_tag")
    node = next((n for n in s.get("nodes", []) if n["tag"] == node_tag), None) if node_tag else None
    if node_tag == "direct":
        results = _test_egress_ip(use_proxy=False, allow_direct_fallback=False)
        note = "设备绑定 direct，按直连出口检测"
    elif node and node.get("enabled", True):
        results, note = _test_egress_for_selector(node_tag, strict_proxy=True)
        note = f"设备绑定 {node_tag}，{note}"
    else:
        results = _egress_error_rows("device has no valid node binding")
        note = "设备未绑定有效节点，无法进行代理出口检测"

    summary = _summarize_egress(results)
    geo = _lookup_ip_geo(summary["detected_ip"] or "") if summary["detected_ip"] else {}
    if not summary["detected_ip"] and node_tag and node_tag != "direct":
        audit("egress_device_fail", f"mac={mac} node={node_tag} note={note}", level="warn", component="egress")
    return {
        "mac": mac, "device_name": dev.get("name"), "node_tag": node_tag,
        "node_server": node.get("server") if node else None,
        "results": results, "detected_ip": summary["detected_ip"],
        "consistent": summary["consistent"], "unique_ips": summary["unique_ips"],
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": summary["proxied"],
        "note": note,
    }


@app.get("/api/egress/router")
def api_egress_router():
    try:
        _auto_heal_selector(read_state())
    except Exception:
        pass
    results = _test_egress_ip(use_proxy=True, allow_direct_fallback=False)
    summary = _summarize_egress(results)
    geo = _lookup_ip_geo(summary["detected_ip"] or "") if summary["detected_ip"] else {}
    note = "通过 mixed 入站代理出口检测" if summary["proxied"] else "代理出口检测失败（未获得代理出口 IP）"
    return {
        "results": results, "detected_ip": summary["detected_ip"],
        "consistent": summary["consistent"], "unique_ips": summary["unique_ips"],
        "country": geo.get("country", ""), "country_code": geo.get("countryCode", ""),
        "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        "tested_at": int(time.time()),
        "proxied": summary["proxied"],
        "note": note,
    }


# ── Alerts API ──

@app.get("/api/alerts")
def api_alerts():
    with _health_lock:
        return list(_health_state.get("alerts", []))


@app.post("/api/alerts/{alert_id}/ack")
def api_alert_ack(alert_id: str):
    with _health_lock:
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
            _need_apply = False
            _allow_restart = False
            # Collect health data OUTSIDE the lock to avoid blocking /api/health
            checks, overall, now, _ = _collect_health_checks(_is_singbox_running)
            with _health_lock:
                _health_state["probe_cycle"] += 1
                _apply_health_results(checks, overall, now)
            failed = [n for n, c in checks.items() if c["status"] != "ok"]
            if failed:
                audit("probe_fail",
                      f"cycle={_health_state['probe_cycle']} failed={failed}",
                      level="warn", component="probe")
            s = read_state()
            if _is_fail_close_applicable(s):
                guard_active = _fail_close_guard.get("active")
                if overall == "critical":
                    if not guard_active:
                        _set_fail_close_guard(True, "critical health failure", audit_fn=audit)
                        _need_apply = True
                        audit("fail_close_active",
                              "critical health failure detected",
                              level="error", component="probe")
                    else:
                        _need_apply = True
                        audit("fail_close_reconcile",
                              "guard active and health critical",
                              level="warn", component="probe")
                elif overall == "ok" and guard_active:
                    _set_fail_close_guard(False, "health recovered", audit_fn=audit)
                    _need_apply = True
                    _allow_restart = True
                    audit("fail_close_released",
                          "health recovered",
                          level="info", component="probe")
            elif _fail_close_guard.get("active"):
                _set_fail_close_guard(False, "policy no longer applicable", audit_fn=audit)

            if s.get("enabled", False) and not _fail_close_guard.get("active"):
                with _state_lock:
                    latest = read_state()
                    if _refresh_device_ip_cache(latest):
                        write_state(latest)
                        _need_apply = True
                        s = latest
                        audit("device_ip_cache_refresh", "", component="probe")
                _auto_heal_selector(s)

            # Single consolidated apply per probe cycle
            if _need_apply:
                runtime = _runtime_hot_apply(allow_restart=_allow_restart)
                audit("probe_apply", f"runtime={runtime}", component="probe")

            # Periodic session cleanup
            _cleanup_expired_sessions()
        except Exception as e:
            audit("probe_error", str(e), level="error", component="probe")


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
    # Validate default_policy value
    _VALID_POLICIES = ("whitelist", "block", "allow")
    if req.default_policy is not None and req.default_policy not in _VALID_POLICIES:
        raise HTTPException(400, f"default_policy must be one of {_VALID_POLICIES}")
    _VALID_FAILURE_POLICIES = ("fail-close", "fail-open")
    if req.failure_policy is not None and req.failure_policy not in _VALID_FAILURE_POLICIES:
        raise HTTPException(400, f"failure_policy must be one of {_VALID_FAILURE_POLICIES}")
    # Validate DNS server IPs if provided
    if req.dns is not None:
        servers = req.dns.get("servers", [])
        if isinstance(servers, list):
            for srv in servers:
                try:
                    ipaddress.ip_address(str(srv))
                except ValueError:
                    raise HTTPException(400, f"Invalid DNS server IP: {srv}")
    with _state_lock:
        s = read_state()
        if req.default_policy is not None:
            s["default_policy"] = req.default_policy
        if req.failure_policy is not None:
            s["failure_policy"] = req.failure_policy
        if req.dns is not None:
            s["dns"] = req.dns
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("settings", json.dumps(req.model_dump(exclude_none=True), ensure_ascii=False) + f" runtime={runtime}")
    return {"ok": True, "runtime": runtime}

@app.post("/api/service/toggle")
def api_toggle(req: ToggleReq):
    with _state_lock:
        s = read_state()
        s["enabled"] = req.enabled
        write_state(s)
    if not req.enabled:
        if _fail_close_guard.get("active"):
            _set_fail_close_guard(False, "service disabled", audit_fn=audit)
        _flush_nftables()
        _flush_ip_rules()
        for service_name in _SINGBOX_SERVICE_NAMES:
            try:
                subprocess.run(["service", service_name, "stop"], capture_output=True, timeout=10)
            except Exception:
                pass
        try:
            subprocess.run(["killall", "sing-box"], capture_output=True, timeout=5)
        except Exception:
            pass
        audit("toggle", "service disabled, rules flushed")

        return {"ok": True, "enabled": req.enabled,
                "runtime": {"singbox_config": "stopped", "nftables": "flushed", "singbox_reload": "stopped", "ip_rules": "flushed"}}

    runtime = _runtime_hot_apply(allow_restart=True)
    audit("toggle", f"service enabled runtime={runtime}")
    return {"ok": True, "enabled": req.enabled, "runtime": runtime}


# ── Sources (multi 3x-ui) ──

@app.get("/api/sources")
def api_sources():
    s = read_state()
    out = []
    for src in s.get("xui_sources", []):
        safe = dict(src)
        safe["password"] = "***" if safe.get("password") else ""
        safe.setdefault("enabled", True)
        safe.setdefault("last_sync", 0)
        safe.setdefault("last_error", "")
        node_count = sum(1 for n in s.get("nodes", []) if n.get("source") == src["id"])
        safe["node_count"] = node_count
        out.append(safe)
    return out

@app.post("/api/sources")
def api_source_create(req: SourceCreate):
    with _state_lock:
        s = read_state()
        src = {"id": _gen_id(), "name": req.name, "base_url": req.base_url,
               "username": req.username, "password": req.password, "enabled": True,
               "last_sync": 0, "last_error": ""}
        s.setdefault("xui_sources", []).append(src)
        write_state(s)
    audit("source_add", req.name)
    return {"ok": True, "id": src["id"]}

@app.put("/api/sources/{sid}")
def api_source_update(sid: str, req: SourceUpdate):
    with _state_lock:
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
    with _state_lock:
        s = read_state()
        s["xui_sources"] = [x for x in s.get("xui_sources", []) if x["id"] != sid]
        s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid]
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("source_del", f"{sid} runtime={runtime}")
    return {"ok": True, "runtime": runtime}

@app.post("/api/sources/{sid}/sync")
def api_source_sync(sid: str):
    with _state_lock:
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
        with _state_lock:
            s = read_state()
            for x in s.get("xui_sources", []):
                if x.get("id") == sid:
                    x["last_error"] = str(e)
                    break
            write_state(s)
        raise HTTPException(400, str(e))
    panel_host = urllib.parse.urlparse(src["base_url"]).hostname or ""
    with _state_lock:
        s = read_state()
        existing_tags = {n["tag"] for n in s.get("nodes", []) if n.get("source") != sid}
        added, skipped = 0, 0
        deduped = []
        seen_tags = set()
        for n in new_nodes:
            n["source"] = sid
            n["source_type"] = "3xui"
            _node_set_defaults(n)
            _recompute_node_health(n)
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
        s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid] + deduped
        now = int(time.time())
        for x in s.get("xui_sources", []):
            if x.get("id") == sid:
                x["last_sync"] = now
                x["last_error"] = ""
                break
        s["last_sync"] = now
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("source_sync", f"{src['name']} total={len(new_nodes)} added={added} skipped={skipped} runtime={runtime}")
    return {
        "ok": True,
        "count": len(deduped),
        "added": added,
        "skipped": skipped,
        "total_from_source": len(new_nodes),
        "runtime": runtime,
    }

@app.post("/api/nodes/sync-all")
def api_sync_all():
    with _state_lock:
        s = read_state()
        sources = [dict(src) for src in s.get("xui_sources", []) if src.get("enabled")]
    total = 0
    errors = []
    synced = {}
    sync_failures = {}
    with _state_lock:
        s = read_state()
        source_existing_tags = {}
        for n in s.get("nodes", []):
            source_existing_tags.setdefault(n.get("source"), set()).add(n.get("tag"))
        reserved_tags = {n.get("tag") for n in s.get("nodes", []) if n.get("tag")}
    for src in sources:
        try:
            new_nodes = _sync_3xui(src["base_url"], src["username"], src["password"])
            panel_host = urllib.parse.urlparse(src.get("base_url", "")).hostname or ""
            src_id = src.get("id")
            existing_tags = reserved_tags - {t for t in source_existing_tags.get(src_id, set()) if t}
            seen_tags = set()
            deduped = []
            for n in new_nodes:
                n["source"] = src["id"]
                n["source_type"] = "3xui"
                _node_set_defaults(n)
                _recompute_node_health(n)
                if n.get("server") in ("127.0.0.1", "0.0.0.0", "localhost", "::1", "") and panel_host:
                    n["server"] = panel_host
                tag = n.get("tag")
                if not tag or tag in seen_tags or tag in existing_tags:
                    continue
                seen_tags.add(tag)
                deduped.append(n)
            synced[src["id"]] = deduped
            reserved_tags.update(seen_tags)
            total += len(deduped)
        except Exception as e:
            err = str(e)
            errors.append(f"{src['name']}: {err}")
            sync_failures[src.get("id")] = err
    with _state_lock:
        s = read_state()
        now = int(time.time())
        for sid, new_nodes in synced.items():
            s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid] + new_nodes
        for x in s.get("xui_sources", []):
            if x.get("id") in synced:
                x["last_sync"] = now
                x["last_error"] = ""
            elif x.get("id") in sync_failures:
                x["last_error"] = sync_failures[x.get("id")]
        s["last_sync"] = now
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("sync_all", f"total={total} errors={len(errors)} runtime={runtime}")
    return {"ok": True, "total": total, "errors": errors, "runtime": runtime}


# ── Nodes: manual / import / toggle / test ──

@app.get("/api/nodes")
def api_nodes():
    s = read_state()
    nodes = [dict(n) for n in s.get("nodes", [])]
    for n in nodes:
        _node_set_defaults(n)
        _recompute_node_health(n)
        n.setdefault("source_type", "unknown")
    nodes.sort(key=_node_sort_key)
    return nodes

@app.post("/api/nodes/manual")
def api_node_manual(node: ManualNode):
    with _state_lock:
        s = read_state()
        for n in s.get("nodes", []):
            if n["tag"] == node.tag:
                raise HTTPException(400, f"tag '{node.tag}' already exists")
        entry = {k: v for k, v in node.model_dump().items() if v is not None}
        entry["source"] = "manual"
        entry["source_type"] = "manual"
        _node_set_defaults(entry)
        _recompute_node_health(entry)
        s.setdefault("nodes", []).append(entry)
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("node_manual", f"{node.tag} runtime={runtime}")
    return {"ok": True, "tag": node.tag, "runtime": runtime}

@app.post("/api/nodes/import-link/preview")
def api_node_import_preview(req: LinkImport):
    parsed = _parse_links(req.links)
    return {"nodes": parsed, "count": len(parsed)}


@app.post("/api/nodes/import-link")
def api_node_import_link(req: LinkImport):
    parsed = _parse_links(req.links)
    if not parsed:
        raise HTTPException(400, "no valid links found")
    with _state_lock:
        s = read_state()
        existing_tags = {n["tag"] for n in s.get("nodes", [])}
        existing_endpoints = {
            (n.get("server", ""), n.get("server_port", 0))
            for n in s.get("nodes", [])
            if n.get("server")
        }
        added = 0
        skipped = 0
        for n in parsed:
            ep = (n.get("server", ""), n.get("server_port", 0))
            if ep[0] and ep in existing_endpoints:
                skipped += 1
                continue
            if n["tag"] in existing_tags:
                n["tag"] = n["tag"] + "-" + _gen_id()[:4]
            n["source"] = "link"
            n["source_type"] = "link"
            _node_set_defaults(n)
            _recompute_node_health(n)
            s["nodes"].append(n)
            existing_tags.add(n["tag"])
            if ep[0]:
                existing_endpoints.add(ep)
            added += 1
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("link_import", f"added={added} skipped={skipped} runtime={runtime}")
    return {"ok": True, "added": added, "skipped": skipped, "runtime": runtime}

@app.put("/api/nodes/{tag}")
def api_node_update(tag: str, node: ManualNode):
    updated_tag: Optional[str] = None
    with _state_lock:
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
                _node_set_defaults(entry)
                _recompute_node_health(entry)
                s["nodes"][i] = entry
                write_state(s)
                updated_tag = entry["tag"]
                break
        else:
            raise HTTPException(404, "node not found")

    runtime = _runtime_hot_apply(allow_restart=False)
    audit("node_edit", f"{tag} -> {updated_tag} runtime={runtime}")
    return {"ok": True, "tag": updated_tag, "runtime": runtime}

@app.delete("/api/nodes/{tag}")
def api_node_delete(tag: str):
    with _state_lock:
        s = read_state()
        before = len(s.get("nodes", []))
        s["nodes"] = [n for n in s["nodes"] if n["tag"] != tag]
        if len(s["nodes"]) == before:
            raise HTTPException(404, "node not found")
        for d in s.get("devices", []):
            if d.get("node_tag") == tag:
                d["node_tag"] = None
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("node_del", f"{tag} runtime={runtime}")
    return {"ok": True, "runtime": runtime}

@app.post("/api/nodes/batch")
def api_node_batch(req: NodeBatchAction):
    if req.action not in ("delete", "enable", "disable"):
        raise HTTPException(400, "action must be delete, enable, or disable")
    tags_set = set(req.tags)
    if not tags_set:
        raise HTTPException(400, "no tags provided")
    affected = 0
    with _state_lock:
        s = read_state()
        if req.action == "delete":
            before = len(s.get("nodes", []))
            s["nodes"] = [n for n in s["nodes"] if n["tag"] not in tags_set]
            affected = before - len(s["nodes"])
            for d in s.get("devices", []):
                if d.get("node_tag") in tags_set:
                    d["node_tag"] = None
        else:
            target_enabled = req.action == "enable"
            for n in s.get("nodes", []):
                if n["tag"] in tags_set:
                    n["enabled"] = target_enabled
                    _recompute_node_health(n)
                    affected += 1
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("node_batch", f"action={req.action} count={affected} runtime={runtime}")
    return {"ok": True, "action": req.action, "affected": affected, "runtime": runtime}

@app.put("/api/nodes/{tag}/toggle")
def api_node_toggle(tag: str):
    with _state_lock:
        s = read_state()
        for n in s.get("nodes", []):
            if n["tag"] == tag:
                n["enabled"] = not n.get("enabled", True)
                _recompute_node_health(n)
                write_state(s)
                enabled_now = n["enabled"]
                break
        else:
            raise HTTPException(404, "node not found")
    runtime = _runtime_hot_apply(allow_restart=False)
    return {"ok": True, "enabled": enabled_now, "runtime": runtime}

@app.post("/api/nodes/{tag}/test")
def api_node_test(tag: str):
    s = read_state()
    node = next((n for n in s.get("nodes", []) if n["tag"] == tag), None)
    if not node:
        raise HTTPException(404, "node not found")
    server = node.get("server", "")
    port = node.get("server_port", 443)
    if not server or server in ("127.0.0.1", "0.0.0.0"):
        with _state_lock:
            s = read_state()
            for n in s.get("nodes", []):
                if n["tag"] == tag:
                    n["latency"] = -1
                    _mark_node_probe(n, False, "invalid node server")
                    break
            write_state(s)
        return {"ok": True, "tag": tag, "latency": -1}
    latency = _clash_proxy_delay_ms(tag, timeout_ms=5000)
    if latency < 0:
        try:
            t0 = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
                sk.settimeout(5)
                sk.connect((server, port))
            latency = int((time.time() - t0) * 1000)
        except Exception:
            latency = -1
    with _state_lock:
        s = read_state()
        health_score = 0
        health_status = "unknown"
        for n in s.get("nodes", []):
            if n["tag"] == tag:
                n["latency"] = latency
                _mark_node_probe(n, latency >= 0, "tcp connect failed" if latency < 0 else "")
                health_score = _node_health_score_value(n)
                health_status = n.get("health_status", "unknown")
        write_state(s)
    return {"ok": True, "tag": tag, "latency": latency, "health_score": health_score, "health_status": health_status}


@app.post("/api/nodes/{tag}/speedtest")
def api_node_speedtest(tag: str):
    s = read_state()
    node = next((n for n in s.get("nodes", []) if n["tag"] == tag), None)
    if not node:
        raise HTTPException(404, "node not found")
    server = node.get("server", "")
    port = node.get("server_port", 443)
    if not server or server in ("127.0.0.1", "0.0.0.0"):
        with _state_lock:
            s = read_state()
            for n in s.get("nodes", []):
                if n["tag"] == tag:
                    n["latency"] = -1
                    n["speed_mbps"] = 0.0
                    _mark_node_probe(n, False, "invalid node server")
                    break
            write_state(s)
        return {"ok": True, "tag": tag, "latency_ms": -1, "speed_mbps": 0, "message": "invalid node server"}

    latency = _clash_proxy_delay_ms(tag)
    if latency < 0:
        try:
            t0 = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
                sk.settimeout(5)
                sk.connect((server, port))
            latency = int((time.time() - t0) * 1000)
        except Exception:
            latency = -1

    speed_mbps, speed_note = _measure_speed_via_selector(tag)

    with _state_lock:
        s = read_state()
        health_score = 0
        health_status = "unknown"
        for n in s.get("nodes", []):
            if n["tag"] == tag:
                n["latency"] = latency
                n["speed_mbps"] = speed_mbps
                _mark_node_probe(n, latency >= 0, speed_note if latency < 0 else "")
                health_score = _node_health_score_value(n)
                health_status = n.get("health_status", "unknown")
        write_state(s)
    audit("node_speedtest", f"{tag} latency={latency}ms speed={speed_mbps}Mbps note={speed_note}")
    return {
        "ok": True,
        "tag": tag,
        "latency_ms": latency,
        "speed_mbps": speed_mbps,
        "health_score": health_score,
        "health_status": health_status,
        "message": speed_note,
    }


@app.post("/api/nodes/health/refresh")
def api_nodes_health_refresh(limit: int = 20):
    limit = max(1, min(200, int(limit or 20)))
    with _state_lock:
        s = read_state()
        nodes = [dict(n) for n in s.get("nodes", []) if n.get("enabled", True)]

    probe_nodes = []
    for n in nodes:
        tag = n.get("tag")
        server = n.get("server", "")
        if not tag or not server or server in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
            continue
        _recompute_node_health(n)
        probe_nodes.append(n)

    probe_nodes.sort(key=_node_sort_key)
    probe_nodes = probe_nodes[:limit]

    def _probe_one(n):
        tag = str(n.get("tag", ""))
        latency = _clash_proxy_delay_ms(tag, timeout_ms=2500)
        return (tag, latency)

    # Probe nodes in parallel (up to 10 concurrent workers)
    max_workers = min(10, len(probe_nodes)) if probe_nodes else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        probe_results = list(pool.map(_probe_one, probe_nodes))

    checked = 0
    ok_count = 0
    fail_count = 0
    with _state_lock:
        s = read_state()
        node_map = {n.get("tag"): n for n in s.get("nodes", [])}
        for tag, latency in probe_results:
            n = node_map.get(tag)
            if not n:
                continue
            n["latency"] = latency
            _mark_node_probe(n, latency >= 0, "delay probe failed" if latency < 0 else "")
            checked += 1
            if latency >= 0:
                ok_count += 1
            else:
                fail_count += 1
        write_state(s)
        enabled_now = bool(s.get("enabled", False))

    runtime = _runtime_hot_apply(allow_restart=False) if (checked > 0 and enabled_now) else _empty_runtime_results()
    audit("node_health_refresh", f"checked={checked} ok={ok_count} fail={fail_count} runtime={runtime}", component="probe")
    return {
        "ok": True,
        "checked": checked,
        "healthy": ok_count,
        "unhealthy": fail_count,
        "runtime": runtime,
    }


# ── Subscriptions ──

@app.get("/api/subscriptions")
def api_subs():
    s = read_state()
    out = []
    for sub in s.get("subscriptions", []):
        safe = dict(sub)
        safe.setdefault("last_sync", 0)
        safe["node_count"] = sum(1 for n in s.get("nodes", []) if n.get("source") == sub["id"])
        out.append(safe)
    return out

@app.post("/api/subscriptions")
def api_sub_create(req: SubCreate):
    with _state_lock:
        s = read_state()
        sub = {"id": _gen_id(), "name": req.name, "url": req.url, "last_sync": 0}
        if req.headers:
            sub["headers"] = req.headers
        s.setdefault("subscriptions", []).append(sub)
        write_state(s)
    audit("sub_add", req.name)
    return {"ok": True, "id": sub["id"]}

@app.put("/api/subscriptions/{sid}")
def api_sub_update(sid: str, req: SubCreate):
    with _state_lock:
        s = read_state()
        sub = next((x for x in s.get("subscriptions", []) if x["id"] == sid), None)
        if not sub:
            raise HTTPException(404, "subscription not found")
        sub["name"] = req.name
        sub["url"] = req.url
        sub["headers"] = req.headers or {}
        write_state(s)
    audit("sub_update", f"{sid} name={req.name}")
    return {"ok": True}

@app.delete("/api/subscriptions/{sid}")
def api_sub_delete(sid: str):
    with _state_lock:
        s = read_state()
        s["subscriptions"] = [x for x in s.get("subscriptions", []) if x["id"] != sid]
        s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid]
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("sub_del", f"{sid} runtime={runtime}")
    return {"ok": True, "runtime": runtime}

@app.post("/api/subscriptions/{sid}/sync")
def api_sub_sync(sid: str):
    with _state_lock:
        s = read_state()
        sub = next((x for x in s.get("subscriptions", []) if x["id"] == sid), None)
        if not sub:
            raise HTTPException(404, "subscription not found")
        sub_url = sub["url"]
        sub_name = sub["name"]
        sub_headers = sub.get("headers") or {}
    try:
        # Validate URL to prevent SSRF attacks against internal networks
        _validate_url_safe(sub_url)
        fetch_headers = {"User-Agent": "MACFlow/2.0"}
        fetch_headers.update(sub_headers)
        _MAX_SUB_SIZE = 10 * 1024 * 1024  # 10MB
        resp = requests.get(sub_url, headers=fetch_headers, timeout=20, stream=True)
        resp.raise_for_status()
        content_len = int(resp.headers.get("content-length", 0) or 0)
        if content_len > _MAX_SUB_SIZE:
            raise ValueError(f"Subscription too large: {content_len} bytes")
        chunks = []
        total = 0
        for chunk in resp.iter_content(65536):
            total += len(chunk)
            if total > _MAX_SUB_SIZE:
                raise ValueError("Subscription response exceeded 10MB limit")
            chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"fetch failed: {e}")
    parsed = _parse_subscription(text)
    if not parsed:
        raise HTTPException(400, "no nodes parsed from subscription")
    for n in parsed:
        n["source"] = sid
        n["source_type"] = "subscription"
        _node_set_defaults(n)
        _recompute_node_health(n)
    with _state_lock:
        s = read_state()
        s["nodes"] = [n for n in s.get("nodes", []) if n.get("source") != sid] + parsed
        for x in s.get("subscriptions", []):
            if x["id"] == sid:
                x["last_sync"] = int(time.time())
        s["last_sync"] = int(time.time())
        write_state(s)
    runtime = _runtime_hot_apply(allow_restart=False)
    audit("sub_sync", f"{sub_name} count={len(parsed)} runtime={runtime}")
    return {"ok": True, "count": len(parsed), "runtime": runtime}


# ── Devices (direct node binding, per-row apply) ──

@app.get("/api/devices")
def api_devices():
    s = read_state()
    node_map = {n["tag"]: n for n in s.get("nodes", [])}
    mac_to_ip = _resolve_mac_to_ip()
    out: List[Dict[str, Any]] = []
    for d in s.get("devices", []):
        item = dict(d)
        tag = item.get("node_tag")
        item["node_detail"] = _safe_node_summary(node_map.get(tag)) if tag and tag != "direct" else None
        rip, src = _resolve_device_ipv4(item, mac_to_ip)
        item["resolved_ip"] = rip or None
        item["ip_source"] = src
        out.append(item)
    return out

@app.post("/api/devices")
def api_device_upsert(item: DeviceCreate):
    fixed_ip = _normalize_ipv4(item.ip)
    with _state_lock:
        s = read_state()
        devs = s.get("devices", [])
        found = False
        for i, d in enumerate(devs):
            if d["mac"].upper() == item.mac.upper():
                devs[i].update({"name": item.name, "node_tag": item.node_tag, "managed": item.managed})
                if item.remark is not None:
                    devs[i]["remark"] = item.remark
                if item.ip is not None:
                    devs[i]["ip"] = fixed_ip
                found = True
                break
        if not found:
            devs.append({"name": item.name, "mac": item.mac.upper(), "node_tag": item.node_tag,
                          "managed": item.managed, "mark": _next_mark(s), "remark": item.remark or "",
                          "ip": fixed_ip if item.ip is not None else "", "last_ip": ""})
        s["devices"] = devs
        write_state(s)

    runtime = _runtime_hot_apply(allow_restart=False)

    audit("device_upsert", f"{item.mac} -> {item.node_tag} runtime={runtime}")
    return {"ok": True, "runtime": runtime}

@app.post("/api/devices/batch")
def api_device_batch(req: DeviceBatch):
    with _state_lock:
        s = read_state()
        devs = s.get("devices", [])
        idx = {d["mac"].upper(): i for i, d in enumerate(devs)}
        count = 0
        for item in req.devices:
            mac = item.mac.upper()
            fixed_ip = _normalize_ipv4(item.ip)
            if mac in idx:
                devs[idx[mac]].update({"name": item.name, "node_tag": item.node_tag, "managed": item.managed})
                if item.remark is not None:
                    devs[idx[mac]]["remark"] = item.remark
                if item.ip is not None:
                    devs[idx[mac]]["ip"] = fixed_ip
            else:
                devs.append({"name": item.name, "mac": mac, "node_tag": item.node_tag,
                              "managed": item.managed, "mark": _next_mark(s), "remark": item.remark or "",
                              "ip": fixed_ip if item.ip is not None else "", "last_ip": ""})
                idx[mac] = len(devs) - 1
            count += 1
        s["devices"] = devs
        write_state(s)

    runtime = _runtime_hot_apply(allow_restart=False)

    audit("device_batch", f"count={count} runtime={runtime}")
    return {"ok": True, "count": count, "runtime": runtime}

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
                break
        else:
            raise HTTPException(404, "device not found")

    runtime = _runtime_hot_apply(allow_restart=False)

    audit("device_apply", f"{mac} -> {req.node_tag} runtime={runtime}")
    return {"ok": True, "mac": mac, "node_tag": req.node_tag,
            "applied": True, "runtime": runtime}

@app.put("/api/devices/{mac}/remark")
def api_device_remark(mac: str, req: DeviceRemarkUpdate):
    with _state_lock:
        s = read_state()
        for d in s.get("devices", []):
            if d["mac"].upper() == mac.upper():
                d["remark"] = req.remark
                write_state(s)
                audit("device_remark", f"{mac}: {req.remark}")
                return {"ok": True}
    raise HTTPException(404, "device not found")


@app.put("/api/devices/{mac}/ip")
def api_device_ip(mac: str, req: DeviceIpUpdate):
    fixed_ip = _normalize_ipv4(req.ip)
    with _state_lock:
        s = read_state()
        target = None
        for d in s.get("devices", []):
            if d["mac"].upper() == mac.upper():
                target = d
                break
        if target is None:
            raise HTTPException(404, "device not found")
        # IP conflict detection
        if fixed_ip:
            for d in s.get("devices", []):
                if d["mac"].upper() != mac.upper() and _normalize_ipv4(d.get("ip")) == fixed_ip:
                    raise HTTPException(
                        409,
                        f"IP {fixed_ip} already assigned to {d.get('name', d['mac'])}",
                    )
        target["ip"] = fixed_ip
        write_state(s)

    runtime = _runtime_hot_apply(allow_restart=False)
    audit("device_ip", f"{mac} ip={fixed_ip or '-'} runtime={runtime}")
    return {"ok": True, "mac": mac.upper(), "ip": fixed_ip or None, "runtime": runtime}

@app.delete("/api/devices/{mac}")
def api_device_delete(mac: str):
    with _state_lock:
        s = read_state()
        before = len(s.get("devices", []))
        s["devices"] = [d for d in s["devices"] if d["mac"].upper() != mac.upper()]
        removed = before - len(s["devices"])
        write_state(s)

    runtime = _runtime_hot_apply(allow_restart=False)

    audit("device_del", f"{mac} removed={removed} runtime={runtime}")
    return {"ok": True, "deleted": removed, "runtime": runtime}


# ── System info ──

_BOOT_TIME = time.time()

@app.get("/api/system/info")
def api_system_info():
    uptime_sec = int(time.time() - _BOOT_TIME)
    h, rem = divmod(uptime_sec, 3600)
    m, s2 = divmod(rem, 60)
    try:
        mem = _resource_mod.getrusage(_resource_mod.RUSAGE_SELF).ru_maxrss if _resource_mod else 0
        mem_mb = round(mem / 1024, 1) if mem else 0
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
def api_update_apply(request: Request):
    """Download and apply updates with SHA-256 integrity verification."""
    # Fetch checksums manifest first
    checksums: Dict[str, str] = {}
    try:
        cs_r = requests.get(f"{_GITHUB_RAW}/checksums.sha256", timeout=15)
        if cs_r.status_code == 200:
            for line in cs_r.text.strip().splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    checksums[parts[1].strip()] = parts[0].strip().lower()
    except Exception:
        pass

    errors = []
    updated = []
    integrity_failures = []
    for fpath in _UPDATE_FILES:
        try:
            target = (ROOT / fpath).resolve()
            # Path traversal protection
            if not str(target).startswith(str(ROOT.resolve())):
                errors.append(f"{fpath}: path traversal blocked")
                continue
            r = requests.get(f"{_GITHUB_RAW}/{fpath}", timeout=15)
            if r.status_code == 200:
                # Verify SHA-256 integrity if checksums available
                content_hash = hashlib.sha256(r.content).hexdigest().lower()
                expected_hash = checksums.get(fpath, "")
                if checksums and expected_hash:
                    if content_hash != expected_hash:
                        integrity_failures.append(f"{fpath}: SHA-256 mismatch (got {content_hash[:16]}..., expected {expected_hash[:16]}...)")
                        continue
                elif checksums and not expected_hash:
                    # Checksums file exists but this file is not listed — warn but allow
                    pass
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(r.content)
                updated.append(fpath)
            else:
                errors.append(f"{fpath}: HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"{fpath}: {e}")

    if integrity_failures:
        errors.extend(integrity_failures)
        audit("cloud_update_integrity_fail", f"integrity_failures={integrity_failures}", level="error", component="update")

    need_restart = "backend/main.py" in updated
    audit("cloud_update", f"updated={updated} errors={errors}", component="update")

    if need_restart:
        try:
            my_pid = os.getpid()
            # Try procd service restart first, fall back to PID-based restart
            subprocess.Popen(
                ["sh", "-c", f"sleep 2 && (if [ -x /etc/init.d/macflow ]; then /etc/init.d/macflow restart; else kill {my_pid}; sleep 1; cd /opt/macflow && python3 -m uvicorn backend.main:app --host 0.0.0.0 --port {_LISTEN_PORT} > /var/log/macflow.log 2>&1 & fi)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    return {"ok": True, "updated": updated, "errors": errors, "integrity_failures": integrity_failures, "restart_scheduled": need_restart}


# ── Traffic stats (sing-box Clash API) ──

_CLASH_API = os.environ.get("MACFLOW_CLASH_API", "http://127.0.0.1:9090")
_last_traffic: Dict[str, Any] = {"up": 0, "down": 0, "ts": 0}
_traffic_lock = threading.Lock()

def _poll_traffic_once() -> Dict:
    try:
        r = requests.get(f"{_CLASH_API}/traffic", stream=True, timeout=3)
        try:
            for line in r.iter_lines():
                if line:
                    data = json.loads(line)
                    with _traffic_lock:
                        _last_traffic["up"] = data.get("up", 0)
                        _last_traffic["down"] = data.get("down", 0)
                        _last_traffic["ts"] = int(time.time())
                        return dict(_last_traffic)
        finally:
            r.close()
    except Exception:
        pass
    with _traffic_lock:
        return dict(_last_traffic)


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


# ── SSE (Server-Sent Events) real-time stream ──

_sse_clients: list = []  # list of asyncio.Queue
_sse_lock = threading.Lock()
_SSE_PUBLIC = True  # SSE stream is public when auth is disabled
_SSE_MAX_CLIENTS = 50  # Maximum concurrent SSE connections


def _sse_broadcast(event_type: str, data: dict):
    """Broadcast an event to all connected SSE clients."""
    payload = f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    with _sse_lock:
        stale = []
        for i, q in enumerate(_sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                stale.append(i)
        for i in reversed(stale):
            try:
                _sse_clients.pop(i)
            except IndexError:
                pass


def _sse_traffic_loop():
    """Background thread: push traffic+status updates every 2s."""
    while True:
        time.sleep(2)
        if not _sse_clients:
            continue
        try:
            # Traffic data
            tdata = _poll_traffic_once()
            _sse_broadcast("traffic", {
                "up_bytes": tdata["up"],
                "down_bytes": tdata["down"],
                "up_str": _fmt_bytes(tdata["up"]) + "/s",
                "down_str": _fmt_bytes(tdata["down"]) + "/s",
                "ts": tdata["ts"],
            })
            # Connections
            try:
                r = requests.get(f"{_CLASH_API}/connections", timeout=1)
                if r.status_code == 200:
                    cdata = r.json()
                    conns = cdata.get("connections") or []
                    _sse_broadcast("connections", {
                        "count": len(conns),
                        "upload_total": cdata.get("uploadTotal", 0),
                        "download_total": cdata.get("downloadTotal", 0),
                    })
            except Exception:
                pass
            # Status (use cached state from state_lock to reduce disk I/O)
            with _state_lock:
                s = read_state()
            nodes = s.get("nodes", [])
            devs = s.get("devices", [])
            with _health_lock:
                active_alerts = [a for a in _health_state.get("alerts", []) if a.get("status") == "active"]
                overall_health = _health_state.get("overall_status", "unknown")
                fc_active = _fail_close_guard.get("active", False)
            _sse_broadcast("status", {
                "enabled": s.get("enabled", False),
                "node_count": len(nodes),
                "node_enabled": sum(1 for n in nodes if n.get("enabled", True)),
                "device_count": len(devs),
                "managed_count": sum(1 for d in devs if d.get("managed")),
                "policy_version": s.get("policy_version"),
                "rollback_version": s.get("rollback_version"),
                "last_apply": s.get("last_apply", 0),
                "overall_health": overall_health,
                "active_alert_count": len(active_alerts),
                "fail_close_active": fc_active,
            })
        except Exception:
            pass


def _sse_sysinfo_loop():
    """Background thread: push system info every 10s."""
    while True:
        time.sleep(10)
        if not _sse_clients:
            continue
        try:
            uptime_sec = int(time.time() - _BOOT_TIME)
            h, rem = divmod(uptime_sec, 3600)
            m, s2 = divmod(rem, 60)
            mem_mb = 0
            try:
                if _resource_mod:
                    mem_mb = round(_resource_mod.getrusage(_resource_mod.RUSAGE_SELF).ru_maxrss / 1024, 1)
            except Exception:
                try:
                    with open(f"/proc/{os.getpid()}/status") as f:
                        for line in f:
                            if line.startswith("VmRSS:"):
                                mem_mb = round(int(line.split()[1]) / 1024, 1)
                                break
                except Exception:
                    pass
            _sse_broadcast("sysinfo", {
                "uptime_sec": uptime_sec,
                "uptime_str": f"{h}h {m}m {s2}s",
                "memory_mb": mem_mb,
                "pid": os.getpid(),
            })
        except Exception:
            pass


def _start_sse_loops():
    t1 = threading.Thread(target=_sse_traffic_loop, daemon=True, name="sse-traffic")
    t1.start()
    t2 = threading.Thread(target=_sse_sysinfo_loop, daemon=True, name="sse-sysinfo")
    t2.start()


@app.get("/api/events")
async def api_sse_events(request: Request):
    """SSE endpoint for real-time data streaming."""
    # Auth check for SSE
    auth = _load_auth()
    if auth.get("auth_enabled"):
        token = request.query_params.get("token", "")
        if not token:
            token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.cookies.get("macflow_token", "")
        if not _validate_session(token):
            return JSONResponse(status_code=401, content={"detail": "认证失败"})

    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    with _sse_lock:
        if len(_sse_clients) >= _SSE_MAX_CLIENTS:
            return JSONResponse(status_code=503, content={"detail": "SSE 连接数已满"})
        _sse_clients.append(q)

    async def event_generator():
        # Send initial heartbeat
        yield "event: connected\ndata: {}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30)
                    yield msg
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/logs/clear")
def api_logs_clear():
    if LOG_FILE.exists():
        LOG_FILE.write_text("", "utf-8")
    audit("logs_clear", "all logs cleared")
    return {"ok": True}


# ── DHCP discover ──

@app.get("/api/dhcp/discover")
def api_dhcp():
    seen_macs: Dict[str, Dict[str, Any]] = {}  # MAC -> lease info (dedup)
    # Collect from all DHCP lease sources
    for p in ("/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"):
        fp = pathlib.Path(p)
        if fp.exists():
            try:
                for line in fp.read_text(errors="ignore").splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1].upper()
                        if mac not in seen_macs:
                            seen_macs[mac] = {"mac": mac, "ip": parts[2], "hostname": parts[3]}
            except Exception:
                pass
    # odhcpd leases (OpenWrt with odhcpd)
    try:
        odhcpd_dir = pathlib.Path("/tmp/hosts/odhcpd")
        if odhcpd_dir.is_dir():
            for fp in odhcpd_dir.iterdir():
                try:
                    for line in fp.read_text(errors="ignore").splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[1].upper()
                            if mac not in seen_macs:
                                hostname = parts[2] if len(parts) >= 3 else "-"
                                seen_macs[mac] = {"mac": mac, "ip": parts[0], "hostname": hostname}
                except Exception:
                    pass
    except Exception:
        pass
    # ARP table for devices not in DHCP leases
    arp_map = _resolve_mac_to_ip()
    for mac, ip in arp_map.items():
        umac = mac.upper()
        if umac not in seen_macs:
            seen_macs[umac] = {"mac": umac, "ip": ip, "hostname": "-"}
    leases = list(seen_macs.values())
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
    with _apply_lock:
        with _state_lock:
            s = read_state()
            if not s.get("enabled", False):
                raise HTTPException(400, "service is disabled, enable it first")
            version = time.strftime("v%Y%m%d%H%M%S")
            s["rollback_version"] = s.get("policy_version")
            s["policy_version"] = version
            s["last_apply"] = int(time.time())
            managed = [d for d in s.get("devices", []) if d.get("managed")]
            write_state(s)
        results = _reconcile_runtime(_guarded_runtime_state(s), allow_restart=True)
        if _fail_close_guard.get("active"):
            results["fail_close_guard"] = "active"

    audit("apply", f"version={version} devices={len(managed)} results={results}",
          level="info", component="apply")
    return {"ok": True, "policy_version": version, "affected": len(managed), "results": results}

@app.post("/api/rollback")
def api_rollback():
    with _apply_lock:
        with _state_lock:
            s = read_state()
            rv = s.get("rollback_version")
            if not rv:
                raise HTTPException(400, "no rollback version")
            s["policy_version"] = rv
            s["rollback_version"] = None
            s["last_apply"] = int(time.time())
            write_state(s)
        # Re-apply runtime so nftables/sing-box/ip-rules reflect the rollback
        results = _reconcile_runtime(_guarded_runtime_state(s), allow_restart=True)
    audit("rollback", f"to={rv} results={results}")
    return {"ok": True, "restored": rv, "results": results}


# ── Logs ──

@app.get("/api/logs")
def api_logs(lines: int = 100, level: str = "", component: str = "", event: str = ""):
    lines = max(1, min(lines, 5000))  # cap to prevent excessive memory use
    if not LOG_FILE.exists():
        return []
    has_filter = bool(level or component or event)
    # When no filters are applied, use efficient tail reading
    if not has_filter:
        try:
            with open(LOG_FILE, "rb") as f:
                f.seek(0, 2)  # seek to end
                file_size = f.tell()
                # Read last chunk (estimate ~200 bytes per line)
                chunk_size = min(file_size, lines * 250 + 4096)
                f.seek(max(0, file_size - chunk_size))
                tail_data = f.read().decode("utf-8", errors="replace")
            tail_lines = tail_data.strip().splitlines()
            # Take only the last N lines
            tail_lines = tail_lines[-lines:]
            entries = []
            for line in tail_lines:
                try:
                    entries.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    entries.append({"ts": "", "level": "info", "component": "system", "event": "legacy", "message": line})
            return entries
        except Exception:
            pass  # fall through to full read
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


def _build_singbox_full(state: Dict) -> Dict:
    nodes = [dict(n) for n in state.get("nodes", []) if n.get("enabled", True)]
    for n in nodes:
        _recompute_node_health(n)
    nodes.sort(key=_node_sort_key)

    dns_cfg = state.get("dns", {})
    dns_port = int(dns_cfg.get("enforce_redirect_port", 6053))
    dns_servers_ips = dns_cfg.get("servers", ["8.8.8.8", "1.1.1.1"])

    outbounds = []
    outbound_tags = []
    selector_candidates = []
    seen_tags = set()
    for n in nodes:
        ob = _node_to_outbound(n)
        if ob:
            tag = ob.get("tag")
            if not tag or tag in seen_tags:
                continue
            seen_tags.add(tag)
            outbounds.append(ob)
            outbound_tags.append(tag)
            if _node_selector_healthy(n):
                selector_candidates.append(tag)

    if not selector_candidates:
        selector_candidates = list(outbound_tags)

    selector_tags = list(selector_candidates) + ["direct-out"]
    outbounds.append({"type": "selector", "tag": "proxy-select",
                      "outbounds": selector_tags,
                      "default": selector_candidates[0] if selector_candidates else "direct-out",
                      "interrupt_exist_connections": False})
    outbounds.append({"type": "direct", "tag": "direct-out"})

    dns_servers = []
    for ip in dns_servers_ips:
        dns_servers.append({"tag": f"dns-{ip}", "type": "udp", "server": ip, "server_port": 53,
                            "detour": "proxy-select"})
    dns_servers.append({"tag": "local-dns", "type": "local", "detour": "direct-out"})
    # Default remote DNS server for proxied queries
    default_dns_tag = f"dns-{dns_servers_ips[0]}" if dns_servers_ips else "local-dns"

    enabled_outbound_tags = set(outbound_tags)
    mac_to_ip = _resolve_mac_to_ip()
    device_rules = []
    for d in state.get("devices", []):
        if not d.get("managed") or not d.get("node_tag"):
            continue
        tag = d["node_tag"]
        ip, _ = _resolve_device_ipv4(d, mac_to_ip)
        if not ip:
            continue
        if tag == "direct":
            device_rules.append({"source_ip_cidr": [f"{ip}/32"], "outbound": "direct-out"})
        elif tag in enabled_outbound_tags:
            device_rules.append({"source_ip_cidr": [f"{ip}/32"], "outbound": tag})
        else:
            device_rules.append({"source_ip_cidr": [f"{ip}/32"], "outbound": "proxy-select"})

    route_rules: List[Dict] = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    route_rules.extend(device_rules)

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": dns_servers,
            "rules": [
                {"outbound": "any", "server": "local-dns"},
                {"clash_mode": "Direct", "server": "local-dns"},
            ],
            "final": default_dns_tag,
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "singtun0",
             "address": ["172.19.0.1/30"], "auto_route": False,
             "stack": "gvisor", "sniff": True, "sniff_override_destination": True},
            {"type": "direct", "tag": "dns-in", "listen": "0.0.0.0", "listen_port": dns_port},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 1080},
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": route_rules,
            "final": "proxy-select",
            "default_mark": 255,
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "", "secret": ""},
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
        aid = int(node.get("alter_id", 0) or 0)
        if aid > 0:
            ob["alter_id"] = aid
    elif t == "vless":
        ob["uuid"] = node.get("uuid", "")
        flow = node.get("flow", "")
        if flow:
            ob["flow"] = flow
    elif t == "trojan":
        ob["password"] = node.get("password", "")
    elif t == "hysteria2":
        ob["password"] = node.get("password", "")
        # hysteria2 requires TLS — provide default if node has none
        if not node.get("tls"):
            ob["tls"] = {"enabled": True, "server_name": server, "insecure": True}
        obfs = node.get("obfs")
        if obfs and isinstance(obfs, dict) and obfs.get("type"):
            ob["obfs"] = obfs
    elif t == "tuic":
        ob["uuid"] = node.get("uuid", "")
        ob["password"] = node.get("password", "")
        # tuic requires TLS — provide default if node has none
        if not node.get("tls"):
            ob["tls"] = {"enabled": True, "server_name": server, "insecure": True}
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
        # Respect per-node TLS insecure setting; default True for compatibility
        ob["tls"]["insecure"] = tls.get("insecure", True)

    return ob


SINGBOX_CONFIG_PATH = pathlib.Path(os.environ.get("MACFLOW_SINGBOX_CONFIG", "/etc/sing-box/config.json"))
NFT_TABLE = "inet macflow"
_SINGBOX_SERVICE_NAMES = ["sing-box", "sing-box-macflow"]


def _is_singbox_running() -> bool:
    proc_dir = pathlib.Path("/proc")
    if proc_dir.exists():
        try:
            for p in proc_dir.iterdir():
                if not p.name.isdigit():
                    continue
                try:
                    comm = (p / "comm").read_text("utf-8", errors="ignore").strip()
                    if comm == "sing-box":
                        return True
                except Exception:
                    continue
        except Exception:
            pass

    checks = [
        ["pidof", "sing-box"],
        ["pgrep", "-x", "sing-box"],
    ]
    for cmd in checks:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=3, text=True)
            if r.returncode == 0 and r.stdout.strip():
                return True
        except Exception:
            continue
    return False


def _try_singbox_service_actions(actions: List[str], timeout: int = 15) -> tuple:
    details: List[str] = []
    for service_name in _SINGBOX_SERVICE_NAMES:
        for action in actions:
            try:
                r = subprocess.run(["service", service_name, action], capture_output=True, timeout=timeout)
                err = (r.stderr or b"").decode("utf-8", errors="ignore").strip()
                if r.returncode == 0:
                    time.sleep(1)
                    if _is_singbox_running():
                        return True, f"{service_name}:{action}"
                    details.append(f"{service_name}:{action}:ok but not running")
                else:
                    details.append(f"{service_name}:{action}:rc={r.returncode} {err}")
            except Exception as e:
                details.append(f"{service_name}:{action}:exception={e}")
    return False, "; ".join(details)


def _apply_singbox_runtime_config(config: Dict[str, Any], allow_restart: bool = False) -> str:
    try:
        SINGBOX_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SINGBOX_CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), "utf-8")
    except Exception as e:
        return f"write error: {e}"

    reloaded, reload_detail = _try_singbox_service_actions(["reload"], timeout=10)
    if reloaded:
        return "reloaded"
    reload_err = reload_detail or "reload failed"

    if not allow_restart:
        return f"reload failed: {reload_err}"

    restarted, restart_detail = _try_singbox_service_actions(["restart", "start"], timeout=15)
    if restarted:
        return "restarted"

    try:
        _singbox_bin = shutil.which("sing-box") or "/usr/bin/sing-box"
        subprocess.Popen([_singbox_bin, "run", "-c", str(SINGBOX_CONFIG_PATH)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if _is_singbox_running():
            return "started(manual)"
    except Exception as e:
        return f"restart failed after reload error: {reload_err}; {restart_detail}; manual start exception: {e}"
    return f"restart failed after reload error: {reload_err}; {restart_detail}"


def _empty_runtime_results() -> Dict[str, str]:
    return {
        "singbox_config": "skipped",
        "nftables": "skipped",
        "singbox_reload": "skipped",
        "ip_rules": "skipped",
    }


def _reconcile_runtime(state: Dict[str, Any], allow_restart: bool = False) -> Dict[str, str]:
    results = _empty_runtime_results()
    if not state.get("enabled", False):
        return results

    config: Optional[Dict[str, Any]] = None
    try:
        config = _build_singbox_full(state)
        results["singbox_config"] = "rendered"
    except Exception as e:
        results["singbox_config"] = f"error: {e}"

    results["nftables"] = _apply_nftables(state)

    if config is not None:
        results["singbox_reload"] = _apply_singbox_runtime_config(config, allow_restart=allow_restart)

    results["ip_rules"] = _apply_ip_rules(state)
    return results


def _runtime_hot_apply(allow_restart: bool = False) -> Dict[str, str]:
    with _apply_lock:
        with _state_lock:
            current = read_state()
            if _refresh_device_ip_cache(current):
                write_state(current)
        if _fail_close_guard.get("active") and not _is_fail_close_applicable(current):
            _set_fail_close_guard(False, "policy no longer applicable", audit_fn=audit)
        target = _guarded_runtime_state(current)
        results = _reconcile_runtime(target, allow_restart=allow_restart)
        if _fail_close_guard.get("active"):
            results["fail_close_guard"] = "active"
        return results


def _apply_nftables(state: Dict) -> str:
    if not state.get("enabled", False):
        return _flush_nftables()

    managed = [d for d in state.get("devices", []) if d.get("managed") and d.get("mark", 0) > 0]
    # Defense-in-depth: validate all MACs before injecting into nft script
    for d in managed:
        if not _MAC_RE.match(d.get("mac", "")):
            return f"nft error: invalid MAC in device: {d.get('mac', '?')}"
    mac_to_ip = _resolve_mac_to_ip()
    unresolved = []
    for d in managed:
        rip, _ = _resolve_device_ipv4(d, mac_to_ip)
        if not rip:
            unresolved.append(d)
    dns_cfg = state.get("dns", {})
    dns_port = dns_cfg.get("enforce_redirect_port", 6053)
    try:
        dns_port = int(dns_port)
    except (TypeError, ValueError):
        dns_port = 6053
    if not (1 <= dns_port <= 65535):
        dns_port = 6053
    dns_servers = dns_cfg.get("servers", ["8.8.8.8", "1.1.1.1"])
    # Validate DNS server IPs before injecting into nft script
    validated_dns = []
    for srv in dns_servers:
        try:
            ipaddress.ip_address(str(srv))
            validated_dns.append(str(srv))
        except ValueError:
            pass  # skip invalid entries
    if not validated_dns:
        validated_dns = ["8.8.8.8", "1.1.1.1"]
    dns_ipv4, dns_ipv6 = _split_ip_versions(validated_dns)
    doh_ipv4 = sorted(set(_COMMON_DOH_IPV4 + dns_ipv4))
    doh_ipv6 = sorted(set(_COMMON_DOH_IPV6 + dns_ipv6))
    default_policy = state.get("default_policy", "whitelist")
    failure_policy = state.get("failure_policy", "fail-close")

    mac_elements = ", ".join(f'{d["mac"]} : 0x{d["mark"]:x}' for d in managed) if managed else "00:00:00:00:00:00 : 0x0"
    managed_macs = ", ".join(d["mac"] for d in managed) if managed else "00:00:00:00:00:00"
    unresolved_macs = ", ".join(d["mac"] for d in unresolved) if unresolved else "00:00:00:00:00:00"
    unresolved_marks = ", ".join(f"0x{d['mark']:x}" for d in unresolved if int(d.get("mark", 0)) > 0) if unresolved else "0x0"
    doh4_elements = ", ".join(doh_ipv4) if doh_ipv4 else "127.0.0.1"
    doh6_elements = ", ".join(doh_ipv6) if doh_ipv6 else "::1"

    policy_rules = ""
    if default_policy == "whitelist" and failure_policy == "fail-close":
        policy_rules = "    meta mark != 0x0 oifname != \"singtun0\" ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop\n"
    elif default_policy == "block":
        policy_rules = "    meta mark != 0x0 ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop\n"

    # Auto-detect LAN bridge interface name
    lan_iface = _detect_lan_iface()
    _listen_port = _LISTEN_PORT
    captive_chain = ""
    if default_policy in ("whitelist", "block"):
        captive_chain = f"""
  chain captive_redirect {{
    type nat hook prerouting priority dstnat + 10; policy accept;
    iifname "{lan_iface}" ether saddr @unresolved_macs tcp dport 80 counter redirect to :{_listen_port}
    iifname "{lan_iface}" ether saddr @managed_macs accept
    iifname "{lan_iface}" tcp dport 80 counter redirect to :{_listen_port}
  }}"""

    nft_script = f"""
table {NFT_TABLE} {{
  map mac_to_mark {{
    type ether_addr : mark
    elements = {{ {mac_elements} }}
  }}
  set managed_macs {{
    type ether_addr
    elements = {{ {managed_macs} }}
  }}
  set unresolved_macs {{
    type ether_addr
    elements = {{ {unresolved_macs} }}
  }}
  set unresolved_marks {{
    type mark
    elements = {{ {unresolved_marks} }}
  }}
  set doh_ipv4 {{
    type ipv4_addr
    elements = {{ {doh4_elements} }}
  }}
  set doh_ipv6 {{
    type ipv6_addr
    elements = {{ {doh6_elements} }}
  }}
  chain prerouting_mark {{
    type filter hook prerouting priority mangle; policy accept;
    ct mark != 0x0 meta mark set ct mark
    ct state new ether saddr @managed_macs meta mark set ether saddr map @mac_to_mark
    ct state new ct mark set meta mark
  }}
  chain dns_guard {{
    type nat hook prerouting priority dstnat; policy accept;
    meta mark != 0x0 udp dport 53 counter redirect to :{dns_port}
    meta mark != 0x0 tcp dport 53 counter redirect to :{dns_port}
  }}
  chain forward_guard {{
    type filter hook forward priority filter; policy accept;
    meta mark != 0x0 meta mark @unresolved_marks counter drop
    meta mark != 0x0 ip daddr @doh_ipv4 tcp dport 443 counter drop
    meta mark != 0x0 ip daddr @doh_ipv4 udp dport 443 counter drop
    meta mark != 0x0 ip6 daddr @doh_ipv6 tcp dport 443 counter drop
    meta mark != 0x0 ip6 daddr @doh_ipv6 udp dport 443 counter drop
    meta mark != 0x0 tcp dport 853 counter drop
    meta mark != 0x0 udp dport 853 counter drop
    meta mark != 0x0 udp dport 8853 counter drop
    meta mark != 0x0 udp dport 784 counter drop
    meta mark != 0x0 udp dport 3478 counter drop
    meta mark != 0x0 udp dport 5349 counter drop
    meta mark != 0x0 tcp dport 3478 counter drop
{policy_rules}  }}
  chain ipv6_guard {{
    type filter hook forward priority filter; policy accept;
    meta mark != 0x0 ip6 daddr != fe80::/10 ip6 daddr != ::1 counter drop
  }}{captive_chain}
}}
"""
    # Atomic apply: single nft -f with flush inside the script avoids
    # a window where no rules are loaded between delete and re-add.
    atomic_script = f"flush table {NFT_TABLE}\ndelete table {NFT_TABLE}\n" + nft_script
    try:
        r = subprocess.run(["nft", "-f", "-"], input=atomic_script.encode(),
                           capture_output=True, timeout=10)
        if r.returncode != 0:
            err_msg = r.stderr.decode(errors='ignore')
            # If table didn't exist yet, retry without flush/delete prefix
            if 'No such file' in err_msg or 'does not exist' in err_msg:
                r2 = subprocess.run(["nft", "-f", "-"], input=nft_script.encode(),
                                    capture_output=True, timeout=10)
                if r2.returncode != 0:
                    return f"nft error: {r2.stderr.decode(errors='ignore')}"
                return "ok"
            return f"nft error: {err_msg}"
        return "ok"
    except Exception as e:
        return f"nft exception: {e}"


def _flush_nftables() -> str:
    """Flush the macflow nftables table (disable all rules)."""
    try:
        subprocess.run(["nft", "flush", "table", NFT_TABLE],
                       capture_output=True, timeout=5)
        subprocess.run(["nft", "delete", "table", NFT_TABLE],
                       capture_output=True, timeout=5)
        return "flushed"
    except Exception as e:
        return f"flush exception: {e}"


def _flush_ip_rules() -> str:
    """Remove all macflow ip rules (pref 20000-29999)."""
    return _flush_macflow_ip_rules()


def _flush_macflow_ip_rules() -> str:
    """Remove ip rules in the macflow pref range (20000-29999) and flush associated routing tables."""
    try:
        r = subprocess.run(["ip", "-4", "rule", "show"], capture_output=True, timeout=5, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts or "fwmark" not in parts:
                continue
            pref_str = parts[0].rstrip(":")
            try:
                pref_val = int(pref_str)
            except ValueError:
                continue
            if 20000 <= pref_val < 30000:
                try:
                    subprocess.run(["ip", "-4", "rule", "del", "pref", pref_str],
                                   capture_output=True, timeout=3)
                except Exception:
                    pass
        # Also flush routing tables in macflow range to prevent stale entries
        for table_id in range(MARK_TABLE_BASE, MARK_TABLE_BASE + 256):
            try:
                subprocess.run(["ip", "-4", "route", "flush", "table", str(table_id)],
                               capture_output=True, timeout=2)
            except Exception:
                pass
        return "flushed"
    except Exception as e:
        return f"flush exception: {e}"


def _apply_ip_rules(state: Dict) -> str:
    if not state.get("enabled", False):
        return _flush_ip_rules()

    managed = [d for d in state.get("devices", []) if d.get("managed") and d.get("mark", 0) > 0]
    default_policy = state.get("default_policy", "whitelist")
    failure_policy = state.get("failure_policy", "fail-close")
    errors = []

    _flush_macflow_ip_rules()

    if default_policy == "block":
        for d in managed:
            mark = d["mark"]
            try:
                subprocess.run(
                    ["ip", "-4", "rule", "add", "pref", "20000",
                     "fwmark", f"0x{mark:x}", "blackhole"],
                    capture_output=True, timeout=3)
            except Exception as e:
                errors.append(f"block rule {mark}: {e}")
        return "ok (block mode)" if not errors else "; ".join(errors)

    marks_seen = set()
    marks_ordered = sorted(set(d["mark"] for d in managed))
    pref = 20000
    for d in managed:
        mark = d["mark"]
        if mark in marks_seen:
            continue
        marks_seen.add(mark)
        table = _mark_to_table(mark, marks_ordered)

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

    if default_policy == "whitelist" and failure_policy == "fail-close":
        for mark in marks_seen:
            try:
                subprocess.run(
                    ["ip", "-4", "rule", "add", "pref", str(pref),
                     "fwmark", f"0x{mark:x}", "blackhole"],
                    capture_output=True, timeout=3)
                pref += 10
            except Exception as e:
                errors.append(f"blackhole {mark}: {e}")

    return "ok" if not errors else "; ".join(errors)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=_LISTEN_PORT)
