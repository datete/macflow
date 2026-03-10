"""MACFlow health state, probes and fail-close helpers."""
import concurrent.futures
import os
import re
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

health_lock = threading.Lock()

health_state: Dict[str, Any] = {
    "checks": {},
    "alerts": [],
    "overall_status": "unknown",
    "checked_at": 0,
    "probe_cycle": 0,
}

fail_close_guard: Dict[str, Any] = {
    "active": False,
    "since": 0,
    "updated_at": 0,
    "reason": "",
}

PROBE_INTERVAL = 60


def node_set_defaults(node: Dict[str, Any]) -> bool:
    changed = False
    defaults = {
        "enabled": True,
        "latency": None,
        "speed_mbps": 0.0,
        "health_score": 50,
        "health_status": "unknown",
        "health_failures": 0,
        "last_probe_at": 0,
        "last_probe_ok_at": 0,
        "last_probe_error": "",
    }
    for k, v in defaults.items():
        if k not in node:
            node[k] = v
            changed = True
    try:
        score = int(node.get("health_score", 50))
    except Exception:
        score = 50
    score = max(0, min(100, score))
    if node.get("health_score") != score:
        node["health_score"] = score
        changed = True
    try:
        failures = int(node.get("health_failures", 0))
    except Exception:
        failures = 0
    failures = max(0, failures)
    if node.get("health_failures") != failures:
        node["health_failures"] = failures
        changed = True
    st = str(node.get("health_status", "unknown") or "unknown")
    if st not in ("healthy", "degraded", "unhealthy", "disabled", "unknown"):
        st = "unknown"
    if node.get("health_status") != st:
        node["health_status"] = st
        changed = True
    try:
        speed = float(node.get("speed_mbps") or 0.0)
    except Exception:
        speed = 0.0
    if speed < 0:
        speed = 0.0
    if node.get("speed_mbps") != speed:
        node["speed_mbps"] = speed
        changed = True
    return changed


def node_health_score_value(node: Dict[str, Any]) -> int:
    try:
        return max(0, min(100, int(node.get("health_score", 0))))
    except Exception:
        return 0


def compute_node_health_score(latency: Optional[int], speed_mbps: float, failures: int, enabled: bool) -> tuple:
    if not enabled:
        return 0, "disabled"

    if latency is None:
        latency_points = 42
    elif latency < 0:
        latency_points = 5
    elif latency <= 80:
        latency_points = 55
    elif latency <= 180:
        latency_points = 45
    elif latency <= 350:
        latency_points = 32
    elif latency <= 650:
        latency_points = 20
    else:
        latency_points = 10

    if speed_mbps >= 80:
        speed_points = 40
    elif speed_mbps >= 30:
        speed_points = 32
    elif speed_mbps >= 10:
        speed_points = 24
    elif speed_mbps >= 3:
        speed_points = 16
    elif speed_mbps > 0:
        speed_points = 8
    else:
        speed_points = 10

    penalty = min(failures * 12, 60)
    score = max(0, min(100, latency_points + speed_points - penalty))

    if score >= 70 and failures == 0 and (latency is None or latency >= 0):
        return score, "healthy"
    if score >= 40:
        return score, "degraded"
    return score, "unhealthy"


def recompute_node_health(node: Dict[str, Any]) -> bool:
    changed = node_set_defaults(node)
    try:
        latency = int(node["latency"]) if node.get("latency") is not None else None
    except Exception:
        latency = None
    try:
        speed = float(node.get("speed_mbps") or 0.0)
    except Exception:
        speed = 0.0
    failures = int(node.get("health_failures", 0)) if str(node.get("health_failures", "")).isdigit() else 0
    score, status = compute_node_health_score(latency, speed, failures, bool(node.get("enabled", True)))

    last_probe = node.get("last_probe_at", 0) or 0
    if last_probe and node.get("enabled", True):
        age_hours = (time.time() - last_probe) / 3600
        if age_hours > 6:
            decay = min(int((age_hours - 6) * 2), 30)
            score = max(0, score - decay)
            if score < 40 and status == "healthy":
                status = "degraded"
            if score < 20 and status != "disabled":
                status = "unhealthy"

    if node.get("health_score") != score:
        node["health_score"] = score
        changed = True
    if node.get("health_status") != status:
        node["health_status"] = status
        changed = True
    return changed


def mark_node_probe(node: Dict[str, Any], probe_ok: bool, probe_error: str = "") -> bool:
    changed = node_set_defaults(node)
    now = int(time.time())
    if node.get("last_probe_at") != now:
        node["last_probe_at"] = now
        changed = True
    failures = int(node.get("health_failures", 0)) if str(node.get("health_failures", "")).isdigit() else 0
    if probe_ok:
        next_failures = 0
        if node.get("health_failures") != next_failures:
            node["health_failures"] = next_failures
            changed = True
        if node.get("last_probe_ok_at") != now:
            node["last_probe_ok_at"] = now
            changed = True
        if node.get("last_probe_error"):
            node["last_probe_error"] = ""
            changed = True
    else:
        next_failures = failures + 1
        if node.get("health_failures") != next_failures:
            node["health_failures"] = next_failures
            changed = True
        short_err = (probe_error or "probe failed")[:180]
        if node.get("last_probe_error") != short_err:
            node["last_probe_error"] = short_err
            changed = True
    if recompute_node_health(node):
        changed = True
    return changed


def node_selector_healthy(node: Dict[str, Any]) -> bool:
    if not node.get("enabled", True):
        return False
    if node.get("health_status") in ("unhealthy", "disabled"):
        return False
    return node_health_score_value(node) >= 35


def node_sort_key(node: Dict[str, Any]) -> tuple:
    score = node_health_score_value(node)
    latency = node.get("latency")
    try:
        if latency is None:
            raise ValueError("latency missing")
        latency_val = int(latency)
        if latency_val < 0:
            latency_val = 10_000
    except Exception:
        latency_val = 9_000
    return (-score, latency_val, str(node.get("tag", "")))


def run_check(cmd: List[str], timeout: int = 3) -> tuple:
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        ms = int((time.time() - t0) * 1000)
        return r.returncode, r.stdout, ms
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return -1, str(e), ms


def extract_nft_counters(output: str, keyword: str) -> Dict[str, int]:
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


def is_local_port_listening(port: int, proto: str) -> bool:
    if port <= 0:
        return False
    proto = proto.lower()
    if proto not in ("tcp", "udp"):
        return False

    files = ["/proc/net/tcp", "/proc/net/tcp6"] if proto == "tcp" else ["/proc/net/udp", "/proc/net/udp6"]
    hex_port = f"{port:04X}"

    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local = parts[1]
                    st = parts[3]
                    if ":" not in local:
                        continue
                    _, phex = local.rsplit(":", 1)
                    if phex.upper() != hex_port:
                        continue
                    if proto == "tcp" and st != "0A":
                        continue
                    return True
        except Exception:
            continue
    return False


def check_singbox(is_singbox_running: Callable[[], bool]) -> Dict[str, Any]:
    t0 = time.time()
    ok = is_singbox_running()
    ms = int((time.time() - t0) * 1000)
    return {
        "status": "ok" if ok else "critical",
        "status_legacy": "running" if ok else "stopped",
        "message": "sing-box process active" if ok else "sing-box not running",
        "latency_ms": ms,
    }


def check_tun() -> Dict[str, Any]:
    rc, out, ms = run_check(["ip", "link", "show", "singtun0"])
    up = rc == 0 and "UP" in out
    return {
        "status": "ok" if up else "critical",
        "status_legacy": "up" if up else "down",
        "message": "TUN interface UP" if up else "TUN interface down or missing",
        "latency_ms": ms,
    }


def check_nftables() -> Dict[str, Any]:
    rc, _, ms = run_check(["nft", "list", "table", "inet", "macflow"])
    loaded = rc == 0
    return {
        "status": "ok" if loaded else "critical",
        "status_legacy": "loaded" if loaded else "missing",
        "message": "macflow table loaded" if loaded else "macflow table not found",
        "latency_ms": ms,
    }


def check_dns_guard() -> Dict[str, Any]:
    rc, out, ms = run_check(["nft", "list", "chain", "inet", "macflow", "dns_guard"])
    if rc != 0:
        return {
            "status": "critical", "status_legacy": "missing",
            "message": "dns_guard chain not found", "latency_ms": ms,
            "details": {"chain_exists": False},
        }

    has_udp = "udp dport 53" in out and "redirect" in out
    has_tcp = "tcp dport 53" in out and "redirect" in out
    counters = extract_nft_counters(out, "redirect")
    m = re.search(r"redirect\s+to\s+:(\d+)", out)
    redirect_port = int(m.group(1)) if m else 0
    udp_listener = is_local_port_listening(redirect_port, "udp") if has_udp else True
    tcp_listener = is_local_port_listening(redirect_port, "tcp") if has_tcp else True

    details = {
        "chain_exists": True,
        "udp53_redirect": has_udp,
        "tcp53_redirect": has_tcp,
        "redirect_packets": counters["packets"],
        "redirect_port": redirect_port,
        "udp_listener": udp_listener,
        "tcp_listener": tcp_listener,
    }
    if has_udp and has_tcp and udp_listener and tcp_listener:
        return {
            "status": "ok", "status_legacy": "loaded",
            "message": f"dns_guard active, {counters['packets']} pkts redirected",
            "latency_ms": ms, "details": details,
        }
    if has_udp and has_tcp and (not udp_listener or not tcp_listener):
        missing = []
        if not udp_listener:
            missing.append("udp")
        if not tcp_listener:
            missing.append("tcp")
        return {
            "status": "critical", "status_legacy": "degraded",
            "message": f"dns_guard redirects to :{redirect_port} but listener missing ({'/'.join(missing)})",
            "latency_ms": ms, "details": details,
        }
    status = "critical" if not (has_udp or has_tcp) else "warn"
    return {
        "status": status, "status_legacy": "degraded",
        "message": "dns_guard partial or missing redirect rules",
        "latency_ms": ms, "details": details,
    }


def check_leak_guard() -> Dict[str, Any]:
    rc, out, ms = run_check(["nft", "list", "chain", "inet", "macflow", "forward_guard"])
    if rc != 0:
        return {
            "status": "critical", "status_legacy": "missing",
            "message": "leak_guard (forward_guard) chain not found", "latency_ms": ms,
            "details": {"chain_exists": False},
        }

    checks = {
        "doh_443_block": "dport 443" in out and "doh_ipv4" in out and "drop" in out,
        "doh_ipv6_block": "dport 443" in out and "doh_ipv6" in out and "drop" in out,
        "dot_853_block": "dport 853" in out and "drop" in out,
        "doq_8853_block": "dport 8853" in out and "drop" in out,
        "dnscrypt_784_block": "dport 784" in out and "drop" in out,
        "stun_3478_block": "dport 3478" in out and "drop" in out,
        "stun_5349_block": "dport 5349" in out and "drop" in out,
    }
    all_ok = all(checks.values())
    return {
        "status": "ok" if all_ok else "warn",
        "status_legacy": "loaded" if all_ok else "degraded",
        "message": "leak_guard rules complete" if all_ok else "leak_guard missing some blocking rules",
        "latency_ms": ms,
        "details": {"chain_exists": True, **checks},
    }


def check_ipv6_guard() -> Dict[str, Any]:
    rc, out, ms = run_check(["nft", "list", "chain", "inet", "macflow", "ipv6_guard"])
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
        "latency_ms": ms,
        "details": {"chain_exists": True, "has_drop_rules": has_drop},
    }


def collect_health_checks(is_singbox_running: Callable[[], bool]) -> tuple:
    t0 = time.time()
    check_fns = {
        "singbox": lambda: check_singbox(is_singbox_running),
        "tun": check_tun,
        "nftables": check_nftables,
        "dns_guard": check_dns_guard,
        "leak_guard": check_leak_guard,
        "ipv6_guard": check_ipv6_guard,
    }
    checks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(check_fns)) as pool:
        futures = {pool.submit(fn): name for name, fn in check_fns.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                checks[name] = future.result()
            except Exception as e:
                checks[name] = {
                    "status": "critical",
                    "message": f"check raised exception: {e}",
                    "latency_ms": 0,
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
    return checks, overall, int(t0), int((time.time() - t0) * 1000)


def update_alerts(checks: Dict[str, Any], now: int) -> None:
    existing = {a["id"]: a for a in health_state.get("alerts", [])}
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
                    "id": alert_id,
                    "severity": severity,
                    "title": f"{name} check failed",
                    "message": c["message"],
                    "first_seen": now,
                    "last_seen": now,
                    "status": "active",
                    "recovered_at": None,
                }
        elif c["status"] == "ok" and alert_id in existing and existing[alert_id]["status"] == "active":
            existing[alert_id]["status"] = "resolved"
            existing[alert_id]["recovered_at"] = now

    health_state["alerts"] = list(existing.values())


def apply_health_results(checks: Dict[str, Any], overall: str, now: int) -> None:
    for name, check in checks.items():
        prev = health_state["checks"].get(name, {})
        if check["status"] == "ok":
            check["consecutive_failures"] = 0
            check["last_ok_at"] = now
            check["last_fail_at"] = prev.get("last_fail_at", 0)
        else:
            check["consecutive_failures"] = prev.get("consecutive_failures", 0) + 1
            check["last_ok_at"] = prev.get("last_ok_at", 0)
            check["last_fail_at"] = now
        health_state["checks"][name] = check

    health_state["overall_status"] = overall
    health_state["checked_at"] = now
    update_alerts(checks, now)


def run_health_checks(is_singbox_running: Callable[[], bool]) -> tuple:
    checks, overall, now, elapsed = collect_health_checks(is_singbox_running)
    apply_health_results(checks, overall, now)
    return checks, overall, now, elapsed


def is_fail_close_applicable(state: Dict[str, Any]) -> bool:
    return (
        state.get("enabled", False)
        and state.get("default_policy", "whitelist") == "whitelist"
        and state.get("failure_policy", "fail-close") == "fail-close"
    )


def set_fail_close_guard(active: bool, reason: str, audit_fn: Optional[Callable[..., None]] = None) -> None:
    now = int(time.time())
    with health_lock:
        prev_active = fail_close_guard.get("active", False)
        if active:
            fail_close_guard["active"] = True
            fail_close_guard["reason"] = reason
            if not fail_close_guard.get("since"):
                fail_close_guard["since"] = now
            fail_close_guard["updated_at"] = now
        else:
            fail_close_guard["active"] = False
            fail_close_guard["reason"] = reason
            fail_close_guard["since"] = 0
            fail_close_guard["updated_at"] = now

    if audit_fn and prev_active != active:
        audit_fn(
            "fail_close_guard",
            f"active={active} reason={reason}",
            level="error" if active else "info",
            component="probe",
        )


def guarded_runtime_state(state: Dict[str, Any]) -> Dict[str, Any]:
    if fail_close_guard.get("active") and is_fail_close_applicable(state):
        forced = dict(state)
        forced["default_policy"] = "block"
        return forced
    return state
