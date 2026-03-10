"""MACFlow state storage and migration helpers."""
import json
import os
import threading
from typing import Any, Dict, Optional

from health import node_set_defaults, recompute_node_health
from utils import DATA_DIR, STATE_FILE, audit, ensure_data_dir, normalize_ipv4

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

state_lock = threading.RLock()
_state_cache: Optional[Dict[str, Any]] = None
_state_cache_mtime: float = 0


def read_state() -> Dict[str, Any]:
    global _state_cache, _state_cache_mtime
    ensure_data_dir()
    with state_lock:
        if not STATE_FILE.exists():
            write_state(INITIAL_STATE)
            return dict(INITIAL_STATE)

        try:
            current_mtime = STATE_FILE.stat().st_mtime
        except OSError:
            current_mtime = 0

        if _state_cache is not None and current_mtime == _state_cache_mtime and current_mtime > 0:
            return json.loads(json.dumps(_state_cache))

        try:
            text = STATE_FILE.read_text("utf-8").strip()
            if not text:
                raise ValueError("empty state file")
            raw = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            audit("state_corrupt", f"state.json corrupt ({exc}), resetting to defaults", level="error")
            write_state(INITIAL_STATE)
            return dict(INITIAL_STATE)

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
            if "remark" not in d:
                d["remark"] = ""
                changed = True

            ip_fixed = normalize_ipv4(d.get("ip"))
            if d.get("ip", "") != ip_fixed:
                d["ip"] = ip_fixed
                changed = True

            ip_last = normalize_ipv4(d.get("last_ip"))
            if d.get("last_ip", "") != ip_last:
                d["last_ip"] = ip_last
                changed = True

        for n in raw.get("nodes", []):
            if node_set_defaults(n):
                changed = True
            if recompute_node_health(n):
                changed = True

        for src in raw.get("xui_sources", []):
            if "enabled" not in src:
                src["enabled"] = True
                changed = True
            if "last_sync" not in src:
                src["last_sync"] = 0
                changed = True
            if "last_error" not in src:
                src["last_error"] = ""
                changed = True

        for sub in raw.get("subscriptions", []):
            if "last_sync" not in sub:
                sub["last_sync"] = 0
                changed = True

        if changed:
            write_state(raw)
        else:
            _state_cache = json.loads(json.dumps(raw))
            _state_cache_mtime = current_mtime

        return raw


def write_state(data: Dict[str, Any]) -> None:
    global _state_cache, _state_cache_mtime
    with state_lock:
        ensure_data_dir()
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
        tmp.replace(STATE_FILE)
        try:
            os.chmod(STATE_FILE, 0o600)
        except OSError:
            pass

        _state_cache = json.loads(json.dumps(data))
        try:
            _state_cache_mtime = STATE_FILE.stat().st_mtime
        except OSError:
            _state_cache_mtime = 0


def next_mark(state: Dict[str, Any]) -> int:
    used = {d.get("mark", 0) for d in state.get("devices", [])}
    mark = 0x100
    while mark in used:
        mark += 1
    return mark
