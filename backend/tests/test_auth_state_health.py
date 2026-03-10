"""Tests for extracted auth/state/health modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import time
from pathlib import Path

import auth
import health
import state


class TestAuthModule:
    def test_hash_and_verify_password(self):
        pwd = "VeryStrongPass123!"
        stored = auth.hash_password(pwd)
        assert stored.startswith("pbkdf2:")
        assert auth.verify_password(pwd, stored) is True
        assert auth.verify_password("wrong", stored) is False

    def test_session_create_validate_delete(self):
        token = auth.create_session("127.0.0.1")
        assert auth.validate_session(token) is True
        auth.delete_session(token)
        assert auth.validate_session(token) is False

    def test_public_path(self):
        assert auth.is_path_public("/api/auth/login") is True
        assert auth.is_path_public("/captive/foo") is True
        assert auth.is_path_public("/private/endpoint") is False


class TestHealthModule:
    def test_node_health_recompute(self):
        node = {"enabled": True, "latency": 50, "speed_mbps": 60.0, "health_failures": 0}
        changed = health.recompute_node_health(node)
        assert changed is True
        assert node["health_status"] in ("healthy", "degraded")
        assert 0 <= node["health_score"] <= 100

    def test_mark_node_probe_failure(self):
        node = {"enabled": True, "latency": 120, "speed_mbps": 10.0}
        health.mark_node_probe(node, False, "timeout")
        assert node["health_failures"] >= 1
        assert node["last_probe_error"] == "timeout"

    def test_fail_close_guard_toggle(self):
        health.set_fail_close_guard(True, "critical", audit_fn=None)
        assert health.fail_close_guard["active"] is True
        health.set_fail_close_guard(False, "recovered", audit_fn=None)
        assert health.fail_close_guard["active"] is False


class TestStateModule:
    def test_next_mark(self):
        s = {"devices": [{"mark": 0x100}, {"mark": 0x101}]}
        assert state.next_mark(s) == 0x102

    def test_write_and_read_state(self, tmp_path):
        old_state_file = state.STATE_FILE
        old_data_dir = state.DATA_DIR
        old_cache = state._state_cache
        old_cache_mtime = state._state_cache_mtime
        try:
            state.DATA_DIR = tmp_path
            state.STATE_FILE = tmp_path / "state.json"
            state._state_cache = None
            state._state_cache_mtime = 0
            sample = dict(state.INITIAL_STATE)
            sample["enabled"] = True
            state.write_state(sample)
            loaded = state.read_state()
            assert loaded["enabled"] is True
        finally:
            state.STATE_FILE = old_state_file
            state.DATA_DIR = old_data_dir
            state._state_cache = old_cache
            state._state_cache_mtime = old_cache_mtime

    def test_read_state_migrates_device_fields(self, tmp_path):
        old_state_file = state.STATE_FILE
        old_data_dir = state.DATA_DIR
        old_cache = state._state_cache
        old_cache_mtime = state._state_cache_mtime
        try:
            state.DATA_DIR = tmp_path
            state.STATE_FILE = tmp_path / "state.json"
            state._state_cache = None
            state._state_cache_mtime = 0
            legacy = {
                "enabled": True,
                "default_policy": "whitelist",
                "failure_policy": "fail-close",
                "dns": {},
                "xui_sources": [],
                "subscriptions": [],
                "nodes": [],
                "devices": [{"mac": "AA:BB:CC:DD:EE:FF", "group": "g1", "ip": "not-ip"}],
                "last_sync": 0,
                "last_apply": 0,
                "policy_version": None,
                "rollback_version": None,
            }
            state.STATE_FILE.write_text(json.dumps(legacy), encoding="utf-8")
            loaded = state.read_state()
            dev = loaded["devices"][0]
            assert "node_tag" in dev
            assert dev["mark"] == 0
            assert dev["remark"] == ""
            assert dev["ip"] == ""
        finally:
            state.STATE_FILE = old_state_file
            state.DATA_DIR = old_data_dir
            state._state_cache = old_cache
            state._state_cache_mtime = old_cache_mtime
