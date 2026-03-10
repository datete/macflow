"""Tests for backend/models.py – Pydantic model validation."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from pydantic import ValidationError
from models import (
    SourceCreate, SourceUpdate, ManualNode, LinkImport, SubCreate,
    DeviceCreate, DeviceBatch, NodeBatchAction, DeviceNodeUpdate,
    DeviceRemarkUpdate, DeviceIpUpdate, SettingsUpdate, ToggleReq,
    LoginRequest, SetPasswordRequest,
)


# ── SourceCreate ──

class TestSourceCreate:
    def test_valid(self):
        s = SourceCreate(name="test", base_url="https://panel.example.com:1234", username="admin", password="pass")
        assert s.base_url == "https://panel.example.com:1234"

    def test_strips_trailing_slash(self):
        s = SourceCreate(name="test", base_url="http://host.com/", username="u", password="p")
        assert not s.base_url.endswith("/")

    def test_rejects_ftp(self):
        with pytest.raises(ValidationError, match="http or https"):
            SourceCreate(name="x", base_url="ftp://host.com", username="u", password="p")

    def test_rejects_no_host(self):
        with pytest.raises(ValidationError, match="hostname"):
            SourceCreate(name="x", base_url="http:///path", username="u", password="p")


# ── ManualNode ──

class TestManualNode:
    def test_valid(self):
        n = ManualNode(type="vless", tag="node1", server="1.2.3.4", server_port=443)
        assert n.server_port == 443

    def test_port_too_low(self):
        with pytest.raises(ValidationError, match="server_port"):
            ManualNode(type="vless", tag="n", server="s", server_port=0)

    def test_port_too_high(self):
        with pytest.raises(ValidationError, match="server_port"):
            ManualNode(type="vless", tag="n", server="s", server_port=70000)

    def test_empty_tag(self):
        with pytest.raises(ValidationError, match="tag"):
            ManualNode(type="vmess", tag="", server="s", server_port=443)

    def test_tag_too_long(self):
        with pytest.raises(ValidationError, match="128"):
            ManualNode(type="vmess", tag="x" * 200, server="s", server_port=443)

    def test_tag_stripped(self):
        n = ManualNode(type="vmess", tag="  hello  ", server="s", server_port=443)
        assert n.tag == "hello"


# ── DeviceCreate ──

class TestDeviceCreate:
    def test_valid(self):
        d = DeviceCreate(name="phone", mac="aa:bb:cc:dd:ee:ff")
        assert d.mac == "AA:BB:CC:DD:EE:FF"
        assert d.node_tag == "direct"
        assert d.managed is True

    def test_invalid_mac(self):
        with pytest.raises(ValidationError, match="Invalid MAC"):
            DeviceCreate(name="x", mac="not-a-mac")


# ── SubCreate ──

class TestSubCreate:
    def test_valid(self):
        s = SubCreate(name="sub1", url="https://sub.example.com/token")
        assert s.url.startswith("https")

    def test_rejects_ftp(self):
        with pytest.raises(ValidationError, match="http or https"):
            SubCreate(name="s", url="ftp://host.com/sub")


# ── Simple models ──

class TestSimpleModels:
    def test_toggle_req(self):
        t = ToggleReq(enabled=True)
        assert t.enabled is True

    def test_login_request(self):
        l = LoginRequest(password="secret")
        assert l.password == "secret"

    def test_set_password_request(self):
        s = SetPasswordRequest(password="old", new_password="new")
        assert s.new_password == "new"

    def test_device_batch(self):
        batch = DeviceBatch(devices=[
            DeviceCreate(name="d1", mac="aa:bb:cc:dd:ee:ff"),
            DeviceCreate(name="d2", mac="11:22:33:44:55:66"),
        ])
        assert len(batch.devices) == 2

    def test_settings_update_optional(self):
        s = SettingsUpdate()
        assert s.default_policy is None
        assert s.dns is None

    def test_node_batch_action(self):
        a = NodeBatchAction(tags=["n1", "n2"], action="delete")
        assert a.action == "delete"

    def test_device_remark_update(self):
        r = DeviceRemarkUpdate(remark="living room")
        assert r.remark == "living room"

    def test_device_ip_update(self):
        i = DeviceIpUpdate(ip="10.0.0.5")
        assert i.ip == "10.0.0.5"

    def test_source_update_partial(self):
        s = SourceUpdate(name="new name")
        assert s.name == "new name"
        assert s.base_url is None

    def test_link_import(self):
        l = LinkImport(links="vless://...")
        assert l.links
