"""Tests for backend/parsers.py – link parsers, subscription decoder, 3x-ui converter."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import base64
import json
import pytest
from parsers import (
    parse_ss, parse_vmess, parse_vless, parse_trojan,
    parse_hy2, parse_tuic, parse_links, parse_subscription,
    convert_inbound, extract_transport, json_or_dict,
    safe_node_summary,
)


# ── Shadowsocks ──

class TestParseSs:
    def test_standard(self):
        link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#MyNode"
        r = parse_ss(link)
        assert r["type"] == "shadowsocks"
        assert r["server"] == "1.2.3.4"
        assert r["server_port"] == 8388
        assert r["method"] == "aes-256-gcm"
        assert r["password"] == "password"
        assert r["tag"] == "MyNode"

    def test_ipv6_bracket(self):
        link = "ss://YWVzLTI1Ni1nY206cGFzcw@[::1]:8388#v6"
        r = parse_ss(link)
        assert r["server"] == "::1"
        assert r["server_port"] == 8388
        assert r["tag"] == "v6"

    def test_base64_full_link(self):
        raw = "aes-128-gcm:testpwd@example.com:443"
        encoded = base64.b64encode(raw.encode()).decode().rstrip("=")
        link = f"ss://{encoded}#encoded"
        r = parse_ss(link)
        assert r["server"] == "example.com"
        assert r["password"] == "testpwd"


# ── VMess ──

class TestParseVmess:
    def test_standard(self):
        data = {
            "v": "2", "ps": "vmess-node", "add": "server.com", "port": "443",
            "id": "uuid-123", "aid": "0", "scy": "auto", "net": "ws",
            "path": "/ws", "host": "cdn.host.com", "tls": "tls",
            "sni": "sni.host.com"
        }
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        r = parse_vmess(f"vmess://{encoded}")
        assert r["type"] == "vmess"
        assert r["server"] == "server.com"
        assert r["uuid"] == "uuid-123"
        assert r["transport"]["type"] == "ws"
        assert r["transport"]["headers"]["Host"] == "cdn.host.com"
        assert r["tls"]["enabled"] is True
        assert r["tls"]["server_name"] == "sni.host.com"
        assert r["alter_id"] == 0

    def test_no_tls(self):
        data = {"add": "1.2.3.4", "port": 10086, "id": "uid", "net": "tcp"}
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        r = parse_vmess(f"vmess://{encoded}")
        assert "tls" not in r
        assert r["transport"]["type"] == "tcp"

    def test_grpc_transport(self):
        data = {"add": "s.com", "port": 443, "id": "u", "net": "grpc", "path": "svc"}
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        r = parse_vmess(f"vmess://{encoded}")
        assert r["transport"]["type"] == "grpc"
        assert r["transport"]["service_name"] == "svc"


# ── VLESS ──

class TestParseVless:
    def test_tls(self):
        link = "vless://uuid-abc@server.com:443?security=tls&sni=sni.com&type=ws&path=/ws&host=cdn.com&fp=chrome&alpn=h2,http/1.1#My VLESS"
        r = parse_vless(link)
        assert r["type"] == "vless"
        assert r["uuid"] == "uuid-abc"
        assert r["server"] == "server.com"
        assert r["server_port"] == 443
        assert r["tls"]["enabled"] is True
        assert r["tls"]["server_name"] == "sni.com"
        assert r["tls"]["alpn"] == ["h2", "http/1.1"]
        assert r["tls"]["utls"]["fingerprint"] == "chrome"
        assert r["transport"]["type"] == "ws"
        assert r["transport"]["headers"]["Host"] == "cdn.com"
        assert r["tag"] == "My VLESS"

    def test_reality(self):
        link = "vless://uid@1.2.3.4:443?security=reality&sni=example.com&pbk=publickey123&sid=shortid&fp=chrome&flow=xtls-rprx-vision&type=tcp#Reality"
        r = parse_vless(link)
        assert r["tls"]["reality"]["enabled"] is True
        assert r["tls"]["reality"]["public_key"] == "publickey123"
        assert r["tls"]["reality"]["short_id"] == "shortid"
        assert r["flow"] == "xtls-rprx-vision"

    def test_no_security(self):
        link = "vless://uid@1.2.3.4:8080?type=tcp#plain"
        r = parse_vless(link)
        assert "tls" not in r

    def test_grpc(self):
        link = "vless://uid@s.com:443?type=grpc&serviceName=mygrpc&security=tls#grpc-node"
        r = parse_vless(link)
        assert r["transport"]["type"] == "grpc"
        assert r["transport"]["service_name"] == "mygrpc"


# ── Trojan ──

class TestParseTrojan:
    def test_standard(self):
        link = "trojan://password123@server.com:443?sni=sni.com&type=ws&path=/trojan&host=cdn.com&fp=firefox&alpn=h2#TrojanWS"
        r = parse_trojan(link)
        assert r["type"] == "trojan"
        assert r["password"] == "password123"
        assert r["server"] == "server.com"
        assert r["tls"]["enabled"] is True
        assert r["tls"]["server_name"] == "sni.com"
        assert r["tls"]["utls"]["fingerprint"] == "firefox"
        assert r["transport"]["type"] == "ws"
        assert r["tag"] == "TrojanWS"

    def test_defaults_to_tls(self):
        link = "trojan://pass@1.2.3.4:443#simple"
        r = parse_trojan(link)
        assert r["tls"]["enabled"] is True
        assert r["tls"]["server_name"] == "1.2.3.4"

    def test_grpc(self):
        link = "trojan://pwd@s.com:443?type=grpc&serviceName=svc#grpc"
        r = parse_trojan(link)
        assert r["transport"]["type"] == "grpc"
        assert r["transport"]["service_name"] == "svc"


# ── Hysteria2 ──

class TestParseHy2:
    def test_standard(self):
        link = "hy2://password@server.com:443?sni=sni.com&insecure=1&obfs=salamander&obfs-password=obfspwd&alpn=h3#Hy2Node"
        r = parse_hy2(link)
        assert r["type"] == "hysteria2"
        assert r["password"] == "password"
        assert r["server"] == "server.com"
        assert r["tls"]["enabled"] is True
        assert r["tls"]["insecure"] is True
        assert r["tls"]["server_name"] == "sni.com"
        assert r["tls"]["alpn"] == ["h3"]
        assert r["obfs"]["type"] == "salamander"
        assert r["obfs"]["password"] == "obfspwd"

    def test_no_obfs(self):
        link = "hysteria2://pwd@1.2.3.4:443#simple"
        r = parse_hy2(link)
        assert r["tls"]["enabled"] is True
        assert "obfs" not in r

    def test_secure_by_default(self):
        link = "hy2://pwd@host.com:8443#secure"
        r = parse_hy2(link)
        assert r["tls"]["insecure"] is False


# ── TUIC ──

class TestParseTuic:
    def test_standard(self):
        link = "tuic://uuid123:password456@server.com:443#TUIC"
        r = parse_tuic(link)
        assert r["type"] == "tuic"
        assert r["uuid"] == "uuid123"
        assert r["password"] == "password456"
        assert r["server"] == "server.com"
        assert r["server_port"] == 443
        assert r["tag"] == "TUIC"

    def test_default_port(self):
        link = "tuic://u:p@host.com#node"
        r = parse_tuic(link)
        assert r["server_port"] == 443


# ── parse_links (multi-line) ──

class TestParseLinks:
    def test_multiple_protocols(self):
        lines = (
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.1.1.1:8388#SS\n"
            "trojan://pwd@2.2.2.2:443#Trojan\n"
            "tuic://u:p@3.3.3.3:443#TUIC\n"
        )
        results = parse_links(lines)
        assert len(results) == 3
        types = [r["type"] for r in results]
        assert "shadowsocks" in types
        assert "trojan" in types
        assert "tuic" in types

    def test_skips_bad_lines(self):
        lines = "invalid_line\nss://YWVzLTI1Ni1nY206cGFzcw@1.1.1.1:8388#OK\n"
        results = parse_links(lines)
        assert len(results) == 1

    def test_empty(self):
        assert parse_links("") == []
        assert parse_links("\n\n\n") == []


# ── parse_subscription ──

class TestParseSubscription:
    def test_base64_encoded(self):
        raw = "ss://YWVzLTI1Ni1nY206cGFzcw@1.1.1.1:8388#node1"
        encoded = base64.b64encode(raw.encode()).decode()
        results = parse_subscription(encoded)
        assert len(results) == 1
        assert results[0]["type"] == "shadowsocks"

    def test_singbox_json(self):
        data = {"outbounds": [
            {"type": "vless", "tag": "vl1", "server": "s.com", "server_port": 443},
            {"type": "direct", "tag": "direct-out"},  # should be filtered
            {"type": "selector", "tag": "sel"},        # should be filtered
            {"type": "vmess", "tag": "", "server": ""},  # empty tag/server, filtered
        ]}
        results = parse_subscription(json.dumps(data))
        assert len(results) == 1
        assert results[0]["tag"] == "vl1"

    def test_plain_links(self):
        raw = "trojan://pwd@s.com:443#node\n"
        results = parse_subscription(raw)
        assert len(results) == 1


# ── convert_inbound (3x-ui) ──

class TestConvertInbound:
    def test_vmess(self):
        inbound = {
            "protocol": "vmess",
            "remark": "my-vmess",
            "listen": "0.0.0.0",
            "port": 10086,
            "streamSettings": json.dumps({"network": "ws", "wsSettings": {"path": "/ws"}}),
            "settings": json.dumps({"clients": [{"id": "uuid-1"}, {"id": "uuid-2"}, {"id": ""}]}),
        }
        nodes = convert_inbound(inbound)
        assert len(nodes) == 2  # empty uuid filtered
        assert nodes[0]["uuid"] == "uuid-1"
        assert nodes[0]["server_port"] == 10086

    def test_trojan_empty_password_filtered(self):
        inbound = {
            "protocol": "trojan",
            "remark": "tj",
            "listen": "0.0.0.0",
            "port": 443,
            "streamSettings": "{}",
            "settings": json.dumps({"clients": [{"password": "pwd"}, {"password": ""}]}),
        }
        nodes = convert_inbound(inbound)
        assert len(nodes) == 1

    def test_shadowsocks(self):
        inbound = {
            "protocol": "shadowsocks",
            "remark": "ss",
            "listen": "0.0.0.0",
            "port": 8388,
            "streamSettings": "{}",
            "settings": json.dumps({"method": "aes-128-gcm", "password": "test"}),
        }
        nodes = convert_inbound(inbound)
        assert len(nodes) == 1
        assert nodes[0]["method"] == "aes-128-gcm"

    def test_unknown_protocol(self):
        nodes = convert_inbound({"protocol": "wireguard", "remark": "wg", "streamSettings": "{}", "settings": "{}"})
        assert len(nodes) == 1
        assert nodes[0]["type"] == "unknown"


# ── extract_transport ──

class TestExtractTransport:
    def test_ws(self):
        t = extract_transport({"network": "ws", "wsSettings": {"path": "/path", "headers": {"Host": "h"}}})
        assert t["type"] == "ws"
        assert t["path"] == "/path"

    def test_grpc(self):
        t = extract_transport({"network": "grpc", "grpcSettings": {"serviceName": "svc"}})
        assert t["type"] == "grpc"
        assert t["service_name"] == "svc"

    def test_tcp_default(self):
        t = extract_transport({})
        assert t["type"] == "tcp"


# ── json_or_dict ──

class TestJsonOrDict:
    def test_dict_passthrough(self):
        d = {"a": 1}
        assert json_or_dict(d) is d

    def test_json_string(self):
        assert json_or_dict('{"a": 1}') == {"a": 1}

    def test_empty(self):
        assert json_or_dict("") == {}
        assert json_or_dict(None) == {}

    def test_invalid(self):
        assert json_or_dict("not json") == {}


# ── safe_node_summary ──

class TestSafeNodeSummary:
    def test_none(self):
        assert safe_node_summary(None) is None

    def test_node(self):
        node = {"tag": "n1", "type": "vless", "server": "s.com", "server_port": 443,
                "latency": 50, "speed_mbps": 10.0, "health_score": 80, "health_status": "healthy",
                "extra_field": "ignore"}
        s = safe_node_summary(node)
        assert s["tag"] == "n1"
        assert "extra_field" not in s

    def test_empty_dict(self):
        # Empty dict is falsy in Python, so safe_node_summary returns None
        assert safe_node_summary({}) is None
