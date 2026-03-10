"""Tests for backend/utils.py – validation, IP helpers, format utilities."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from utils import (
    validate_mac, validate_ip_str, validate_url_safe,
    normalize_ipv4, fmt_bytes, split_ip_versions,
    mark_to_table, gen_id, _MAC_RE, MARK_TABLE_BASE,
)


# ── MAC validation ──

class TestValidateMac:
    def test_valid_lowercase(self):
        assert validate_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_valid_uppercase(self):
        assert validate_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_valid_mixed(self):
        assert validate_mac("  aA:bB:01:23:45:67  ") == "AA:BB:01:23:45:67"

    def test_invalid_short(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("AA:BB:CC:DD:EE")

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("AABBCCDDEEFF")

    def test_invalid_chars(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("GG:HH:II:JJ:KK:LL")


# ── IP validation ──

class TestValidateIpStr:
    def test_valid_ipv4(self):
        assert validate_ip_str("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert validate_ip_str("::1") == "::1"

    def test_strips_whitespace(self):
        assert validate_ip_str("  10.0.0.1  ") == "10.0.0.1"

    def test_invalid(self):
        with pytest.raises(ValueError):
            validate_ip_str("not_an_ip")


# ── URL validation ──

class TestValidateUrlSafe:
    def test_valid_https(self):
        assert validate_url_safe("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert validate_url_safe("http://192.168.1.1:8080") == "http://192.168.1.1:8080"

    def test_reject_ftp(self):
        with pytest.raises(ValueError, match="http or https"):
            validate_url_safe("ftp://example.com")

    def test_reject_loopback(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url_safe("http://127.0.0.1/path")

    def test_reject_link_local(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url_safe("http://169.254.1.1/path")

    def test_allow_private_lan(self):
        # Private LAN addresses should be allowed (for 3x-ui)
        assert validate_url_safe("http://192.168.1.100:8080") == "http://192.168.1.100:8080"

    def test_reject_empty_hostname(self):
        with pytest.raises(ValueError, match="missing hostname"):
            validate_url_safe("http:///path")


# ── normalize_ipv4 ──

class TestNormalizeIpv4:
    def test_valid(self):
        assert normalize_ipv4("192.168.1.1") == "192.168.1.1"

    def test_none(self):
        assert normalize_ipv4(None) == ""

    def test_empty(self):
        assert normalize_ipv4("") == ""

    def test_ipv6_returns_empty(self):
        assert normalize_ipv4("::1") == ""

    def test_invalid_returns_empty(self):
        assert normalize_ipv4("abc") == ""

    def test_whitespace_stripped(self):
        assert normalize_ipv4("  10.0.0.1 ") == "10.0.0.1"


# ── fmt_bytes ──

class TestFmtBytes:
    def test_bytes(self):
        assert fmt_bytes(500) == "500 B"

    def test_kilobytes(self):
        assert fmt_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert fmt_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert fmt_bytes(3 * 1024 * 1024 * 1024) == "3.00 GB"

    def test_zero(self):
        assert fmt_bytes(0) == "0 B"


# ── split_ip_versions ──

class TestSplitIpVersions:
    def test_mixed(self):
        v4, v6 = split_ip_versions(["1.1.1.1", "::1", "8.8.8.8", "2001:db8::1"])
        assert v4 == ["1.1.1.1", "8.8.8.8"]
        assert v6 == ["::1", "2001:db8::1"]

    def test_empty(self):
        v4, v6 = split_ip_versions([])
        assert v4 == []
        assert v6 == []

    def test_invalid_skipped(self):
        v4, v6 = split_ip_versions(["invalid", "1.2.3.4", None, ""])
        assert v4 == ["1.2.3.4"]
        assert v6 == []

    def test_non_list_wrapped(self):
        v4, v6 = split_ip_versions("10.0.0.1")
        assert v4 == ["10.0.0.1"]


# ── mark_to_table ──

class TestMarkToTable:
    def test_first_mark(self):
        assert mark_to_table(0x100, [0x100, 0x101, 0x102]) == MARK_TABLE_BASE

    def test_second_mark(self):
        assert mark_to_table(0x101, [0x100, 0x101, 0x102]) == MARK_TABLE_BASE + 1

    def test_non_sequential(self):
        assert mark_to_table(0x200, [0x100, 0x200]) == MARK_TABLE_BASE + 1

    def test_unknown_mark_fallback(self):
        result = mark_to_table(0x105, [0x100, 0x101])
        assert isinstance(result, int)


# ── gen_id ──

class TestGenId:
    def test_length(self):
        assert len(gen_id()) == 8  # 4 bytes = 8 hex chars

    def test_unique(self):
        ids = {gen_id() for _ in range(100)}
        assert len(ids) == 100


# ── MAC regex ──

class TestMacRe:
    def test_valid(self):
        assert _MAC_RE.match("AA:BB:CC:DD:EE:FF")

    def test_invalid(self):
        assert not _MAC_RE.match("AABBCCDDEEFF")
        assert not _MAC_RE.match("AA-BB-CC-DD-EE-FF")
