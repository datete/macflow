"""MACFlow utility functions – pure helpers with no FastAPI or state dependencies."""
import ipaddress
import json
import os
import pathlib
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional

# ── Constants ──

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = pathlib.Path(os.environ.get("MACFLOW_DATA_DIR", str(ROOT / "data")))
STATE_FILE = DATA_DIR / "state.json"
LOG_FILE = DATA_DIR / "audit.log"
WEB_DIR = pathlib.Path(os.environ.get("MACFLOW_WEB_DIR", str(ROOT / "web")))
MAX_LOG_LINES = 1000
LISTEN_PORT = int(os.environ.get("MACFLOW_LISTEN_PORT", 18080))

_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

MARK_TABLE_BASE = 100


# ── Validation helpers ──

def validate_mac(mac: str) -> str:
    """Validate and normalize MAC address. Raises ValueError if invalid."""
    mac = mac.strip().upper()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    return mac


def validate_ip_str(ip_str: str) -> str:
    """Validate IP address string. Raises ValueError if invalid."""
    ip_str = ip_str.strip()
    ipaddress.ip_address(ip_str)  # raises ValueError on invalid
    return ip_str


def validate_url_safe(url: str) -> str:
    """Validate URL is http/https and not targeting internal addresses."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"URL scheme must be http or https, got: {parsed.scheme}")
    hostname = parsed.hostname or ''
    if not hostname:
        raise ValueError("URL missing hostname")
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_loopback or addr.is_link_local:
            raise ValueError(f"URL target {hostname} is not allowed")
    except ValueError as e:
        if 'not allowed' in str(e):
            raise
        pass  # hostname is not an IP, that's fine
    return url


# ── LAN interface detection ──

_LAN_IFACE_CACHE: Optional[str] = None
_LAN_IFACE_LOCK = threading.Lock()
_LAN_IFACE_TTL = 300
_LAN_IFACE_TS: float = 0


def detect_lan_iface() -> str:
    """Auto-detect LAN bridge interface name (br-lan, br0, eth0, etc.)."""
    global _LAN_IFACE_CACHE, _LAN_IFACE_TS
    with _LAN_IFACE_LOCK:
        now = time.time()
        if _LAN_IFACE_CACHE and (now - _LAN_IFACE_TS) < _LAN_IFACE_TTL:
            return _LAN_IFACE_CACHE
        candidates = ["br-lan", "br0", "eth0", "lan0"]
        try:
            r = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                for name in candidates:
                    if f": {name}:" in line or f": {name}@" in line:
                        _LAN_IFACE_CACHE = name
                        _LAN_IFACE_TS = now
                        return name
        except Exception:
            pass
        _LAN_IFACE_CACHE = "br-lan"
        _LAN_IFACE_TS = now
        return "br-lan"


# ── IP helpers ──

def normalize_ipv4(value: Any) -> str:
    """Normalize an IPv4 address string; return '' for invalid/non-v4."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        ip_obj = ipaddress.ip_address(text)
        if ip_obj.version != 4:
            return ""
        return str(ip_obj)
    except Exception:
        return ""


def resolve_mac_to_ip() -> Dict[str, str]:
    """Resolve MAC -> IP from ARP table and DHCP leases."""
    mac_to_ip: Dict[str, str] = {}
    try:
        r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip_addr = parts[0]
                for i, p in enumerate(parts):
                    if p == "lladdr" and i + 1 < len(parts):
                        mac_to_ip[parts[i + 1].upper()] = ip_addr
    except Exception:
        pass
    for p in ("/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"):
        try:
            with open(p) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac_to_ip[parts[1].upper()] = parts[2]
        except Exception:
            pass
    try:
        import pathlib as _pl
        odhcpd_dir = _pl.Path("/tmp/hosts/odhcpd")
        if odhcpd_dir.is_dir():
            for fp in odhcpd_dir.iterdir():
                try:
                    for line in fp.read_text(errors="ignore").splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            mac_to_ip[parts[1].upper()] = parts[0]
                except Exception:
                    pass
    except Exception:
        pass
    return mac_to_ip


def resolve_device_ipv4(device: Dict[str, Any], mac_to_ip: Dict[str, str]) -> tuple:
    """Resolve a device's IPv4 address with priority: static > dynamic > cached."""
    static_ip = normalize_ipv4(device.get("ip"))
    if static_ip:
        return static_ip, "static"

    mac = str(device.get("mac", "")).upper()
    dynamic_ip = normalize_ipv4(mac_to_ip.get(mac))
    if dynamic_ip:
        return dynamic_ip, "dynamic"

    cached_ip = normalize_ipv4(device.get("last_ip"))
    if cached_ip:
        return cached_ip, "cached"

    return "", "unknown"


def refresh_device_ip_cache(state: Dict[str, Any], mac_to_ip: Optional[Dict[str, str]] = None) -> bool:
    """Update last_ip for all devices from ARP/DHCP. Returns True if any change."""
    changed = False
    if mac_to_ip is None:
        mac_to_ip = resolve_mac_to_ip()

    for d in state.get("devices", []):
        if "remark" not in d:
            d["remark"] = ""
            changed = True

        static_ip = normalize_ipv4(d.get("ip"))
        if d.get("ip", "") != static_ip:
            d["ip"] = static_ip
            changed = True

        mac = str(d.get("mac", "")).upper()
        dynamic_ip = normalize_ipv4(mac_to_ip.get(mac))
        wanted_last_ip = dynamic_ip or normalize_ipv4(d.get("last_ip"))
        if d.get("last_ip", "") != wanted_last_ip:
            d["last_ip"] = wanted_last_ip
            changed = True

    return changed


# ── Mark / table helpers ──

def mark_to_table(mark: int, marks_ordered: list) -> int:
    """Map a fwmark to a routing table number (deterministic, sequential from MARK_TABLE_BASE)."""
    try:
        idx = marks_ordered.index(mark)
    except ValueError:
        idx = mark - 0x100
    return MARK_TABLE_BASE + idx


def gen_id() -> str:
    """Generate a short random hex ID."""
    return secrets.token_hex(4)


def fmt_bytes(b: int) -> str:
    """Format a byte count into a human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


def split_ip_versions(values: List[Any]) -> tuple:
    """Split a list of IP address strings into (ipv4_list, ipv6_list)."""
    ipv4: List[str] = []
    ipv6: List[str] = []
    if not isinstance(values, list):
        values = [values]
    for raw in values:
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        try:
            ip_obj = ipaddress.ip_address(text)
            if ip_obj.version == 4:
                ipv4.append(text)
            else:
                ipv6.append(text)
        except Exception:
            continue
    return ipv4, ipv6


def panel_url() -> str:
    """Return the panel base URL."""
    return f"http://0.0.0.0:{LISTEN_PORT}"


# ── Logging / audit ──

_log_lock = threading.Lock()


def ensure_data_dir():
    """Ensure DATA_DIR exists."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def audit(action: str, detail: str = "", level: str = "info", component: str = "system") -> None:
    """Append a structured JSON audit log entry (thread-safe, with rotation)."""
    ensure_data_dir()
    entry = json.dumps({
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "component": component,
        "event": action,
        "message": detail,
    }, ensure_ascii=False)
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
        if LOG_FILE.stat().st_size > 500_000:
            lines = LOG_FILE.read_text("utf-8").splitlines()
            trimmed = "\n".join(lines[-MAX_LOG_LINES:]) + "\n"
            tmp_log = LOG_FILE.with_suffix(".tmp")
            tmp_log.write_text(trimmed, "utf-8")
            tmp_log.replace(LOG_FILE)
