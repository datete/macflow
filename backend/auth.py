"""MACFlow authentication – password hashing, sessions, rate limiting."""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Dict

from utils import DATA_DIR

# ── Config ──

AUTH_FILE = DATA_DIR / "auth.json"
SESSION_TTL = 86400 * 7  # 7 days
MAX_SESSIONS = 50
_PBKDF2_ITERATIONS = 260_000  # OWASP recommended minimum for SHA-256

# Rate limiting
_AUTH_RATE_WINDOW = 60
_AUTH_RATE_MAX = 5
_AUTH_LOCKOUT = 300

# Public paths / prefixes
PUBLIC_PATHS = frozenset({
    "/", "/captive", "/favicon.ico",
    "/api/auth/login", "/api/auth/status", "/api/auth/setup",
    "/api/captive/status", "/api/events",
})
PUBLIC_PREFIXES = ("/captive",)

# ── State ──

_sessions: Dict[str, Dict[str, Any]] = {}
_session_lock = threading.Lock()
_auth_attempts: Dict[str, list] = {}
_auth_attempts_lock = threading.Lock()
_auth_cache: Dict[str, Any] = {}
_auth_cache_mtime: float = 0
_auth_cache_lock = threading.Lock()


# ── Password helpers ──

def hash_password(password: str) -> str:
    """Hash password with PBKDF2-SHA256 + random salt."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), _PBKDF2_ITERATIONS).hex()
    return f"pbkdf2:{salt}:{h}"


def verify_password(password: str, stored: str) -> bool:
    """Verify password against stored hash. Supports PBKDF2 and SHA-256 legacy.

    Plain-text password storage is no longer supported for security reasons.
    If a plain-text password is detected, verification will fail and the
    admin must re-set the password via /api/auth/setup.
    """
    if stored.startswith("pbkdf2:"):
        _, salt, expected = stored.split(":", 2)
        h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), _PBKDF2_ITERATIONS).hex()
        return hmac.compare_digest(h, expected)
    if ":" not in stored:
        # Plain-text passwords are no longer accepted — force password reset
        return False
    salt, expected = stored.split(":", 1)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return hmac.compare_digest(h, expected)


# ── Auth file I/O ──

def load_auth() -> Dict[str, Any]:
    """Load auth config with file mtime caching (thread-safe)."""
    global _auth_cache, _auth_cache_mtime
    with _auth_cache_lock:
        try:
            if AUTH_FILE.exists():
                mt = AUTH_FILE.stat().st_mtime
                if mt != _auth_cache_mtime or not _auth_cache:
                    _auth_cache = json.loads(AUTH_FILE.read_text("utf-8"))
                    _auth_cache_mtime = mt
                return dict(_auth_cache)
        except Exception:
            pass
        return {"password_hash": "", "auth_enabled": False}


def save_auth(auth: Dict[str, Any]):
    """Atomically write auth config."""
    global _auth_cache, _auth_cache_mtime
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = AUTH_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(auth, indent=2, ensure_ascii=False), "utf-8")
    tmp.replace(AUTH_FILE)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass
    with _auth_cache_lock:
        _auth_cache = dict(auth)
        try:
            _auth_cache_mtime = AUTH_FILE.stat().st_mtime
        except Exception:
            _auth_cache_mtime = time.time()


# ── Rate limiting ──

def check_rate_limit(client_ip: str) -> bool:
    """Returns True if request is allowed, False if rate-limited."""
    with _auth_attempts_lock:
        now = time.time()
        cutoff = now - max(_AUTH_RATE_WINDOW, _AUTH_LOCKOUT)
        stale_ips = [ip for ip, ts in _auth_attempts.items()
                     if all(t < cutoff for t in ts)]
        for ip in stale_ips:
            del _auth_attempts[ip]
        attempts = _auth_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < max(_AUTH_RATE_WINDOW, _AUTH_LOCKOUT)]
        _auth_attempts[client_ip] = attempts
        recent = [t for t in attempts if now - t < _AUTH_RATE_WINDOW]
        if len(recent) >= _AUTH_RATE_MAX:
            return False
        return True


def record_auth_attempt(client_ip: str):
    """Record a failed auth attempt for rate limiting."""
    with _auth_attempts_lock:
        _auth_attempts.setdefault(client_ip, []).append(time.time())
        if len(_auth_attempts) > 100:
            now = time.time()
            cutoff = now - max(_AUTH_RATE_WINDOW, _AUTH_LOCKOUT)
            stale = [ip for ip, ts in _auth_attempts.items()
                     if ip != client_ip and all(t < cutoff for t in ts)]
            for ip in stale:
                del _auth_attempts[ip]


# ── Sessions ──

def create_session(client_ip: str = "") -> str:
    """Create a new session token."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _session_lock:
        _sessions[token] = {
            "created_at": now,
            "expires_at": now + SESSION_TTL,
            "ip": client_ip,
        }
        expired = [k for k, v in _sessions.items() if v["expires_at"] < now]
        for k in expired:
            del _sessions[k]
        if len(_sessions) > MAX_SESSIONS:
            oldest = sorted(_sessions.items(), key=lambda x: x[1]["created_at"])
            for k, _ in oldest[:len(_sessions) - MAX_SESSIONS]:
                del _sessions[k]
    return token


def validate_session(token: str) -> bool:
    """Check if a session token is valid."""
    if not token:
        return False
    with _session_lock:
        session = _sessions.get(token)
        if not session:
            return False
        if session["expires_at"] < time.time():
            _sessions.pop(token, None)
            return False
    return True


def is_path_public(path: str) -> bool:
    """Check if a path is publicly accessible without auth."""
    if path in PUBLIC_PATHS:
        return True
    for prefix in PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return True
    if path.endswith((".html", ".css", ".js", ".ico", ".svg", ".png", ".jpg", ".woff2")):
        return True
    return False


def cleanup_expired_sessions():
    """Remove expired sessions (called from probe_loop)."""
    now_ts = time.time()
    with _session_lock:
        expired_keys = [k for k, v in _sessions.items() if v.get("expires_at", 0) < now_ts]
        for k in expired_keys:
            del _sessions[k]


def clear_sessions():
    """Clear all sessions (used on auth disable)."""
    with _session_lock:
        _sessions.clear()


def delete_session(token: str):
    """Delete a specific session."""
    with _session_lock:
        _sessions.pop(token, None)
