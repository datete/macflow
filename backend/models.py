"""MACFlow Pydantic request/response models."""
import urllib.parse
from typing import Dict, List, Optional

from pydantic import BaseModel, field_validator

from utils import _MAC_RE

# ── Max field lengths ──
_MAX_NAME = 256
_MAX_URL = 2048
_MAX_REMARK = 1024
_MAX_PASSWORD = 512
_MAX_TAG = 128
_MAX_SERVER = 256
_MAX_LINKS = 1024 * 1024  # 1MB of link text


def _check_length(v: str, field: str, max_len: int) -> str:
    if len(v) > max_len:
        raise ValueError(f'{field} must not exceed {max_len} characters')
    return v


# ── Source models ──

class SourceCreate(BaseModel):
    name: str
    base_url: str
    username: str
    password: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return _check_length(v.strip(), 'name', _MAX_NAME)

    @field_validator('base_url')
    @classmethod
    def validate_base_url(cls, v):
        v = _check_length(v.strip(), 'base_url', _MAX_URL)
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('base_url must use http or https scheme')
        if not parsed.hostname:
            raise ValueError('base_url missing hostname')
        return v.rstrip('/')

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        return _check_length(v, 'username', _MAX_NAME)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        return _check_length(v, 'password', _MAX_PASSWORD)


class SourceUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator('base_url')
    @classmethod
    def validate_base_url(cls, v):
        if v is None:
            return v
        v = _check_length(v.strip(), 'base_url', _MAX_URL)
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('base_url must use http or https scheme')
        if not parsed.hostname:
            raise ValueError('base_url missing hostname')
        return v.rstrip('/')

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return v
        return _check_length(v.strip(), 'name', _MAX_NAME)


# ── Node models ──

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

    @field_validator('server_port')
    @classmethod
    def validate_port_range(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('server_port must be between 1 and 65535')
        return v

    @field_validator('tag')
    @classmethod
    def validate_tag_length(cls, v):
        v = v.strip()
        if not v:
            raise ValueError('tag must not be empty')
        return _check_length(v, 'tag', _MAX_TAG)

    @field_validator('server')
    @classmethod
    def validate_server(cls, v):
        return _check_length(v.strip(), 'server', _MAX_SERVER)

    transport: Optional[Dict] = None
    tls: Optional[Dict] = None


class LinkImport(BaseModel):
    links: str

    @field_validator('links')
    @classmethod
    def validate_links_length(cls, v):
        return _check_length(v, 'links', _MAX_LINKS)


# ── Subscription models ──

class SubCreate(BaseModel):
    name: str
    url: str
    headers: Optional[Dict[str, str]] = None

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return _check_length(v.strip(), 'name', _MAX_NAME)

    @field_validator('url')
    @classmethod
    def validate_url_scheme(cls, v):
        v = _check_length(v.strip(), 'url', _MAX_URL)
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Subscription URL must use http or https scheme')
        return v


# ── Device models ──

class DeviceCreate(BaseModel):
    name: str
    mac: str
    node_tag: Optional[str] = "direct"
    managed: bool = True
    remark: Optional[str] = None
    ip: Optional[str] = None

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return _check_length(v.strip(), 'name', _MAX_NAME)

    @field_validator('mac')
    @classmethod
    def validate_mac_format(cls, v):
        v = v.strip().upper()
        if not _MAC_RE.match(v):
            raise ValueError(f'Invalid MAC address format: {v}')
        return v

    @field_validator('remark')
    @classmethod
    def validate_remark(cls, v):
        if v is None:
            return v
        return _check_length(v, 'remark', _MAX_REMARK)


class DeviceBatch(BaseModel):
    devices: List[DeviceCreate]


class NodeBatchAction(BaseModel):
    tags: List[str]
    action: str  # "delete" | "enable" | "disable"

    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        if v not in ('delete', 'enable', 'disable'):
            raise ValueError("action must be 'delete', 'enable', or 'disable'")
        return v


class DeviceNodeUpdate(BaseModel):
    node_tag: str

    @field_validator('node_tag')
    @classmethod
    def validate_node_tag(cls, v):
        return _check_length(v.strip(), 'node_tag', _MAX_TAG)


class DeviceRemarkUpdate(BaseModel):
    remark: str

    @field_validator('remark')
    @classmethod
    def validate_remark(cls, v):
        return _check_length(v, 'remark', _MAX_REMARK)


class DeviceIpUpdate(BaseModel):
    ip: Optional[str] = None


# ── Settings models ──

class SettingsUpdate(BaseModel):
    default_policy: Optional[str] = None
    failure_policy: Optional[str] = None
    dns: Optional[Dict] = None

    @field_validator('default_policy')
    @classmethod
    def validate_default_policy(cls, v):
        if v is not None and v not in ('whitelist', 'blacklist'):
            raise ValueError("default_policy must be 'whitelist' or 'blacklist'")
        return v

    @field_validator('failure_policy')
    @classmethod
    def validate_failure_policy(cls, v):
        if v is not None and v not in ('fail-close', 'fail-open'):
            raise ValueError("failure_policy must be 'fail-close' or 'fail-open'")
        return v


class ToggleReq(BaseModel):
    enabled: bool


# ── Auth models ──

class LoginRequest(BaseModel):
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        return _check_length(v, 'password', _MAX_PASSWORD)


class SetPasswordRequest(BaseModel):
    password: str
    new_password: str = ""

    @field_validator('password', 'new_password')
    @classmethod
    def validate_password(cls, v):
        return _check_length(v, 'password', _MAX_PASSWORD)
