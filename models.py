from datetime import datetime, time
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class EntityCreate(BaseModel):
    name: str
    entity_type: str = "user"
    department: Optional[str] = None
    email: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EntityUpdate(BaseModel):
    """Every field optional -- only what's sent gets changed. is_active is
    the "restrict" switch: setting it false blocks the entity from
    reporting any further events (existing history is untouched)."""
    name: Optional[str] = None
    department: Optional[str] = None
    email: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

    def as_field_dict(self) -> Dict[str, Any]:
        return self.model_dump(exclude_unset=True)


class EntityOut(BaseModel):
    id: int
    name: str
    entity_type: str
    department: Optional[str] = None
    email: Optional[str] = None
    is_active: bool
    created_at: datetime


class EventIn(BaseModel):
    entity_id: Optional[int] = None
    entity_name: Optional[str] = None   # used to look up/auto-create an entity when entity_id isn't known
    entity_type: str = "user"           # only used if auto-creating via entity_name
    event_type: str  # login, logoff, file_access, data_transfer, vpn_connect, privileged_logon, ...
    event_time: Optional[datetime] = None
    status: str = "success"  # success, fail
    source_ip: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    resource: Optional[str] = None
    bytes_transferred: int = 0
    file_count: Optional[int] = None    # number of files involved, for data_transfer/file_access events
    raw: Dict[str, Any] = Field(default_factory=dict)


class EventBatchIn(BaseModel):
    events: List[EventIn]


class AnomalyOut(BaseModel):
    id: int
    entity_id: int
    event_id: Optional[int]
    rule_name: str
    severity: str
    score: float
    description: Optional[str]
    details: Dict[str, Any]
    status: str
    detected_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]


class AnomalyStatusUpdate(BaseModel):
    status: str  # acknowledged, resolved, false_positive, open
    resolved_by: Optional[str] = None


class LoginRequest(BaseModel):
    username: str  # accepts either a username OR an email address
    password: str


class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str  # "admin", "analyst", or "employee"
    entity_name: Optional[str] = None  # required when role == "employee"


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    entity_id: Optional[int] = None
    entity_name: Optional[str] = None
    must_change_password: bool = False
    expires_at: datetime


class SignupResponse(BaseModel):
    """Distinct from LoginResponse because a self-registered analyst isn't
    logged in immediately -- their account exists but is pending admin
    approval, so there's no token yet."""
    pending_approval: bool
    message: str
    username: str
    role: str
    token: Optional[str] = None
    entity_id: Optional[int] = None
    entity_name: Optional[str] = None
    must_change_password: bool = False
    expires_at: Optional[datetime] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ResetAllPasswordsRequest(BaseModel):
    confirm: bool = False


class PasswordResetOut(BaseModel):
    username: Optional[str] = None
    reset_count: Optional[int] = None
    default_password: str


class PendingUserOut(BaseModel):
    username: str
    email: Optional[str] = None
    created_at: datetime


class UserOut(BaseModel):
    username: str
    email: Optional[str] = None
    role: str
    entity_id: Optional[int] = None
    entity_name: Optional[str] = None
    is_approved: bool
    must_change_password: bool = False
    created_at: datetime


class ConfigUpdate(BaseModel):
    """Every field is optional -- only the fields you send get changed.
    This is how thresholds and working hours get adjusted, either globally
    (PUT /config/default) or per-entity (PUT /config/{entity_id})."""
    timezone: Optional[str] = None
    work_start: Optional[time] = None
    work_end: Optional[time] = None
    work_days: Optional[List[int]] = None  # 0=Mon .. 6=Sun
    off_hours_enabled: Optional[bool] = None
    off_hours_low_hours: Optional[float] = None
    off_hours_medium_hours: Optional[float] = None
    off_hours_high_hours: Optional[float] = None
    off_hours_critical_hours: Optional[float] = None

    failed_login_enabled: Optional[bool] = None
    failed_login_low_threshold: Optional[int] = None
    failed_login_medium_threshold: Optional[int] = None
    failed_login_high_threshold: Optional[int] = None
    failed_login_critical_threshold: Optional[int] = None

    data_transfer_window_minutes: Optional[int] = None
    data_transfer_enabled: Optional[bool] = None
    data_transfer_low_mb: Optional[float] = None
    data_transfer_medium_mb: Optional[float] = None
    data_transfer_high_mb: Optional[float] = None
    data_transfer_critical_mb: Optional[float] = None

    social_media_block_enabled: Optional[bool] = None

    changed_by: Optional[str] = None

    def as_field_dict(self) -> Dict[str, Any]:
        data = self.model_dump(exclude_unset=True, exclude={"changed_by"})
        return data
