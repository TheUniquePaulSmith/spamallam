"""Per-user time-zone preference: the catalogue offered on the Users page and
the one helper every screen uses to render a stored UTC timestamp in the
viewer's chosen zone.

Timestamps are persisted everywhere as ISO-8601 UTC strings (see
``store.audit``, ``store.tracelog``, ``store.users`` …). ``friendly`` is the
single conversion point — templates get it injected as ``fmt_dt`` and the
dashboard summary passes the viewer's zone into ``tracelog.read_recent_summary``.

IANA zone names are used as the stored value so daylight-saving transitions are
handled automatically; the visible label carries the standard-time abbreviation
and offset the way a user expects to pick it ("Eastern Standard Time (EST)
UTC-5"). ``zoneinfo`` resolves the names from the bundled ``tzdata`` wheel
(the python:3.12-slim image ships no system zone database); anything that fails
to resolve degrades to UTC rather than breaking the page.
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TZ = "UTC"

# (IANA name, human label). Ordered roughly west -> east. The label is what the
# drop-down shows; the name is what we store and convert with.
TIMEZONES: list[tuple[str, str]] = [
    ("Pacific/Honolulu", "Hawaii-Aleutian Standard Time (HST) UTC-10"),
    ("America/Anchorage", "Alaska Standard Time (AKST) UTC-9"),
    ("America/Los_Angeles", "Pacific Standard Time (PST) UTC-8"),
    ("America/Phoenix", "Mountain Standard Time - Arizona, no DST (MST) UTC-7"),
    ("America/Denver", "Mountain Standard Time (MST) UTC-7"),
    ("America/Chicago", "Central Standard Time (CST) UTC-6"),
    ("America/New_York", "Eastern Standard Time (EST) UTC-5"),
    ("America/Halifax", "Atlantic Standard Time (AST) UTC-4"),
    ("America/Sao_Paulo", "Brasilia Time (BRT) UTC-3"),
    ("UTC", "Coordinated Universal Time (UTC) UTC+0"),
    ("Europe/London", "Greenwich Mean Time (GMT) UTC+0"),
    ("Europe/Paris", "Central European Time (CET) UTC+1"),
    ("Europe/Berlin", "Central European Time (CET) UTC+1"),
    ("Europe/Athens", "Eastern European Time (EET) UTC+2"),
    ("Europe/Moscow", "Moscow Standard Time (MSK) UTC+3"),
    ("Asia/Dubai", "Gulf Standard Time (GST) UTC+4"),
    ("Asia/Karachi", "Pakistan Standard Time (PKT) UTC+5"),
    ("Asia/Kolkata", "India Standard Time (IST) UTC+5:30"),
    ("Asia/Dhaka", "Bangladesh Standard Time (BST) UTC+6"),
    ("Asia/Bangkok", "Indochina Time (ICT) UTC+7"),
    ("Asia/Shanghai", "China Standard Time (CST) UTC+8"),
    ("Asia/Singapore", "Singapore Standard Time (SGT) UTC+8"),
    ("Asia/Tokyo", "Japan Standard Time (JST) UTC+9"),
    ("Australia/Sydney", "Australian Eastern Standard Time (AEST) UTC+10"),
    ("Pacific/Auckland", "New Zealand Standard Time (NZST) UTC+12"),
]

_VALID = {name for name, _ in TIMEZONES}


def is_valid(name: str) -> bool:
    return name in _VALID


def normalize(name: str | None) -> str:
    """Coerce a stored/submitted value to a known zone, falling back to UTC."""
    return name if name and name in _VALID else DEFAULT_TZ


def _parse(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    # Timestamps written without an offset are UTC by convention here.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def friendly(value: str, tz_name: str = DEFAULT_TZ, *, with_zone: bool = True) -> str:
    """Render an ISO-8601 timestamp string in ``tz_name``.

    Unparseable input is returned unchanged; an unknown/unavailable zone falls
    back to UTC. Format: ``Aug 30, 2026 14:05 EDT``.
    """
    dt = _parse(value)
    if dt is None:
        return value or ""
    try:
        tz = timezone.utc if tz_name == "UTC" else ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc
    local = dt.astimezone(tz)
    out = local.strftime("%b %d, %Y %H:%M")
    if with_zone:
        out += " " + (local.tzname() or tz_name)
    return out
