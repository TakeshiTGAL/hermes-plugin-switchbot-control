"""Command whitelist, safety types, and the daily-cap schedule floor."""
from __future__ import annotations

import re
from datetime import datetime, timedelta

DEVICE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
DAILY_CAP_LIMIT = 10_000
MIN_REPEAT_SECONDS = 120
DEFAULT_MAX_STATUS = 8
MAX_STATUS_HI = 20

DEFAULT_COMMANDS = frozenset({
    "turnOn",
    "turnOff",
    "press",
    "pause",
    "volumeAdd",
    "volumeSub",
    "channelAdd",
    "channelSub",
    "setMute",
    "FastForward",
    "Rewind",
    "Next",
    "Previous",
    "Pause",
    "Play",
    "Stop",
})
SAFETY_COMMANDS = frozenset({"lock", "unlock", "deadbolt"})
_SAFETY_TOKENS = frozenset({"lock", "keypad", "garage", "door"})
_POSITION = re.compile(r"^0,(0|1|ff),(\d{1,3})$")
_SET_ALL = re.compile(r"^(\d{1,2}),([0-5]),([1-4]),(on|off)$")
_CHANNEL = re.compile(r"^\d{1,4}$")

_MONTHS = {name: index for index, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1,
)}
_DOW = {name: index for index, name in enumerate(("sun", "mon", "tue", "wed", "thu", "fri", "sat"))}
_DURATION = re.compile(
    r"(\d*)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)\Z",
    re.IGNORECASE,
)
_DURATION_MINUTES = {"m": 1, "h": 60, "d": 1440}


def is_safety_type(device_type: str) -> bool:
    tokens = [part for part in re.split(r"[^a-z0-9]+", device_type.lower()) if part]
    for token in tokens:
        if token in _SAFETY_TOKENS or token.startswith("lock"):
            return True
    return False


def watch_kind(device_type: str) -> str | None:
    """Map an OpenAPI deviceType to a watch. Outdoor Meter is WoIOSensor."""
    text = device_type.lower().strip()
    if "meter" in text or text == "woiosensor":
        return "meter"
    if "contact" in text:
        return "contact"
    if "plug" in text:
        return "plug"
    return None


def curtain_position_allowed(device_type: str) -> bool:
    """setPosition is the Curtain and Curtain 3 form. 0 is open, 100 is closed."""
    return device_type in {"Curtain", "Curtain3"}


def prepare_command(command: str, parameter: str | None) -> tuple[str, str] | str:
    if command in DEFAULT_COMMANDS or command in SAFETY_COMMANDS:
        if parameter in {None, "", "default"}:
            return command, "default"
        return f"'{command}' only accepts parameter default. Nothing was sent."
    if command == "setPosition":
        match = _POSITION.fullmatch(parameter or "")
        if not match:
            return "setPosition expects 0,ff,0 through 0,ff,100 (mode 0, 1, or ff). Nothing was sent."
        position = int(match.group(2))
        if position > 100:
            return "setPosition only accepts a position from 0 to 100. Nothing was sent."
        return command, parameter or ""
    if command == "setAll":
        match = _SET_ALL.fullmatch(parameter or "")
        if not match:
            return "setAll expects temperature,mode,fan,power as in 26,1,3,on. Nothing was sent."
        if not 0 <= int(match.group(1)) <= 40:
            return (
                "setAll accepts a Celsius temperature from 0 to 40. "
                "The OpenAPI names the unit and does not publish that range. Nothing was sent."
            )
        return command, parameter or ""
    if command == "SetChannel":
        if not _CHANNEL.fullmatch(parameter or ""):
            return "SetChannel expects a channel number. Nothing was sent."
        return command, parameter or ""
    return (
        f"'{command}' is not in the command list. "
        "User-defined infrared buttons are not accepted. Nothing was sent."
    )


def calls_per_tick(max_status_reads: int) -> int:
    return 1 + max_status_reads


def min_gap_seconds(max_status_reads: int, daily_cap: int) -> int:
    calls = calls_per_tick(max_status_reads)
    needed = (86_400 * calls + daily_cap - 1) // daily_cap
    return max(MIN_REPEAT_SECONDS, needed)


def _duration_minutes(text: str) -> int | None:
    match = _DURATION.fullmatch(text.strip())
    if not match:
        return None
    number = int(match.group(1)) if match.group(1) else 1
    return number * _DURATION_MINUTES[match.group(2)[0].lower()]


def _cron_token(token: str, names: dict[str, int] | None) -> int | None:
    if token.isdigit():
        return int(token)
    if names is not None and token.lower() in names:
        return names[token.lower()]
    return None


def _cron_values(field: str, lo: int, hi: int, names: dict[str, int] | None = None) -> set[int] | None:
    values: set[int] = set()
    for part in field.split(","):
        step = 1
        chunk = part
        if "/" in part:
            chunk, raw_step = part.split("/", 1)
            if not raw_step.isdigit() or int(raw_step) < 1:
                return None
            step = int(raw_step)
        if chunk in {"*", ""}:
            start, end = lo, hi
        elif "-" in chunk:
            left, right = chunk.split("-", 1)
            start = _cron_token(left, names)
            end = _cron_token(right, names)
            if start is None or end is None or start > end or start < lo or end > hi:
                return None
        else:
            start = _cron_token(chunk, names)
            if start is None or start < lo or start > hi:
                return None
            end = start
        for number in range(start, end + 1, step):
            values.add(number)
    return values or None


def cron_min_gap_seconds(parts: list[str], floor: int) -> int | None:
    if len(parts) == 6:
        seconds = _cron_values(parts[0], 0, 59)
        if not seconds or len(seconds) != 1:
            return 0 if seconds else None
        fields = parts[1:]
    else:
        fields = parts
    minute = _cron_values(fields[0], 0, 59)
    hour = _cron_values(fields[1], 0, 23)
    day = _cron_values(fields[2], 1, 31)
    month = _cron_values(fields[3], 1, 12, _MONTHS)
    dow = _cron_values(fields[4], 0, 7, _DOW)
    if not all((minute, hour, day, month, dow)):
        return None
    assert minute and hour and day and month and dow
    if 7 in dow:
        dow = (dow - {7}) | {0}
    dom_star = fields[2] == "*"
    dow_star = fields[4] == "*"
    start = datetime(2024, 1, 1)
    every_month = month == set(range(1, 13))
    if dom_star and dow_star and every_month:
        window_days = 2
    elif dom_star and every_month:
        window_days = 14
    elif dow_star and every_month:
        window_days = 62
    else:
        window_days = 366
    end = start + timedelta(days=window_days)
    previous: datetime | None = None
    smallest: int | None = None
    cursor = start
    while cursor < end:
        cron_dow = (cursor.weekday() + 1) % 7
        if cursor.month in month and cursor.hour in hour and cursor.minute in minute:
            dom_ok = cursor.day in day
            dow_ok = cron_dow in dow
            if dom_star and dow_star:
                matched = True
            elif dom_star:
                matched = dow_ok
            elif dow_star:
                matched = dom_ok
            else:
                matched = dom_ok or dow_ok
            if matched:
                if previous is not None:
                    gap = int((cursor - previous).total_seconds())
                    if smallest is None or gap < smallest:
                        smallest = gap
                    if smallest < floor:
                        return smallest
                previous = cursor
        cursor += timedelta(minutes=1)
    return 366 * 24 * 3600 if smallest is None else smallest


def schedule_refusal(expr: str, floor_seconds: int) -> str | None:
    text = expr.strip()
    floor_minutes = (floor_seconds + 59) // 60
    prove = (
        f"This plugin could not prove that schedule waits at least {floor_seconds} seconds, "
        "so no job was created."
    )
    if not text:
        return "That schedule is empty, so no job was created."
    lower = text.lower()
    if lower.startswith("every "):
        minutes = _duration_minutes(text[6:])
        if minutes is None:
            return prove
        if minutes * 60 < floor_seconds:
            return f"That schedule is faster than every {floor_minutes} minutes, so no job was created."
        return None
    if lower.startswith("in "):
        if _duration_minutes(text[3:]) is None:
            return "This plugin could not prove that one-shot delay, so no job was created."
        return None
    minutes = _duration_minutes(text)
    if minutes is not None:
        if minutes * 60 < floor_seconds:
            return f"That schedule is faster than every {floor_minutes} minutes, so no job was created."
        return None
    if "T" in text or re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", text):
        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return "This plugin could not prove that timestamp, so no job was created."
        return None
    parts = text.split()
    if len(parts) in {5, 6} and all(re.fullmatch(r"[A-Za-z0-9*,/-]+", part) for part in parts):
        gap = cron_min_gap_seconds(parts, floor_seconds)
        if gap is None:
            return prove
        if gap < floor_seconds:
            return f"That schedule is faster than every {floor_minutes} minutes, so no job was created."
        return None
    return prove
