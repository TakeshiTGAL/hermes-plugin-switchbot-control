"""List, approved commands, and a watch that does not send commands."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .client import ApiError, SwitchBot, redact
    from .policy import (
        DAILY_CAP_LIMIT,
        DEFAULT_MAX_STATUS,
        DEVICE_ID,
        MAX_STATUS_HI,
        SAFETY_COMMANDS,
        calls_per_tick,
        curtain_motion,
        curtain_position_allowed,
        deliver_looks_like_schedule,
        is_safety_type,
        min_gap_seconds,
        prepare_command,
        schedule_refusal,
        watch_kind,
    )
    from .safety import command_block_reason, plugin_data_dir, request_command_approval
else:
    from client import ApiError, SwitchBot, redact
    from policy import (
        DAILY_CAP_LIMIT,
        DEFAULT_MAX_STATUS,
        DEVICE_ID,
        MAX_STATUS_HI,
        SAFETY_COMMANDS,
        calls_per_tick,
        curtain_motion,
        curtain_position_allowed,
        deliver_looks_like_schedule,
        is_safety_type,
        min_gap_seconds,
        prepare_command,
        schedule_refusal,
        watch_kind,
    )
    from safety import command_block_reason, plugin_data_dir, request_command_approval

TOOLSET = "switchbot_control"
JOB_NAME = "switchbot-control"
DEFAULT_SCHEDULE = "*/5 * * * *"
CRON_PROMPT = (
    "Call the switchbot_watch tool with no arguments. "
    "Do not call switchbot_command. Do not turn devices on or off, press a bot, move a curtain, or lock or unlock anything. "
    "If the tool result has notify true, reply with its message field and nothing else. "
    "If notify is false, reply with NO_REPLY."
)
_READING_KEYS = ("temperature", "humidity", "openState", "power", "weight", "electricCurrent", "voltage")
FAILURE_REMIND_SECONDS = 24 * 3600
_PROFILE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def _profile_name() -> str:
    """Active Hermes profile.

    ``default`` when unset or ``~/.hermes``. A home shaped as ``<root>/profiles/<name>``
    uses that directory name even when the root is not ``~/.hermes`` (``hermes -p``
    only rewrites ``HERMES_HOME``). Any other home is ``custom``.
    """
    for key in ("HERMES_PROFILE_NAME", "HERMES_PROFILE"):
        value = os.environ.get(key, "").strip()
        if value and set(value) <= _PROFILE_CHARS:
            return value
    home = os.environ.get("HERMES_HOME", "").strip()
    if not home:
        return "default"
    try:
        path = Path(home).expanduser().resolve()
        default_home = (Path.home() / ".hermes").resolve()
    except OSError:
        return "default"
    if path == default_home:
        return "default"
    if path.parent.name == "profiles" and set(path.name) <= _PROFILE_CHARS and not path.name.startswith("."):
        return path.name
    return "custom"


def hermes_cron(verb: str) -> str:
    """``hermes cron <verb>``, with ``-p <name>`` when the profile is not default."""
    name = _profile_name()
    if name and name != "default":
        return f"hermes -p {name} cron {verb}"
    return f"hermes cron {verb}"


@dataclass
class Deps:
    token: str
    secret: str
    data_dir: Path | None = None
    safety_devices: bool = False
    daily_cap: int = DAILY_CAP_LIMIT
    warn_remaining: int = 1000
    max_status_reads: int = DEFAULT_MAX_STATUS
    temperature_high_c: float | None = None
    temperature_low_c: float | None = None
    humidity_high_pct: float | None = None
    plug_weight_watts: float | None = None
    config_problem: str = ""
    now: Callable[[], float] = time.time
    transport: Any = None
    approver: Callable[[str, str], tuple[bool, str]] | None = None
    cron_module: Any = None


def dumps(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def fail(code: str, message: str, next_step: str, **extra: Any) -> str:
    body = {"ok": False, "error": code, "message": message, "next_step": next_step, "moved": False}
    body.update(extra)
    return dumps(body)


def _shown(deps: Deps, text: str) -> str:
    return redact(text, deps.token, deps.secret)


def _clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(lo, min(hi, value))


def _optional_number(value: Any, label: str) -> tuple[float | None, str]:
    if value is None:
        return None, ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, ""
        try:
            return float(text), ""
        except ValueError:
            return None, f"{label} is not a number, so no API call was made."
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, f"{label} is not a number, so no API call was made."
    return float(value), ""


def deps_from_config(get_config: Callable[[str, Any], Any], *, token: str, secret: str, **kw: Any) -> Deps:
    try:
        data = plugin_data_dir()
    except Exception:
        data = None
    parsed = [
        _optional_number(get_config("temperature_high_c", ""), "temperature_high_c"),
        _optional_number(get_config("temperature_low_c", ""), "temperature_low_c"),
        _optional_number(get_config("humidity_high_pct", ""), "humidity_high_pct"),
        _optional_number(get_config("plug_weight_watts", ""), "plug_weight_watts"),
    ]
    problems = [problem for _value, problem in parsed if problem]
    return Deps(
        token=token,
        secret=secret,
        data_dir=data,
        safety_devices=get_config("safety_devices", False) is True,
        daily_cap=_clamp_int(get_config("daily_cap", DAILY_CAP_LIMIT), DAILY_CAP_LIMIT, 1, DAILY_CAP_LIMIT),
        warn_remaining=_clamp_int(get_config("warn_remaining", 1000), 1000, 0, DAILY_CAP_LIMIT),
        max_status_reads=_clamp_int(get_config("max_status_reads", DEFAULT_MAX_STATUS), DEFAULT_MAX_STATUS, 1, MAX_STATUS_HI),
        temperature_high_c=parsed[0][0],
        temperature_low_c=parsed[1][0],
        humidity_high_pct=parsed[2][0],
        plug_weight_watts=parsed[3][0],
        config_problem=" ".join(problems),
        **kw,
    )


def _unexpected(args: dict, allowed: set[str]) -> str | None:
    extra = sorted(set(args) - allowed)
    if extra:
        return fail("bad_args", f"Unexpected arguments: {', '.join(extra)}.", "Remove those arguments and try again.")
    return None


def _client(deps: Deps) -> SwitchBot:
    if not deps.token.strip() or not deps.secret.strip():
        raise ApiError(
            "missing_key",
            "SWITCHBOT_TOKEN and SWITCHBOT_SECRET are not both set.",
            next_step="Set both environment variables. No API call was made.",
        )
    return SwitchBot(deps.token, deps.secret, deps.transport, deps.now)


def _usage_path(deps: Deps) -> Path:
    if deps.data_dir is None:
        raise ApiError(
            "no_data_dir",
            "Plugin data is not available, so no API call was made.",
            next_step="The daily counter has to be written before a call. Fix plugin data and try again.",
        )
    return deps.data_dir / "usage.json"


def _utc_day(deps: Deps) -> str:
    return datetime.fromtimestamp(deps.now(), timezone.utc).date().isoformat()


def _read_usage(deps: Deps) -> dict:
    path = _usage_path(deps)
    if not path.exists():
        return {"utc_date": _utc_day(deps), "count": 0, "warned": False}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ApiError(
            "bad_usage",
            "The daily counter could not be read, so no API call was made.",
            next_step="Leave usage.json in place or remove that file, then try again. The cap was not bypassed.",
        ) from None
    if not isinstance(loaded, dict):
        raise ApiError("bad_usage", "The daily counter is not a count, so no API call was made.", next_step="Replace usage.json with a JSON object that has an integer count, or delete it.")
    count = loaded.get("count")
    if isinstance(count, bool) or not isinstance(count, int):
        raise ApiError("bad_usage", "The daily counter is not a count, so no API call was made.", next_step="Replace usage.json with a JSON object that has an integer count, or delete it.")
    if loaded.get("utc_date") != _utc_day(deps):
        return {"utc_date": _utc_day(deps), "count": 0, "warned": False}
    loaded["warned"] = loaded.get("warned") is True
    return loaded


def _write_usage(deps: Deps, usage: dict) -> None:
    path = _usage_path(deps)
    tmp = path.with_name("usage.json.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(usage), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        raise ApiError(
            "bad_usage",
            "The daily counter could not be written, so no API call was made.",
            next_step="Fix permissions on the plugin data directory and try again.",
        ) from None


def _call(deps: Deps, method: str, path: str, body: dict | None = None) -> dict:
    client = _client(deps)
    usage = _read_usage(deps)
    if usage["count"] >= deps.daily_cap:
        raise ApiError(
            "daily_cap",
            f"The UTC-day counter is {usage['count']}, which is the cap of {deps.daily_cap}.",
            next_step="No further API call was made today. The counter resets on the next UTC date.",
        )
    usage["count"] += 1
    _write_usage(deps, usage)
    return client.request(method, path, body)


def _near_cap(deps: Deps) -> str | None:
    usage = _read_usage(deps)
    remaining = deps.daily_cap - usage["count"]
    if remaining > deps.warn_remaining:
        return None
    if usage.get("warned") is True:
        return None
    usage["warned"] = True
    _write_usage(deps, usage)
    return f"Approaching the daily cap: {remaining} calls left out of {deps.daily_cap} on this UTC date."


def _public(deps: Deps, payload: dict) -> str:
    text = dumps(payload)
    return redact(text, deps.token, deps.secret)


def _summary_item(item: dict) -> dict:
    return {
        "deviceId": item.get("deviceId"),
        "deviceType": item.get("deviceType") or item.get("remoteType"),
        "deviceName": item.get("deviceName"),
        "remote": "remoteType" in item and "deviceType" not in item,
    }


def _configured(deps: Deps) -> str | None:
    if deps.config_problem:
        return fail("bad_config", deps.config_problem, "Fix the plugin config. No API call was made.")
    return None


def devices(deps: Deps, args: dict) -> str:
    bad = _unexpected(args or {}, {"device_id"}) or _configured(deps)
    if bad:
        return bad
    device_id = (args or {}).get("device_id")
    if device_id is not None and (not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id)):
        return fail("bad_device", "device_id must be letters, digits, and hyphens, at most 64 characters.", "Use an id from the account list. No API call was made.")
    try:
        listed = _call(deps, "GET", "/v1.1/devices")
        body = listed.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("deviceList"), list) or not isinstance(body.get("infraredRemoteList"), list):
            return fail("bad_list", "The list response did not contain both device lists.", "Nothing was reported as an inventory.")
        inventory = [_summary_item(item) for item in body["deviceList"] if isinstance(item, dict)]
        remotes = [_summary_item(item) for item in body["infraredRemoteList"] if isinstance(item, dict)]
        status = None
        if device_id:
            status_body = _call(deps, "GET", f"/v1.1/devices/{device_id}/status").get("body")
            if not isinstance(status_body, dict) or not status_body:
                return _shown(deps, fail(
                    "empty_status",
                    "The API returned statusCode 100 with an empty body, so this plugin does not report a device state.",
                    "Confirm the device id. An unknown id did this on the live API.",
                    devices=inventory,
                    infrared_remotes=remotes,
                ))
            status = {key: status_body.get(key) for key in ("deviceId", "deviceType", *_READING_KEYS) if key in status_body}
        warning = _near_cap(deps)
    except ApiError as exc:
        return _shown(deps, fail(exc.code, exc.message, exc.next_step))
    payload = {
        "ok": True,
        "moved": False,
        "devices": inventory,
        "infrared_remotes": remotes,
        "device_count": len(inventory),
        "infrared_count": len(remotes),
        "status": status,
        "calls_today": _read_usage(deps)["count"],
        "daily_cap": deps.daily_cap,
    }
    if warning:
        payload["notify"] = True
        payload["message"] = warning
    return _public(deps, payload)


def _find(listed: dict, device_id: str) -> dict | None:
    body = listed.get("body")
    if not isinstance(body, dict):
        return None
    for key in ("deviceList", "infraredRemoteList"):
        rows = body.get(key)
        if not isinstance(rows, list):
            continue
        for item in rows:
            if isinstance(item, dict) and item.get("deviceId") == device_id:
                return item
    return None


def command(deps: Deps, args: dict) -> str:
    bad = _unexpected(args or {}, {"device_id", "command", "parameter"}) or _configured(deps)
    if bad:
        return bad
    device_id = (args or {}).get("device_id")
    name = (args or {}).get("command")
    parameter = (args or {}).get("parameter")
    if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
        return fail("bad_device", "device_id must be letters, digits, and hyphens, at most 64 characters.", "No API call was made.")
    if not isinstance(name, str):
        return fail("bad_command", "command must be a string from the command list.", "No API call was made.")
    if parameter is not None and not isinstance(parameter, str):
        return fail("bad_command", "parameter must be a string.", "No API call was made.")
    prepared = prepare_command(name, parameter)
    if isinstance(prepared, str):
        return fail("bad_command", prepared, "No API call was made.")
    command_name, command_parameter = prepared
    if command_name in SAFETY_COMMANDS and not deps.safety_devices:
        return fail(
            "safety_off",
            f"'{command_name}' is a lock or door command, and safety_devices is off.",
            "Leave it off unless you intend to allow it. Even then, each command asks for approval, and a previous always or session choice does not cover the next call. Nothing was sent.",
        )
    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        return fail(
            "host_isolation",
            "Commands are refused while HERMES_PLUGIN_HOST_PROCESS is 1. Nothing was sent.",
            "Set plugins.isolation to in_process. A watch in this process also fails, because the cron mark is not visible. No API call was made.",
        )
    if deps.approver is None:
        blocked = command_block_reason(device_id, command_name)
        if blocked:
            return fail("not_approved", blocked, "No API call was made.")
    try:
        listed = _call(deps, "GET", "/v1.1/devices")
    except ApiError as exc:
        return _shown(deps, fail(exc.code, exc.message, exc.next_step))
    item = _find(listed, device_id)
    if item is None:
        return fail(
            "unknown_device",
            "That device id is not in the account list, so no command was sent.",
            "List the devices and use one of those ids. The command POST was not made.",
        )
    device_type = str(item.get("deviceType") or item.get("remoteType") or "")
    device_name = str(item.get("deviceName") or "unnamed")
    if command_name == "setPosition" and not curtain_position_allowed(device_type):
        return fail(
            "bad_command",
            f"setPosition is sent only for Curtain and Curtain3. This device is {device_type or 'unknown'}. Nothing was sent.",
            "Blind Tilt and Roller Shade are refused. No command POST was made.",
        )
    if is_safety_type(device_type) and not deps.safety_devices:
        return fail(
            "safety_off",
            f"'{device_type}' is a lock, keypad, garage, or door, and safety_devices is off.",
            "No command was sent. Enabling the flag still asks for approval every time, and a previous always or session choice does not cover the next call.",
        )
    if deps.approver is not None:
        approved, why = deps.approver(device_id, command_name)
    else:
        approved, why = request_command_approval(
            device_id,
            command_name,
            device_name=device_name,
            device_type=device_type,
            parameter=command_parameter,
            effect=curtain_motion(device_type, command_name, command_parameter),
        )
    if not approved:
        extra: dict[str, Any] = {}
        if why.startswith("BLOCKED: the approval question would be cut off"):
            extra["retryable"] = False
        return fail("not_approved", why or "The command was not approved.", "No command POST was made.", **extra)
    try:
        result = _call(
            deps,
            "POST",
            f"/v1.1/devices/{device_id}/commands",
            {"command": command_name, "parameter": command_parameter, "commandType": "command"},
        )
    except ApiError as exc:
        return _shown(deps, fail(exc.code, exc.message, exc.next_step))
    try:
        warning = _near_cap(deps)
    except ApiError:
        return _public(deps, {
            "ok": True,
            "moved": False,
            "accepted": True,
            "device_id": device_id,
            "device_type": device_type,
            "command": command_name,
            "statusCode": result.get("statusCode"),
            "message": (
                "The API accepted the command (HTTP 200, statusCode 100, message success). "
                "The daily counter could not be updated after that POST. "
                "The command may have reached the device."
            ),
            "notify": False,
        })
    message = (
        "The API accepted the command (HTTP 200, statusCode 100, message success). "
        "This plugin did not read the device afterward, so it does not claim the device moved."
    )
    if warning:
        message = warning + " " + message
    return _public(deps, {
        "ok": True,
        "moved": False,
        "accepted": True,
        "device_id": device_id,
        "device_type": device_type,
        "command": command_name,
        "statusCode": result.get("statusCode"),
        "message": message,
        "notify": bool(warning),
    })


def _reading(device_type: str, body: dict) -> dict:
    row = {"deviceType": device_type}
    for key in _READING_KEYS:
        if key in body and not isinstance(body[key], (dict, list)):
            row[key] = body[key]
    return row


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _alerts(previous: dict | None, current: dict, deps: Deps) -> list[str]:
    notes: list[str] = []
    kind = watch_kind(str(current.get("deviceType") or ""))
    if kind == "meter":
        checks = (
            ("temperature", deps.temperature_high_c, "at or above", True),
            ("temperature", deps.temperature_low_c, "at or below", False),
            ("humidity", deps.humidity_high_pct, "at or above", True),
        )
        for field, limit, word, high in checks:
            if limit is None:
                continue
            now = _number(current.get(field))
            if now is None:
                continue
            crossed = now >= limit if high else now <= limit
            before = _number((previous or {}).get(field))
            already = before is not None and (before >= limit if high else before <= limit)
            if crossed and not already:
                notes.append(f"{field} is {now}, {word} {limit}")
    elif kind == "contact" and previous is not None:
        old = previous.get("openState")
        new = current.get("openState")
        if isinstance(old, str) and isinstance(new, str) and old != new:
            notes.append(f"openState changed from {old} to {new}")
    elif kind == "plug":
        if previous is not None:
            old = previous.get("power")
            new = current.get("power")
            if isinstance(old, str) and isinstance(new, str) and old != new:
                notes.append(f"power changed from {old} to {new}")
        if deps.plug_weight_watts is not None:
            now = _number(current.get("weight"))
            before = _number((previous or {}).get("weight"))
            if now is not None and now >= deps.plug_weight_watts and not (before is not None and before >= deps.plug_weight_watts):
                notes.append(f"weight is {now}, at or above {deps.plug_weight_watts}")
    return notes


def _watch_fail_path(deps: Deps) -> Path | None:
    if deps.data_dir is None:
        return None
    return deps.data_dir / "watch_fail.json"


def _count(loaded: dict, key: str) -> int:
    value = loaded.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _read_watch_counts(deps: Deps) -> tuple[int, int]:
    loaded = _read_watch_fail(deps)
    return _count(loaded, "streak"), _count(loaded, "empty")


def _read_watch_fail(deps: Deps) -> dict:
    path = _watch_fail_path(deps)
    if path is None or not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _write_watch_counts(deps: Deps, streak: int, empty: int, notified_at: float | None = None) -> None:
    path = _watch_fail_path(deps)
    if path is None:
        return
    row: dict[str, Any] = {"streak": streak, "empty": empty}
    if notified_at is not None:
        row["notified_at"] = notified_at
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name("watch_fail.json.tmp")
        tmp.write_text(json.dumps(row), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return


def _notify_watch_failure(deps: Deps, payload: str, *, advance: bool = True) -> str:
    try:
        body = json.loads(payload)
    except json.JSONDecodeError:
        body = {"ok": False, "moved": False, "message": payload}
    if not isinstance(body, dict):
        body = {"ok": False, "moved": False, "message": payload}
    loaded = _read_watch_fail(deps)
    streak = _count(loaded, "streak")
    now = deps.now()
    last = loaded.get("notified_at")
    if isinstance(last, bool) or not isinstance(last, (int, float)):
        last = None
    # A streak stays quiet for 24 hours after its last notice, then notifies again.
    # A missing time, or one in the future, notifies now.
    if not advance:
        body["notify"] = True
        text = str(body.get("message") or "")
        body["message"] = (
            text
            + " This check did not update the cron failure record, so the owner's next cron run can still report it."
            + " This plugin cannot tell whether Hermes delivered a notice."
        )
        return _public(deps, body)
    notify = streak == 0 or last is None or not 0 <= now - last < FAILURE_REMIND_SECONDS
    body["notify"] = notify
    text = str(body.get("message") or "")
    body["message"] = (
        text
        + " This plugin cannot tell whether Hermes delivered a notice."
        + " If one was not delivered, the streak stays quiet until the next 24-hour notice."
        + f" {hermes_cron('list')} shows a run whose result was not delivered."
    )
    _write_watch_counts(deps, streak + 1, 0, now if notify else last)
    return _public(deps, body)


def _is_cron_turn() -> bool:
    """True only when Hermes says this turn is cron. A missing helper does not count as cron."""
    try:
        from tools.approval_context import _is_cron_approval_context
    except Exception:
        return False
    try:
        return _is_cron_approval_context() is True
    except Exception:
        return False


def watch(deps: Deps, args: dict, *, advance: bool = True) -> str:
    unexpected = _unexpected(args or {}, set())
    if unexpected:
        return unexpected
    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        return fail(
            "plugin_host",
            "plugins.isolation is host, so this process cannot see Hermes's cron mark. "
            "This check cannot watch devices in this shape. "
            "This check did not report the devices as unchanged and did not update the cron watch.",
            "Set plugins.isolation to in_process. The cron watch does not run in the plugin host.",
            notify=True,
        )
    bad = _configured(deps)
    if bad:
        return _notify_watch_failure(deps, bad, advance=advance)
    try:
        listed = _call(deps, "GET", "/v1.1/devices")
        body = listed.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("deviceList"), list):
            return _notify_watch_failure(
                deps,
                fail("bad_list", "The list response did not contain deviceList.", "No status call was made."),
            )
        chosen = []
        for item in body["deviceList"]:
            if not isinstance(item, dict):
                continue
            device_type = str(item.get("deviceType") or "")
            device_id = item.get("deviceId")
            if watch_kind(device_type) and isinstance(device_id, str) and DEVICE_ID.fullmatch(device_id):
                chosen.append((device_id, device_type))
        chosen.sort()
        skipped = max(0, len(chosen) - deps.max_status_reads)
        chosen = chosen[: deps.max_status_reads]
        path = None if deps.data_dir is None else deps.data_dir / "watch.json"
        previous: dict = {}
        previous_faults: dict = {}
        previous_list_gap = False
        previous_bad = False
        if path is not None and path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("devices"), dict):
                    previous = loaded["devices"]
                    if isinstance(loaded.get("faults"), dict):
                        previous_faults = {
                            key: value for key, value in loaded["faults"].items() if isinstance(key, str)
                        }
                    previous_list_gap = loaded.get("list_gap") is True
                else:
                    previous_bad = True
            except (OSError, json.JSONDecodeError):
                previous_bad = True
        readings: dict[str, dict] = {}
        faults: dict[str, int | str] = {}
        alert_notes: list[str] = []
        quiet_notes: list[str] = []
        numeric_power_changed = False
        if previous_bad:
            alert_notes.append(
                "watch.json could not be read, so this tick does not say that nothing changed. "
                "New readings are stored as the baseline."
            )
        for device_id, device_type in chosen:
            remaining = deps.daily_cap - _read_usage(deps)["count"]
            if remaining < 1:
                alert_notes.append(f"Stopped before {device_id}: the daily cap has no calls left.")
                break
            try:
                status_body = _call(deps, "GET", f"/v1.1/devices/{device_id}/status").get("body")
            except ApiError as exc:
                if exc.code != "api_error" or not isinstance(exc.status_code, int) or isinstance(exc.status_code, bool):
                    raise
                if exc.status_code == 161:
                    note = f"{device_id} is offline (statusCode 161). It was not stored."
                elif exc.status_code == 171:
                    note = f"{device_id} hub is offline (statusCode 171). It was not stored."
                else:
                    note = f"{device_id} status failed (statusCode {exc.status_code}). It was not stored."
                faults[device_id] = exc.status_code
                if previous_faults.get(device_id) == exc.status_code:
                    quiet_notes.append(note)
                else:
                    alert_notes.append(note)
                continue
            if not isinstance(status_body, dict) or not status_body:
                note = f"{device_id} returned an empty status body, so it was not stored as a reading."
                faults[device_id] = "empty"
                if previous_faults.get(device_id) == "empty":
                    quiet_notes.append(note)
                else:
                    alert_notes.append(note)
                continue
            current = _reading(device_type, status_body)
            prior = None if previous_bad or not isinstance(previous.get(device_id), dict) else previous.get(device_id)
            if prior is not None and watch_kind(device_type) == "plug":
                old_power, new_power = prior.get("power"), current.get("power")
                old_number, new_number = _number(old_power), _number(new_power)
                if (
                    old_number is not None
                    and new_number is not None
                    and not isinstance(old_power, str)
                    and not isinstance(new_power, str)
                    and old_number != new_number
                ):
                    numeric_power_changed = True
            alert_notes.extend(f"{device_id}: {note}" for note in _alerts(prior, current, deps))
            readings[device_id] = current
        if path is not None and advance:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                stored = {} if previous_bad else dict(previous)
                stored.update(readings)
                if len(stored) > 200:
                    kept = dict(readings)
                    for key, value in stored.items():
                        if len(kept) >= 200:
                            break
                        kept.setdefault(key, value)
                    stored = kept
                payload = {"devices": stored, "faults": faults}
                if not chosen and previous and not previous_bad:
                    payload["list_gap"] = True
                path.write_text(json.dumps(payload), encoding="utf-8")
            except OSError:
                alert_notes.append("The readings could not be written to watch.json.")
        warning = _near_cap(deps)
    except ApiError as exc:
        return _notify_watch_failure(deps, _shown(deps, fail(exc.code, exc.message, exc.next_step)), advance=advance)
    if not chosen and previous and not previous_bad:
        gap_note = (
            f"The device list has no meter, contact sensor, or plug. "
            f"The previous watch file still has {len(previous)} device row(s). "
            "This is not a normal empty account."
        )
        if previous_list_gap:
            quiet_notes.append(gap_note)
        else:
            alert_notes.append(gap_note)
    notes = alert_notes + quiet_notes
    empty_notice = False
    if not chosen and not notes:
        _streak, empty_count = _read_watch_counts(deps)
        empty_notice = empty_count == 0
        if advance:
            _write_watch_counts(deps, 0, empty_count + 1)
        if empty_notice:
            message = (
                "No meter, contact sensor, or plug was in the device list. "
                "An empty list can also mean Cloud Services is off. "
                "This notice is sent once for this empty stretch. "
                "Later quiet ticks are not a healthy watch."
            )
        else:
            message = (
                "No meter, contact sensor, or plug was in the device list. "
                "An empty list can also mean Cloud Services is off. "
                "This empty stretch was already announced. "
                "A quiet tick is not a healthy watch."
            )
    elif notes:
        if advance:
            _write_watch_counts(deps, 0, 0)
        message = " ".join(notes)
    else:
        if advance:
            _write_watch_counts(deps, 0, 0)
        verb = "Stored" if advance else "Read"
        if numeric_power_changed:
            message = (
                "A numeric power field is not compared. "
                f"{verb} {len(readings)} readings. No meter threshold or contact openState change was reported. "
                "Plug Mini on/off is not watched."
            )
        else:
            message = (
                f"{verb} {len(readings)} readings. No meter threshold, contact openState change, "
                "or plain Plug on/off string change. A numeric power field is not compared. "
                "Plug Mini on/off is not watched."
            )
    if skipped:
        message += f" {skipped} matching devices were not read because max_status_reads is {deps.max_status_reads}."
    if warning:
        message = warning + " " + message
    if not advance and (alert_notes or empty_notice):
        message += " This check did not update the cron watch, so the owner's next cron run can still report it."
    return _public(deps, {
        "ok": True,
        "moved": False,
        "notify": bool(alert_notes or warning or empty_notice),
        "message": message,
        "readings": len(readings),
        "calls_today": _read_usage(deps)["count"],
    })


def _cron(deps: Deps):
    if deps.cron_module is not None:
        return deps.cron_module
    try:
        from cron import jobs
        return jobs
    except Exception as exc:
        raise ApiError(
            "no_cron",
            f"Hermes cron is not available ({type(exc).__name__}).",
            next_step=(
                f"Create the job with {hermes_cron('create')}. "
                "Point the prompt at switchbot_watch only. The toolset still includes switchbot_command, and cron cannot send it. "
                "No faster than the cap allows."
            ),
        ) from None


def slash_schedule_args(parts: list[str], default: str = DEFAULT_SCHEDULE) -> tuple[str, str]:
    deliver = parts[1] if len(parts) > 1 else ""
    when = " ".join(parts[2:]) if len(parts) > 2 else default
    return when, deliver


_DELIVER_PLATFORMS = frozenset({
    "telegram", "discord", "slack", "whatsapp", "signal",
    "matrix", "mattermost", "homeassistant", "dingtalk", "feishu",
    "wecom", "wecom_callback", "weixin", "sms", "email", "webhook", "bluebubbles",
    "qqbot", "yuanbao",
})
_DELIVER_SPECIAL = frozenset({"local", "origin", "all"})


def _extra_platform_names() -> set[str]:
    try:
        from gateway.platform_registry import platform_registry
    except Exception:
        return set()
    try:
        return {str(name).strip().lower() for name in platform_registry.registered_names() if str(name).strip()}
    except Exception:
        return set()


def canonical_deliver(value: str) -> str | None:
    """Return a deliver string Hermes cron can route, or None when a part would be stored and then dropped."""
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        return None
    known = _DELIVER_PLATFORMS | _extra_platform_names()
    kept: list[str] = []
    for part in parts:
        low = part.lower()
        if low in _DELIVER_SPECIAL or low in known:
            kept.append(low)
            continue
        if low == "bot-chat":
            kept.append("bot-chat")
            continue
        if low.startswith("bot-chat:"):
            name = part.split(":", 1)[1].strip()
            if not name:
                return None
            kept.append("bot-chat:" + name)
            continue
        if ":" in part:
            platform, rest = part.split(":", 1)
            if platform.strip().lower() in known and rest.strip():
                kept.append(platform.strip().lower() + ":" + rest.strip())
                continue
        return None
    return ",".join(kept)


def schedule(deps: Deps, when: str = DEFAULT_SCHEDULE, deliver: str = "") -> str:
    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        return fail(
            "plugin_host",
            "plugins.isolation is host, so this process cannot see Hermes's cron mark. No cron job was created.",
            "Set plugins.isolation to in_process before scheduling the watch.",
        )
    bad = _configured(deps)
    if bad:
        return bad
    if not deliver.strip():
        return fail(
            "no_deliver",
            "No delivery target was given, so no cron job was created.",
            "Pass a Hermes deliver target such as telegram, discord, slack, or local.",
        )
    if deliver_looks_like_schedule(deliver):
        return fail(
            "deliver_looks_like_schedule",
            f"'{deliver.strip()}' looks like the start of a schedule, not a delivery target, so no cron job was created.",
            "Put the delivery target first, then the schedule: /switchbot-control schedule telegram every 10m, "
            "or /switchbot-control schedule local */5 * * * *. "
            "From the CLI: hermes switchbot-control schedule --deliver telegram --schedule \"every 10m\".",
        )
    accepted = canonical_deliver(deliver)
    if accepted is None:
        return fail(
            "bad_deliver",
            f"The delivery target {deliver.strip()!r} is not a Hermes cron destination, so no cron job was created.",
            "Use local, origin, all, a platform name such as telegram, platform:chat_id, bot-chat, "
            "or a comma combination such as origin,all. cli, cron, and api_server are not delivery targets.",
        )
    deliver = accepted
    floor = min_gap_seconds(deps.max_status_reads, deps.daily_cap)
    refusal = schedule_refusal(when, floor)
    if refusal:
        return fail(
            "schedule_too_fast",
            refusal,
            f"One watch tick can call the API {calls_per_tick(deps.max_status_reads)} times. "
            f"The schedule must be at least {floor} seconds so that stays within {deps.daily_cap} calls per UTC day. Nothing was created.",
        )
    try:
        jobs = _cron(deps)
        old = next((job for job in jobs.list_jobs(include_disabled=True) if job.get("name") == JOB_NAME), None)
        created = jobs.create_job(
            prompt=CRON_PROMPT, schedule=when, name=JOB_NAME, deliver=deliver.strip(),
            enabled_toolsets=[TOOLSET],
        )
        if old and old.get("id") and old.get("id") != created.get("id"):
            try:
                jobs.remove_job(old["id"])
            except Exception:
                return dumps({
                    "ok": True,
                    "moved": False,
                    "message": (
                        f"Scheduled new job {created.get('id')}, but the previous job {old.get('id')} is still there. "
                        f"Remove the previous one with {hermes_cron('remove')}. "
                        f"{hermes_cron('list')} only shows jobs. {hermes_cron('status')} shows one job. "
                        "Watch state was not deleted."
                    ),
                    "job_id": created.get("id"),
                })
    except ApiError as exc:
        return _shown(deps, fail(exc.code, exc.message, exc.next_step))
    except Exception as exc:
        return fail("no_cron", f"Could not schedule ({type(exc).__name__}: {exc}).", "No API call was made.")
    target = deliver.strip()
    where = "saved on this machine only. It is not sent to a chat." if target == "local" else (
        f"marked for delivery to {target}. Hermes sends that only when the platform is already configured. "
        "This plugin does not check that the chat exists."
    )
    return dumps({
        "ok": True,
        "moved": False,
        "message": (
            f"Scheduled {JOB_NAME} ({created.get('schedule_display') or when}). Results are {where} "
            "The prompt tells the job to call switchbot_watch only. The toolset still includes switchbot_command, and a cron context cannot send a command. "
            "Each slot that runs is at least one model turn, and a turn that calls a tool makes two or more model requests. "
            "The default every 5 minutes is 288 slots per day, and the prompt asks each one to call switchbot_watch, so 576 or more model requests a day. "
            "If a run is still going, Hermes skips the next slot, so a slow watch is not 288 turns. "
            "Hermes skips the agent with no_agent=True, which requires a script, when a script returns wakeAgent=false, or when monitor_script or monitor_url output is unchanged. This plugin passes none of those. "
            "Removing this plugin does not remove the job. "
            f"Remove it with hermes switchbot-control unschedule or {hermes_cron('remove')}. "
            f"{hermes_cron('list')} only shows the job. {hermes_cron('status')} shows one job. "
            + (
                " bot-chat delivery starts one model turn, and the agent can act on that text."
                if "bot-chat" in target.lower() else ""
            )
        ),
        "job_id": created.get("id"),
        "deliver": target,
    })


def unschedule(deps: Deps) -> str:
    try:
        jobs = _cron(deps)
        old = next((job for job in jobs.list_jobs(include_disabled=True) if job.get("name") == JOB_NAME), None)
        if not old:
            return dumps({"ok": True, "moved": False, "message": "switchbot-control is not scheduled. usage.json, watch.json, and watch_fail.json were left in place."})
        jobs.remove_job(old["id"])
    except ApiError as exc:
        return _shown(deps, fail(exc.code, exc.message, exc.next_step))
    except Exception as exc:
        return fail(
            "no_cron",
            f"Could not remove the job ({type(exc).__name__}).",
            f"Use {hermes_cron('list')} to see it, {hermes_cron('status')} to inspect it, then {hermes_cron('remove')}, or hermes switchbot-control unschedule.",
        )
    return dumps({
        "ok": True,
        "moved": False,
        "message": f"Removed cron job {old['id']}. usage.json, watch.json, and watch_fail.json were kept. Removing the plugin does not do this by itself.",
    })
