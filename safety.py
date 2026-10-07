"""Fail-closed gate for SwitchBot commands.

A command is a physical action. Hermes's request_tool_approval returns
approved without a new prompt when yolo is on, when approvals.mode is off,
and when an unattended cron mode is approve. Those cases are refused here,
before any command POST. If a check cannot run, the command is refused.
"""
from __future__ import annotations

import importlib
import uuid
from pathlib import Path
from typing import Any, Callable

PLUGIN_NAME = "switchbot-control"


def _load(module: str, name: str) -> tuple[str, Any]:
    try:
        mod = importlib.import_module(module)
    except Exception:
        return "failed", None
    if not hasattr(mod, name):
        return "missing", None
    try:
        return "ok", getattr(mod, name)
    except Exception:
        return "failed", None


def command_block_reason(device_id: str, command: str) -> str | None:
    cron_status, cron = _load("tools.approval_context", "_is_cron_approval_context")
    if cron_status != "ok":
        return "BLOCKED: could not tell whether this is a cron job, so no command was sent."
    try:
        if cron():
            return "BLOCKED: cron cannot send a SwitchBot command. The watch only reports."
    except Exception:
        return "BLOCKED: the cron check failed, so no command was sent."

    yolo_status, yolo = _load("tools.approval", "_yolo_active")
    if yolo_status != "ok":
        return "BLOCKED: could not read Hermes yolo state, so no command was sent."
    try:
        if yolo():
            return "BLOCKED: Hermes yolo is on, so the approval gate would not ask a person. Turn yolo off and try again."
    except Exception:
        return "BLOCKED: the yolo check failed, so no command was sent."

    mode_status, mode = _load("tools.approval_context", "_get_approval_mode")
    if mode_status != "ok":
        return "BLOCKED: could not read approvals.mode, so no command was sent."
    try:
        if mode() == "off":
            return "BLOCKED: Hermes approvals are off, so nobody would be asked. Turn approvals on and try again."
    except Exception:
        return "BLOCKED: reading approvals.mode failed, so no command was sent."

    for module, name, label in (
        ("tools.approval_context", "_is_single_query_approval_context", "a single-query session"),
        ("tools.approval_context", "_is_unattended_platform_approval_context", "an unattended session"),
    ):
        status, fn = _load(module, name)
        if status != "ok":
            return f"BLOCKED: could not tell whether this is {label}, so no command was sent."
        try:
            if fn():
                return f"BLOCKED: {label} cannot send a SwitchBot command."
        except Exception:
            return f"BLOCKED: the check for {label} failed, so no command was sent."

    approval_status, _approval = _load("tools.approval", "request_tool_approval")
    if approval_status != "ok":
        return "BLOCKED: Hermes approval could not be loaded, so no command was sent."
    if not device_id or not command:
        return "BLOCKED: the command was missing a device or a command name, so nothing was sent."
    return None


def request_command_approval(
    device_id: str,
    command: str,
    *,
    device_name: str,
    device_type: str,
    parameter: str,
) -> tuple[bool, str]:
    reason = command_block_reason(device_id, command)
    if reason:
        return False, reason
    status, fn = _load("tools.approval", "request_tool_approval")
    if status != "ok":
        return False, "BLOCKED: Hermes approval could not be loaded, so no command was sent."
    call_id = uuid.uuid4().hex
    try:
        result = fn(
            "switchbot_command",
            (
                f"Send SwitchBot command {command} to {device_name} "
                f"(id {device_id}, type {device_type}) with parameter {parameter}. "
                "This can move a physical device."
            ),
            rule_key=f"switchbot_command:{device_id}:{command}:{parameter}:{call_id}",
        )
    except Exception:
        return False, "BLOCKED: the Hermes approval request failed, so no command was sent."
    if not isinstance(result, dict) or result.get("approved") is not True:
        message = ""
        if isinstance(result, dict):
            message = str(result.get("message") or "")
        return False, message or "BLOCKED: the SwitchBot command was not approved."
    return True, ""


def plugin_data_dir() -> Path:
    status, fn = _load("plugins.plugin_storage", "plugin_data_dir")
    if status != "ok":
        raise RuntimeError("plugin_data_dir is not available")
    path = fn(PLUGIN_NAME)
    if not isinstance(path, Path):
        path = Path(path)
    return path


Approver = Callable[[str, str], tuple[bool, str]]
