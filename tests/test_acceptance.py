"""Offline checks named in the frozen acceptance table.

Ship drafts are read only when this checkout sits next to them. A git archive
used by the preship runner does not include that directory, and these tests
skip the draft assertions there. They do not open a socket.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import hashlib
import hmac
import json
import sys
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

import safety
from client import HOST, MAX_BYTES, TIMEOUT_SECONDS, ApiError, SwitchBot, sign
from policy import watch_kind
from service import Deps, command, deps_from_config, devices, schedule, unschedule, watch

TOKEN = "test-token"
SECRET = "test-secret"
FROZEN = 1_700_000_000.0
DAY = datetime.fromtimestamp(FROZEN, timezone.utc).date().isoformat()
ROOT = Path(__file__).resolve().parents[1]


def body_of(**payload) -> bytes:
    return json.dumps(payload).encode()


LIST_EMPTY = {
    "statusCode": 100,
    "body": {"deviceList": [], "infraredRemoteList": []},
    "message": "success",
}
UNAUTHORIZED = {"message": "Unauthorized"}
COMMAND_OK = {"statusCode": 100, "body": {}, "message": "success"}


def _list(rows, remotes=None):
    return {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceList": rows, "infraredRemoteList": [] if remotes is None else remotes},
    }


class Router:
    def __init__(self):
        self.calls = []
        self.routes = []

    def add(self, needle: str, status: int, payload: dict):
        self.routes.append((needle, status, body_of(**payload)))

    def __call__(self, method, url, headers, body, timeout, read_limit):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body, "timeout": timeout})
        for needle, status, payload in self.routes:
            if needle in url:
                return status, {"content-type": "application/json"}, payload
        raise AssertionError(url)


def deps(tmp_path, router=None, **kw) -> Deps:
    base = dict(
        token=TOKEN,
        secret=SECRET,
        data_dir=tmp_path,
        transport=router,
        approver=lambda _device, _command: (True, ""),
        safety_devices=False,
        now=lambda: FROZEN,
    )
    base.update(kw)
    return Deps(**base)


def _posts(router) -> list:
    return [call for call in router.calls if call["method"] == "POST"]


def _bot_list():
    return _list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"}])


def _allow_all(monkeypatch, approval):
    def fake(_module, attr):
        if attr == "_get_approval_mode":
            return "ok", (lambda: "manual")
        if attr == "request_tool_approval":
            return "ok", approval
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)


def test_row1_only_v11_on_the_switchbot_host_is_called():
    seen = []

    def transport(method, url, headers, body, timeout, read_limit):
        seen.append((method, url, dict(headers), timeout))
        return 200, {}, body_of(**LIST_EMPTY)

    bot = SwitchBot(TOKEN, SECRET, transport, now=lambda: FROZEN)
    parsed = bot.request("GET", "/v1.1/devices")
    assert parsed["message"] == "success"
    assert len(seen) == 1
    method, url, headers, timeout = seen[0]
    assert method == "GET"
    assert url == HOST + "/v1.1/devices"
    assert url.startswith("https://api.switch-bot.com/v1.1/")
    assert headers["Authorization"] == TOKEN
    assert headers["sign"]
    assert headers["t"]
    assert headers["nonce"]
    assert timeout == TIMEOUT_SECONDS
    for path in ("/v1.0/devices", "/v1.1/../secret", "https://evil.example/v1.1/devices"):
        with pytest.raises(ApiError) as caught:
            bot.request("GET", path)
        assert caught.value.code == "bad_path"
    assert len(seen) == 1


def test_row2_sign_is_the_python3_example_not_the_short_uppercase_one():
    got = sign("token", "secret", 1661927531000, "nonce")
    assert got == "s1htA6ftn0O7EQh7AtZsXax6Vc2DDB7StLvyFLuHxnk="
    material = b"token1661927531000"
    digest = hmac.new(b"secret", material, hashlib.sha256).digest()
    short_hex = hmac.new(b"secret", material, hashlib.sha256).hexdigest().upper()
    short_b64 = base64.b64encode(digest).decode().upper()
    assert got != short_hex
    assert got != short_b64


def test_row3_devices_returns_an_empty_inventory_and_ignores_watch_rows(tmp_path):
    previous = {"devices": {"METER1": {"deviceType": "Meter"}, "PLUG1": {"deviceType": "Plug"}}}
    (tmp_path / "watch.json").write_text(json.dumps(previous), encoding="utf-8")
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    out = json.loads(devices(deps(tmp_path, router), {}))
    assert out["ok"] is True
    assert out["device_count"] == 0
    assert out["infrared_count"] == 0
    assert json.loads((tmp_path / "watch.json").read_text(encoding="utf-8")) == previous
    router.routes.clear()
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceList": []},
    })
    missing = json.loads(devices(deps(tmp_path, router), {}))
    assert missing["ok"] is False
    assert missing["error"] == "bad_list"
    assert "inventory" in missing["message"] or "inventory" in missing["next_step"]


def test_row4_unauthorized_names_the_daily_cap(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    out = json.loads(devices(deps(tmp_path, router), {}))
    assert out["error"] == "unauthorized"
    assert "statusCode" in out["message"]
    assert "10000" in out["next_step"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "10000" in readme
    assert "has not sent that many" not in readme
    assert "それほど送っていない" not in readme


def test_row5_empty_status_is_not_a_reading(tmp_path):
    router = Router()
    router.add("/status", 200, {"statusCode": 100, "body": {}, "message": "success"})
    router.add("/v1.1/devices", 200, _bot_list())
    out = json.loads(devices(deps(tmp_path, router), {"device_id": "BOT1"}))
    assert out["error"] == "empty_status"
    assert out.get("status") in (None, {})
    text = json.dumps(out)
    assert "temperature" not in text


def test_row6_unknown_id_does_not_post_and_190_is_not_accepted(tmp_path):
    router = Router()
    router.add("/commands", 200, {"statusCode": 190, "body": {}, "message": "Wrong deviceId, No this device"})
    router.add("/v1.1/devices", 200, _bot_list())
    missing = json.loads(command(deps(tmp_path, router), {"device_id": "NOPE1", "command": "turnOn"}))
    assert missing["error"] == "unknown_device"
    assert _posts(router) == []
    sent = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "turnOn"}))
    assert sent["ok"] is False
    assert sent.get("accepted") is not True
    assert len(_posts(router)) == 1


def test_row7_redirect_is_not_followed_and_a_huge_body_is_discarded(tmp_path):
    seen = []

    def redirect(method, url, headers, body, timeout, read_limit):
        seen.append(url)
        return 302, {"Location": "https://evil.example/collect"}, b"go"

    listed = json.loads(devices(deps(tmp_path, redirect), {}))
    assert listed["error"] == "redirect"
    assert seen == [HOST + "/v1.1/devices"]
    assert "may have" not in listed["message"]
    assert "evil.example" not in json.dumps(listed)

    def huge(method, url, headers, body, timeout, read_limit):
        return 200, {}, b"x" * (MAX_BYTES + 1)

    oversized = json.loads(devices(deps(tmp_path, huge), {}))
    assert oversized["error"] == "too_large"
    assert "1000000" in oversized["message"]


def test_row8_command_post_408_and_302_may_have_reached(tmp_path):
    def transport(status):
        def inner(method, url, headers, body, timeout, read_limit):
            if method == "POST":
                return status, {}, b""
            return 200, {}, body_of(**_bot_list())
        return inner

    for status in (408, 302):
        out = json.loads(command(deps(tmp_path, transport(status)), {"device_id": "BOT1", "command": "press"}))
        assert "may have reached" in out["message"]
        assert "Check the device state first" in out["next_step"]


@pytest.mark.parametrize("status_code", [161, 171])
def test_row8_command_post_161_and_171_do_not_say_it_moved(status_code, tmp_path):
    def transport(method, url, headers, body, timeout, read_limit):
        if method == "POST":
            return 200, {}, body_of(statusCode=status_code, message="failed", body={})
        return 200, {}, body_of(**_bot_list())

    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is False
    assert "may have reached" not in out["message"]
    assert "does not say the command moved" in out["message"]
    if status_code == 161:
        assert "The device is offline" in out["message"]
        assert "hub is offline" not in out["message"]
    else:
        assert "hub is offline" in out["message"]


def test_row8_dropped_connection_after_post_does_not_say_it_did_not_reach(tmp_path):
    def transport(method, url, headers, body, timeout, read_limit):
        if method == "POST":
            raise ConnectionResetError("reset")
        return 200, {}, body_of(**_bot_list())

    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out["error"] == "network"
    assert "may have reached" in out["message"]
    assert "did not reach" not in out["message"]
    assert "届かなかった" not in out["message"]


def test_row9_usage_write_replaces_a_temp_file(tmp_path, monkeypatch):
    written = []
    real = Path.write_text

    def spy(self, data, *args, **kwargs):
        written.append(self.name)
        return real(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", spy)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _bot_list())
    out = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "press"}))
    assert out["accepted"] is True
    assert "usage.json.tmp" in written
    assert "usage.json" not in written
    saved = json.loads((tmp_path / "usage.json").read_text(encoding="utf-8"))
    assert set(saved) <= {"utc_date", "count", "warned"}


def test_row9_counter_failure_after_a_successful_post_does_not_deny_the_call(tmp_path, monkeypatch):
    import service as service_mod

    reads = {"n": 0}
    real = service_mod._read_usage

    def flaky(plugin):
        reads["n"] += 1
        if reads["n"] >= 3:
            raise ApiError(
                "bad_usage",
                "The daily counter could not be read, so no API call was made.",
                next_step="stop",
            )
        return real(plugin)

    monkeypatch.setattr(service_mod, "_read_usage", flaky)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _bot_list())
    out = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "press"}))
    assert len(_posts(router)) == 1
    assert out["ok"] is True
    assert out["accepted"] is True
    assert out["moved"] is False
    text = json.dumps(out)
    assert "no API call was made" not in text
    assert "may have reached" in text


def test_row9_a_failed_write_before_the_call_still_says_nothing_was_sent(tmp_path, monkeypatch):
    real = Path.write_text

    def broken(self, data, *args, **kwargs):
        if self.name.startswith("usage.json"):
            raise OSError("disk")
        return real(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", broken)
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    out = json.loads(devices(deps(tmp_path, router), {}))
    assert out["error"] == "bad_usage"
    assert "no API call was made" in out["message"]
    assert router.calls == []


def test_row10_accepted_requires_http_200_status_100_and_message_success(tmp_path):
    def transport(method, url, headers, body, timeout, read_limit):
        if method == "POST":
            return 200, {}, body_of(statusCode=100, message="OK", body={})
        return 200, {}, body_of(**_bot_list())

    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out.get("accepted") is not True
    assert out["ok"] is False


def test_row11_customize_ff_on_and_41_are_refused_before_post(tmp_path):
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _bot_list())
    plugin = deps(tmp_path, router)
    for args in (
        {"device_id": "BOT1", "command": "customize"},
        {"device_id": "BOT1", "command": "setAll", "parameter": "26,1,3,FF"},
        {"device_id": "BOT1", "command": "setAll", "parameter": "26,1,3,ON"},
        {"device_id": "BOT1", "command": "setAll", "parameter": "41,1,3,on"},
    ):
        out = json.loads(command(plugin, args))
        assert out["ok"] is False
        assert out["error"] == "bad_command"
    hot = json.loads(command(plugin, {"device_id": "BOT1", "command": "setAll", "parameter": "41,1,3,on"}))
    assert "0 to 40" in hot["message"]
    assert "does not publish" in hot["message"]
    assert _posts(router) == []
    sent = json.loads(command(plugin, {"device_id": "BOT1", "command": "setAll", "parameter": "26,1,3,on"}))
    assert sent["accepted"] is True
    posted = json.loads(_posts(router)[0]["body"].decode())
    assert posted["parameter"] == "26,1,3,on"
    assert posted["command"] == "setAll"


def test_row12_curtain_position_text_and_other_types_are_refused(tmp_path, monkeypatch):
    asked = []

    def approval(_tool, reason, rule_key=""):
        asked.append(reason)
        return {"approved": True}

    _allow_all(monkeypatch, approval)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "CUR1", "deviceType": "Curtain", "deviceName": "Left"},
        {"deviceId": "RS1", "deviceType": "Roller Shade", "deviceName": "Hall"},
        {"deviceId": "BT1", "deviceType": "Blind Tilt", "deviceName": "Study"},
    ]))
    plugin = deps(tmp_path, router, approver=None)
    moved = json.loads(command(plugin, {"device_id": "CUR1", "command": "setPosition", "parameter": "0,1,40"}))
    assert moved["accepted"] is True
    assert "position 40" in asked[0]
    assert "0 is open, 100 is closed" in asked[0]
    assert "0,1,40" in asked[0]
    for device_id, parameter in (("RS1", "0,ff,40"), ("BT1", "up;60"), ("RS1", "50")):
        refused = json.loads(command(plugin, {"device_id": device_id, "command": "setPosition", "parameter": parameter}))
        assert refused["ok"] is False
        assert "0 is open" not in refused["message"] + refused["next_step"]
    assert len(_posts(router)) == 1


def test_row13_safety_flag_cannot_be_turned_on_by_a_tool_argument(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "LOCK1", "deviceType": "Smart Lock", "deviceName": "Front"},
        {"deviceId": "DOOR1", "deviceType": "Door", "deviceName": "Side"},
    ]))
    plugin = deps(tmp_path, router, safety_devices=False)
    argued = json.loads(command(plugin, {"device_id": "LOCK1", "command": "unlock", "safety_devices": True}))
    assert argued["ok"] is False
    assert argued["error"] == "bad_args"
    door = json.loads(command(plugin, {"device_id": "DOOR1", "command": "turnOn"}))
    assert door["error"] == "safety_off"
    assert _posts(router) == []


def test_row15_a_question_that_would_be_cut_is_not_sent(tmp_path, monkeypatch):
    asked = []

    def approval(_tool, reason, rule_key=""):
        asked.append(reason)
        return {"approved": True}

    _allow_all(monkeypatch, approval)
    router = Router()
    long_name = "N" * 400
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": long_name}]))
    out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert out["error"] == "not_approved"
    assert out.get("retryable") is False
    assert "not shortened" in out["message"]
    assert asked == []
    assert _posts(router) == []

    skeleton = safety.approval_question("BOT1", "turnOn", device_name="", device_type="Bot", parameter="default")
    room = 300 - len(skeleton)
    assert room > 0
    escaped_name = "&" * room
    question = safety.approval_question(
        "BOT1", "turnOn", device_name=escaped_name, device_type="Bot", parameter="default",
    )
    assert len(question) <= 300
    assert safety.reason_fits(question) is False
    router.routes.clear()
    router.calls.clear()
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": escaped_name}]))
    escaped = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert escaped.get("retryable") is False
    assert asked == []
    assert _posts(router) == []


def test_row15_a_short_name_is_sent_unchanged(tmp_path, monkeypatch):
    asked = []

    def approval(_tool, reason, rule_key=""):
        asked.append({"reason": reason, "rule_key": rule_key})
        return {"approved": True}

    _allow_all(monkeypatch, approval)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Lamp*"}]))
    out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert out["accepted"] is True
    expected = safety.approval_question(
        "BOT1", "turnOn", device_name="Lamp*", device_type="Bot", parameter="default",
    )
    assert asked[0]["reason"] == expected
    assert "Lamp*" in asked[0]["reason"]
    assert len({item["rule_key"] for item in asked}) == 1


@pytest.mark.parametrize("which", ["cron", "yolo", "off", "single", "unattended"])
def test_row16_each_closed_context_blocks_before_http(which, tmp_path, monkeypatch):
    def fake(_module, attr):
        if attr == "_is_cron_approval_context":
            return "ok", (lambda: which == "cron")
        if attr == "_yolo_active":
            return "ok", (lambda: which == "yolo")
        if attr == "_get_approval_mode":
            return "ok", (lambda: "off" if which == "off" else "manual")
        if attr == "_is_single_query_approval_context":
            return "ok", (lambda: which == "single")
        if attr == "_is_unattended_platform_approval_context":
            return "ok", (lambda: which == "unattended")
        if attr == "request_tool_approval":
            return "ok", (lambda *args, **kwargs: {"approved": True})
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _bot_list())
    out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert out["error"] == "not_approved"
    assert "BLOCKED" in out["message"]
    assert router.calls == []


def test_row16_approved_must_be_true(tmp_path, monkeypatch):
    def approval(*_args, **_kwargs):
        return {"approved": "yes"}

    _allow_all(monkeypatch, approval)
    router = Router()
    router.add("/v1.1/devices", 200, _bot_list())
    out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert out["ok"] is False
    assert _posts(router) == []


HELPERS = (
    ("tools.approval_context", "_is_cron_approval_context"),
    ("tools.approval", "_yolo_active"),
    ("tools.approval_context", "_get_approval_mode"),
    ("tools.approval_context", "_is_single_query_approval_context"),
    ("tools.approval_context", "_is_unattended_platform_approval_context"),
    ("tools.approval", "request_tool_approval"),
)


@pytest.mark.parametrize("module_name,attr", HELPERS)
def test_row16_a_renamed_helper_sends_nothing(module_name, attr, tmp_path):
    saved = {key: sys.modules.get(key) for key in ("tools", "tools.approval", "tools.approval_context")}
    tools = types.ModuleType("tools")
    tools.__path__ = []
    approval_context = types.ModuleType("tools.approval_context")
    approval_mod = types.ModuleType("tools.approval")
    modules = {"tools.approval_context": approval_context, "tools.approval": approval_mod}

    def present(name):
        if name == "_get_approval_mode":
            return lambda: "manual"
        if name == "request_tool_approval":
            return lambda *args, **kwargs: {"approved": True}
        return lambda: False

    try:
        for mod_name, name in HELPERS:
            target = modules[mod_name]
            if name == attr:
                setattr(target, name + "_renamed", present(name))
            else:
                setattr(target, name, present(name))
        sys.modules["tools"] = tools
        sys.modules["tools.approval_context"] = approval_context
        sys.modules["tools.approval"] = approval_mod
        router = Router()
        router.add("/v1.1/devices", 200, _bot_list())
        out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
        assert "BLOCKED" in out["message"]
        assert router.calls == []
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def test_row17_host_schedule_creates_no_job(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_PLUGIN_HOST_PROCESS", "1")
    created = []

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            created.append(kwargs)
            return {"id": "job1"}

    out = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "*/5 * * * *", "local"))
    assert out["error"] == "plugin_host"
    assert created == []
    command_out = json.loads(command(deps(tmp_path, Router()), {"device_id": "BOT1", "command": "press"}))
    assert command_out["error"] == "host_isolation"
    assert "can still report" not in command_out["next_step"]
    assert "in_process" in command_out["next_step"]


def _load(tmp_path, router, monkeypatch):
    import importlib.util

    monkeypatch.setenv("SWITCHBOT_TOKEN", TOKEN)
    monkeypatch.setenv("SWITCHBOT_SECRET", SECRET)
    spec = importlib.util.spec_from_file_location(
        "switchbot_acceptance_plugin",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    module.__path__ = [str(ROOT)]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    class Ctx:
        def __init__(self):
            self.tools = {}
            self.command = None
            self.setup = None
            self.cli = None

        def register_tool(self, name, toolset, schema, handler, **kwargs):
            self.tools[name] = {"schema": schema, "handler": handler}

        def register_command(self, name, handler, description=""):
            self.command = handler

        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            self.setup = setup_fn
            self.cli = handler_fn

        def get_config(self, key, default=None):
            return default

    ctx = Ctx()
    module.register(ctx)
    service_mod = sys.modules[spec.name + ".service"]
    client_mod = sys.modules[spec.name + ".client"]
    monkeypatch.setattr(service_mod, "plugin_data_dir", lambda: tmp_path)
    if router is not None:
        def client(plugin):
            return client_mod.SwitchBot(plugin.token, plugin.secret, router, plugin.now)

        monkeypatch.setattr(service_mod, "_client", client)
    return ctx


def test_row20_slash_turn_on_sends_no_command(tmp_path, monkeypatch):
    router = Router()
    router.add("/v1.1/devices", 200, _bot_list())
    ctx = _load(tmp_path, router, monkeypatch)
    text = asyncio.run(ctx.command("turnOn"))
    assert "does not send a device command" in text
    assert router.calls == []


def test_row20_one_slash_at_a_time_leaves_the_executor_free(tmp_path, monkeypatch):
    order = []
    entered = threading.Event()
    gate = threading.Event()
    state = {"n": 0}
    payload = body_of(**LIST_EMPTY)

    class Hold(Router):
        def __call__(self, method, url, headers, body, timeout, read_limit):
            state["n"] += 1
            order.append("http-start")
            if state["n"] == 1:
                entered.set()
                assert gate.wait(5)
            order.append("http-end")
            return 200, {}, payload

    ctx = _load(tmp_path, Hold(), monkeypatch)

    async def run():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        first = asyncio.create_task(ctx.command("devices"))
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()
        second = asyncio.create_task(ctx.command("devices"))
        await asyncio.sleep(0.05)

        def mark():
            order.append("marker")

        marker = asyncio.create_task(asyncio.to_thread(mark))
        await asyncio.sleep(0.05)
        assert "marker" not in order
        gate.set()
        await marker
        await first
        await second

    asyncio.run(run())
    starts = [index for index, item in enumerate(order) if item == "http-start"]
    assert starts == [0, order.index("http-start", 1)]
    assert len(starts) == 2
    assert order.index("marker") < starts[1]
    assert order.index("http-end") < starts[1]


def test_row21_cli_flags_and_profile_prefix(tmp_path, monkeypatch):
    ctx = _load(tmp_path, Router(), monkeypatch)
    parser = argparse.ArgumentParser()
    ctx.setup(parser)
    options = set()
    for action in parser._actions:
        options.update(action.option_strings)
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                for nested in sub._actions:
                    options.update(nested.option_strings)
            assert "watch_fail.json" in action.choices["unschedule"].format_help()
    assert "--deliver" in options
    assert "--schedule" in options
    assert "-p" not in options
    assert "--profile" not in options
    parsed = parser.parse_args(["schedule", "--deliver", "telegram", "--schedule", "every 10m"])
    assert parsed.deliver == "telegram"
    assert parsed.schedule == "every 10m"

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            return {"id": "job1", "schedule_display": kwargs["schedule"]}

    monkeypatch.delenv("HERMES_PROFILE_NAME", raising=False)
    monkeypatch.setenv("HERMES_PROFILE", "work")
    named = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "every 10m", "telegram"))
    assert named["ok"] is True
    assert "hermes -p work cron list" in named["message"]
    assert "hermes -p work cron status" in named["message"]
    assert "hermes -p work cron remove" in named["message"]
    monkeypatch.delenv("HERMES_PROFILE", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    plain = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "every 10m", "local"))
    assert "hermes cron list" in plain["message"]
    assert "hermes -p " not in plain["message"]
    profile_home = tmp_path / "hermes-root" / "profiles" / "harnessprof"
    profile_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    from_home = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "every 10m", "local"))
    assert "hermes -p harnessprof cron list" in from_home["message"]
    assert "hermes -p harnessprof cron status" in from_home["message"]
    assert "hermes -p harnessprof cron remove" in from_home["message"]
    other = tmp_path / "not-a-profile"
    other.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(other))
    custom = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "every 10m", "local"))
    assert "hermes -p custom cron list" in custom["message"]


def test_row22_and_23_schedule_words_and_the_speed_floor(tmp_path):
    created = []

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            created.append(kwargs)
            return {"id": "job1", "schedule_display": kwargs["schedule"]}

    plugin = deps(tmp_path, cron_module=Jobs())
    monday = json.loads(schedule(plugin, "every monday 9am", "telegram"))
    assert monday["ok"] is False
    assert monday["error"] == "schedule_too_fast"
    assert "could not prove" in monday["message"]
    fast = json.loads(schedule(plugin, "every 1m", "telegram"))
    assert fast["error"] == "schedule_too_fast"
    assert created == []
    for expr in ("every 10m", "*/5 * * * *"):
        out = json.loads(schedule(plugin, expr, "telegram"))
        assert out["ok"] is True
    assert len(created) == 2
    text = json.loads(schedule(plugin, "*/5 * * * *", "local"))["message"]
    assert "switchbot_watch" in text
    assert "switchbot_command" in text
    assert "cannot send" in text
    assert "576 or more" in text
    assert "can only call" not in text
    assert "hermes switchbot-control unschedule" in text
    assert "no_agent=True" in text
    assert "wakeAgent=false" in text
    assert created[0]["prompt"].count("switchbot_watch") >= 1
    assert "switchbot_command" in created[0]["prompt"]


def test_row26_hub2_is_not_a_meter(tmp_path):
    assert watch_kind("Hub 2") is None
    assert watch_kind("WoIOSensor") == "meter"
    router = Router()
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "HUB1", "deviceType": "Hub 2", "temperature": 40},
    ]))
    out = json.loads(watch(deps(tmp_path, router, temperature_high_c=20), {}))
    assert "temperature is" not in out["message"]
    assert not any("/status" in call["url"] for call in router.calls)
    assert len(router.calls) == 1


def test_row27_numeric_power_is_named_first_and_weight_needs_a_threshold(tmp_path):
    (tmp_path / "watch.json").write_text(json.dumps({
        "devices": {"PLUG1": {"deviceType": "Plug Mini (EU)", "power": 1.0, "weight": 1}},
    }), encoding="utf-8")
    router = Router()
    router.add("/PLUG1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "PLUG1", "deviceType": "Plug Mini (EU)", "power": 9.0, "weight": 80},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "PLUG1", "deviceType": "Plug Mini (EU)"}]))
    quiet = json.loads(watch(deps(tmp_path, router), {}))
    assert quiet["message"].startswith("A numeric power field is not compared")
    assert not quiet["message"].startswith("on/off")
    assert "power changed" not in quiet["message"]
    assert "weight is" not in quiet["message"]
    (tmp_path / "watch.json").write_text(json.dumps({
        "devices": {"PLUG1": {"deviceType": "Plug", "weight": 1}},
    }), encoding="utf-8")
    router.routes.clear()
    router.add("/PLUG1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "PLUG1", "deviceType": "Plug", "weight": 80},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "PLUG1", "deviceType": "Plug"}]))
    alert = json.loads(watch(deps(tmp_path, router, plug_weight_watts=10), {}))
    assert "weight is" in alert["message"]
    assert alert["notify"] is True


def test_row29_an_empty_stretch_notifies_again_after_a_failure(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    plugin = deps(tmp_path, router)
    first = json.loads(watch(plugin, {}))
    second = json.loads(watch(plugin, {}))
    assert first["notify"] is True
    assert "Cloud Services" in first["message"]
    assert "not a healthy watch" in first["message"]
    assert second["notify"] is False
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    failed = json.loads(watch(plugin, {}))
    assert failed["notify"] is True
    router.routes.clear()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    again = json.loads(watch(plugin, {}))
    assert again["notify"] is True
    assert "Cloud Services" in again["message"]


def test_row30_list_gap_notifies_once_and_keeps_rows(tmp_path):
    (tmp_path / "watch.json").write_text(json.dumps({
        "devices": {
            "METER1": {"deviceType": "Meter", "temperature": 20},
            "DOOR1": {"deviceType": "Contact Sensor", "openState": "close"},
        },
    }), encoding="utf-8")
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    plugin = deps(tmp_path, router)
    first = json.loads(watch(plugin, {}))
    second = json.loads(watch(plugin, {}))
    assert first["notify"] is True
    assert "not a normal empty account" in first["message"]
    assert second["notify"] is False
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert "METER1" in saved["devices"]
    assert "DOOR1" in saved["devices"]


def test_row33_watch_failure_does_not_claim_delivery(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    plugin = deps(tmp_path, router)
    cron = json.loads(watch(plugin, {}))
    assert cron["notify"] is True
    assert "cannot tell whether Hermes delivered" in cron["message"]
    assert "24-hour" in cron["message"]
    assert "hermes cron list" in cron["message"]
    assert "notice was delivered" not in cron["message"]
    manual = json.loads(watch(plugin, {}, advance=False))
    assert "cannot tell whether Hermes delivered" in manual["message"]
    assert "did not update the cron failure record" in manual["message"]
    assert not (tmp_path / "watch_fail.json").exists() or json.loads((tmp_path / "watch_fail.json").read_text(encoding="utf-8"))["streak"] == 1


def test_row34_bad_threshold_stops_four_tools_and_unschedule_still_removes(tmp_path):
    made = {"job": {"id": "job1", "name": "switchbot-control"}}

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return list(made.values())

        def remove_job(self, job_id):
            assert job_id == "job1"
            made.clear()

    router = Router()
    plugin = deps(tmp_path, router, config_problem="temperature_high_c is not a number, so no API call was made.", cron_module=Jobs())
    for raw in (
        devices(plugin, {}),
        command(plugin, {"device_id": "BOT1", "command": "press"}),
        watch(plugin, {}),
        schedule(plugin, "*/5 * * * *", "local"),
    ):
        body = json.loads(raw)
        assert body["error"] == "bad_config"
    assert router.calls == []
    gone = json.loads(unschedule(plugin))
    assert gone["ok"] is True
    assert made == {}


def test_row35_cap_warn_and_usage_file_shape(tmp_path):
    def get_config(key, default=None):
        if key == "daily_cap":
            return 20000
        if key == "max_status_reads":
            return 50
        return default

    configured = deps_from_config(get_config, token=TOKEN, secret=SECRET)
    assert configured.daily_cap == 10000
    assert configured.max_status_reads == 20
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    argued = json.loads(devices(deps(tmp_path, router), {"daily_cap": 20000}))
    assert argued["error"] == "bad_args"
    assert router.calls == []
    for count in (10000, 10001):
        (tmp_path / "usage.json").write_text(
            json.dumps({"utc_date": DAY, "count": count, "warned": True}),
            encoding="utf-8",
        )
        router.calls.clear()
        capped = json.loads(devices(deps(tmp_path, router), {}))
        assert capped["error"] == "daily_cap"
        assert router.calls == []
    (tmp_path / "usage.json").write_text(
        json.dumps({"utc_date": DAY, "count": 9000, "warned": False}),
        encoding="utf-8",
    )
    first = json.loads(devices(deps(tmp_path, router), {}))
    second = json.loads(devices(deps(tmp_path, router), {}))
    assert "Approaching the daily cap" in first["message"]
    assert "Approaching the daily cap" not in second.get("message", "")
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    json.loads(devices(deps(tmp_path, router), {}))
    saved = json.loads((tmp_path / "usage.json").read_text(encoding="utf-8"))
    assert set(saved) <= {"utc_date", "count", "warned"}
    assert "temperature" not in saved
    assert "deviceName" not in saved


def test_row37_storage_keeps_no_secrets_and_prefers_new_rows(tmp_path):
    old = {f"OLD{i:03d}": {"deviceType": "Meter", "temperature": 1} for i in range(200)}
    (tmp_path / "watch.json").write_text(json.dumps({"devices": old}), encoding="utf-8")
    router = Router()
    router.add("/NEW1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceId": "NEW1",
            "deviceType": "Meter",
            "deviceName": "Living",
            "temperature": 22,
            "powerState": "on",
            "token": TOKEN,
        },
    })
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "NEW1", "deviceType": "Meter", "deviceName": "Living"},
    ]))
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert out["ok"] is True
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert len(saved["devices"]) == 200
    assert "NEW1" in saved["devices"]
    assert "OLD199" not in saved["devices"]
    blob = json.dumps(saved)
    assert TOKEN not in blob
    assert SECRET not in blob
    assert "deviceName" not in blob
    assert "powerState" not in blob
    assert "Living" not in blob
    listed = json.loads(devices(deps(tmp_path, router), {}))
    assert listed["devices"][0]["deviceName"] == "Living"


def test_row37_missing_data_dir_refuses_and_does_not_write(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    plugin = deps(tmp_path, router, data_dir=None)
    for raw in (
        devices(plugin, {}),
        command(plugin, {"device_id": "BOT1", "command": "press"}),
        watch(plugin, {}),
    ):
        body = json.loads(raw)
        assert body["error"] == "no_data_dir"
    assert router.calls == []
    assert list(tmp_path.iterdir()) == []


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_public_text_matches_the_acceptance_table():
    readme = _text("README.md")
    plugin = _text("plugin.yaml")
    init = _text("__init__.py")
    combined = readme + plugin + init
    for needle in (
        "Built on",
        "trademark of its owner",
        "not a SwitchBot product",
        "personal use",
        "commercial",
        "large-scale",
        "Cloud Services",
        "Beyond V9.0",
        "Third-party Services",
        "does not enable",
        "hermes tools",
        "allow_admin_from",
        "user_allowed_commands",
        "/switchbot-control",
        "hermes switchbot-control",
        "Choose once",
        "missing, renamed, or raising",
        "GATEWAY_ALLOW_ALL_USERS",
        "trusted_inbound",
        "approvals.timeout",
        "in_process",
        "asyncio.to_thread",
        "576 or more",
        "288",
        "about 420 seconds",
        "about 340 seconds",
        "estimate, not a cap",
        "WoIOSensor",
        "Hub 2",
        "powerState",
        "wakeAgent=false",
        "no_agent=True",
        "watch_fail.json",
        "Disclosure —",
        "Not checked on hardware",
        "zero devices",
        "WoLock",
        "WoCurtain",
        "Video Doorbell",
        "trademark guideline",
        "delivery ledger",
        "10 minutes old",
        "PAUSE state",
        "enableCloudService",
        "future timestamp",
    ):
        assert needle in combined, needle
    for banned in ("Unofficial", "unofficial", "非公式", "not affiliated", "Not affiliated"):
        assert banned not in readme
        assert banned not in plugin
    assert "pip install" not in readme
    assert "manifest_version: 2" in plugin
    assert 'requires_hermes: ">=0.21.4"' in plugin
    assert "license: MIT" in plugin
    assert "version: 0.1.0" in plugin
    assert "python_dependencies" not in plugin
    tree = ast.parse(init)
    slashes = [node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == "_slash"]
    assert len(slashes) == 1
    assert "import tests" not in init
    assert "register_hook" not in init
    assert "statusCode 100, and message success" in init
    assert "Blind Tilt" in init and "Roller Shade" in init
    assert "mode 0, 1, or ff" in init
    assert "Plug Mini" in init
    schema = plugin
    assert "stops the device list, commands, the watch, and schedule" in schema
    assert "Unschedule still works" in schema
    assert "Clamped to 1-10000" in schema
    assert readme.index("Hermes tools") < readme.index("認証とエラー")
    ship = ROOT.parent / "ship" / "switchbot-control"
    if not ship.is_dir():
        pytest.skip("ship drafts are not beside this checkout")
    catalog = (ship / "switchbot-control.yaml").read_text(encoding="utf-8")
    description = catalog.split("description:", 1)[1].split("maintainer:", 1)[0]
    description = description.strip().strip('"')
    assert len(description) <= 800
    assert "Disclosure —" in description
    for needle in (
        "personal use",
        "Commercial",
        "large-scale",
        "infrared",
        "Cloud Services",
        "Beyond V9.0",
        "Third-party Services",
        "does not enable",
        "hermes tools",
        "/switchbot-control",
        "hermes switchbot-control",
        "Choose once",
        "missing, renamed, or raising",
        "GATEWAY_ALLOW_ALL_USERS",
        "webhook",
        "Home Assistant",
        "0.21.4",
        "trusted_inbound",
    ):
        assert needle in description, needle
    pr = (ship / "pr_body.md").read_text(encoding="utf-8")
    for needle in (
        "personal use",
        "commercial",
        "large-scale",
        "hermes tools",
        "allow_admin_from",
        "Disclosure",
        "4xx other than 408",
        "PAUSE state",
        "enableCloudService",
        "another company's page",
        "576 or more",
        "does not take `-p`",
        "asyncio.to_thread",
    ):
        assert needle in pr, needle
    shas = __import__("re").findall(r"\b[0-9a-f]{40}\b", pr)
    assert len(shas) == 1
