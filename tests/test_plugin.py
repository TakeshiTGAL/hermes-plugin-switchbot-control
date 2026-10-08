"""Offline tests. Auth and error bodies are the live API shapes from 2026-10-06."""
from __future__ import annotations

import json

import pytest

import safety
from client import SwitchBot, sign
from policy import is_safety_type, min_gap_seconds, prepare_command
from service import Deps, command, devices, schedule, unschedule, watch

TOKEN = "test-token"
SECRET = "test-secret"


def body_of(**payload) -> bytes:
    return json.dumps(payload).encode()


LIST_EMPTY = {
    "statusCode": 100,
    "body": {"deviceList": [], "infraredRemoteList": []},
    "message": "success",
}
UNAUTHORIZED = {"message": "Unauthorized"}
EMPTY_STATUS = {"statusCode": 100, "body": {}, "message": "success"}
MISSING_COMMAND = {"statusCode": 190, "body": {}, "message": "Wrong deviceId, No this device"}
METER = {
    "statusCode": 100,
    "body": {
        "deviceId": "C271111EC0AB",
        "deviceType": "Meter",
        "hubDeviceId": "FA7310762361",
        "humidity": 52,
        "temperature": 26.1,
    },
    "message": "success",
}
COMMAND_OK = {"statusCode": 100, "body": {}, "message": "success"}


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
    )
    base.update(kw)
    return Deps(**base)


def test_sign_matches_the_official_python3_example():
    assert sign("token", "secret", 1661927531000, "nonce") == "s1htA6ftn0O7EQh7AtZsXax6Vc2DDB7StLvyFLuHxnk="


def test_client_rejects_401_without_status_code():
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    with pytest.raises(Exception) as caught:
        SwitchBot(TOKEN, SECRET, router).request("GET", "/v1.1/devices")
    assert caught.value.code == "unauthorized"
    assert "no statusCode" in caught.value.message


def test_client_rejects_status_190_on_http_200():
    router = Router()
    router.add("/commands", 200, MISSING_COMMAND)
    with pytest.raises(Exception) as caught:
        SwitchBot(TOKEN, SECRET, router).request("POST", "/v1.1/devices/000000000000/commands", {})
    assert caught.value.code == "api_error"
    assert caught.value.status_code == 190
    assert "Wrong deviceId" in caught.value.message


def test_empty_account_list_and_empty_status_are_not_a_reading(tmp_path):
    router = Router()
    router.add("/status", 200, EMPTY_STATUS)
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    listed = json.loads(devices(deps(tmp_path, router), {}))
    assert listed["ok"] is True
    assert listed["device_count"] == 0
    assert listed["infrared_count"] == 0
    empty = json.loads(devices(deps(tmp_path, router), {"device_id": "000000000000"}))
    assert empty["ok"] is False
    assert empty["error"] == "empty_status"
    assert TOKEN not in json.dumps(empty)


def test_meter_status_uses_the_published_example(tmp_path):
    router = Router()
    router.add("/status", 200, METER)
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceList": [{"deviceId": "C271111EC0AB", "deviceName": "Living Room", "deviceType": "Meter"}],
            "infraredRemoteList": [{"deviceId": "02-202007201626-70", "deviceName": "Air", "remoteType": "Air Conditioner"}],
        },
    })
    out = json.loads(devices(deps(tmp_path, router), {"device_id": "C271111EC0AB"}))
    assert out["status"]["temperature"] == 26.1
    assert out["status"]["humidity"] == 52
    assert out["infrared_count"] == 1


def test_lock_command_does_not_call_the_api_when_safety_is_off(tmp_path):
    router = Router()
    out = json.loads(command(deps(tmp_path, router), {"device_id": "ABC123", "command": "unlock"}))
    assert out["ok"] is False
    assert out["error"] == "safety_off"
    assert router.calls == []


def test_turn_on_of_a_lock_type_does_not_post(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceList": [{"deviceId": "LOCK1", "deviceType": "Smart Lock", "deviceName": "Front"}],
            "infraredRemoteList": [],
        },
    })
    out = json.loads(command(deps(tmp_path, router), {"device_id": "LOCK1", "command": "turnOn"}))
    assert out["error"] == "safety_off"
    assert [call["method"] for call in router.calls] == ["GET"]


def test_approved_bot_press_posts_once_and_does_not_claim_motion(tmp_path):
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceList": [{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"}],
            "infraredRemoteList": [],
        },
    })
    out = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is True
    assert out["moved"] is False
    assert out["accepted"] is True
    post = [call for call in router.calls if call["method"] == "POST"]
    assert len(post) == 1
    sent = json.loads(post[0]["body"].decode())
    assert sent == {"command": "press", "parameter": "default", "commandType": "command"}
    assert TOKEN not in json.dumps(out)


def test_denied_approval_does_not_post(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceList": [{"deviceId": "BOT1", "deviceType": "Bot"}], "infraredRemoteList": []},
    })
    out = json.loads(command(
        deps(tmp_path, router, approver=lambda _d, _c: (False, "no")),
        {"device_id": "BOT1", "command": "turnOn"},
    ))
    assert out["moved"] is False
    assert [call["method"] for call in router.calls] == ["GET"]


def test_missing_approval_helper_refuses_before_http(tmp_path, monkeypatch):
    def fake(module, name):
        if name == "_is_cron_approval_context":
            return "missing", None
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)
    router = Router()
    out = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert "cron" in out["message"]
    assert router.calls == []


def test_unknown_command_and_unsafe_id_make_no_call(tmp_path):
    router = Router()
    bad = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "createKey"}))
    assert bad["error"] == "bad_command"
    weird = json.loads(command(deps(tmp_path, router), {"device_id": "../etc", "command": "turnOn"}))
    assert weird["error"] == "bad_device"
    assert router.calls == []


def test_daily_cap_stops_before_the_request(tmp_path):
    (tmp_path / "usage.json").write_text(json.dumps({"utc_date": "2026-10-06", "count": 10000, "warned": True}), encoding="utf-8")
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)

    def frozen() -> float:
        return 1760000000.0

    # 2026-10-09 or whatever that timestamp is; write the matching date after reading it.
    from datetime import datetime, timezone
    day = datetime.fromtimestamp(frozen(), timezone.utc).date().isoformat()
    (tmp_path / "usage.json").write_text(json.dumps({"utc_date": day, "count": 10000, "warned": True}), encoding="utf-8")
    out = json.loads(devices(deps(tmp_path, router, now=frozen, daily_cap=10000), {}))
    assert out["error"] == "daily_cap"
    assert router.calls == []


def test_watch_reports_a_meter_threshold_and_a_later_contact_change(tmp_path):
    router = Router()
    router.add("/C271111EC0AB/status", 200, METER)
    router.add("/CONTACT1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "CONTACT1", "deviceType": "Contact Sensor", "openState": "close"},
    })
    router.add("/v1.1/devices", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceList": [
                {"deviceId": "C271111EC0AB", "deviceType": "Meter"},
                {"deviceId": "CONTACT1", "deviceType": "Contact Sensor"},
                {"deviceId": "BOT1", "deviceType": "Bot"},
            ],
            "infraredRemoteList": [],
        },
    })
    first = json.loads(watch(deps(tmp_path, router, temperature_high_c=26.0), {}))
    assert first["moved"] is False
    assert "temperature is 26.1" in first["message"]
    assert "CONTACT1" not in first["message"]
    assert [call["method"] for call in router.calls] == ["GET", "GET", "GET"]
    router.calls.clear()
    router.routes = [
        ("/C271111EC0AB/status", 200, body_of(**METER)),
        ("/CONTACT1/status", 200, body_of(
            statusCode=100,
            message="success",
            body={"deviceId": "CONTACT1", "deviceType": "Contact Sensor", "openState": "open"},
        )),
        ("/v1.1/devices", 200, body_of(
            statusCode=100,
            message="success",
            body={
                "deviceList": [
                    {"deviceId": "C271111EC0AB", "deviceType": "Meter"},
                    {"deviceId": "CONTACT1", "deviceType": "Contact Sensor"},
                ],
                "infraredRemoteList": [],
            },
        )),
    ]
    second = json.loads(watch(deps(tmp_path, router, temperature_high_c=26.0), {}))
    assert "openState changed from close to open" in second["message"]
    assert "temperature is 26.1" not in second["message"]
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert "deviceName" not in json.dumps(saved)
    assert TOKEN not in json.dumps(saved)


def test_schedule_refuses_a_fast_cron_and_keeps_state_on_unschedule(tmp_path):
    made = {}

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return list(made.values())

        def create_job(self, **kwargs):
            made["job"] = {"id": "job1", "name": kwargs["name"], "schedule_display": kwargs["schedule"]}
            assert "Do not call switchbot_command" in kwargs["prompt"]
            assert "switchbot_watch" in kwargs["prompt"]
            return made["job"]

        def remove_job(self, job_id):
            assert job_id == "job1"
            made.clear()

    fast = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "* * * * *", "local"))
    assert fast["ok"] is False
    slow = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "*/5 * * * *", "local"))
    assert slow["ok"] is True
    (tmp_path / "usage.json").write_text("{}", encoding="utf-8")
    gone = json.loads(unschedule(deps(tmp_path, cron_module=Jobs())))
    assert gone["ok"] is True
    assert (tmp_path / "usage.json").exists()


def test_safety_words_and_parameter_rules():
    assert is_safety_type("Smart Lock")
    assert is_safety_type("Garage Door Opener")
    assert is_safety_type("Keypad")
    assert not is_safety_type("Contact Sensor")
    assert not is_safety_type("Bot")
    assert prepare_command("turnOn", None) == ("turnOn", "default")
    assert prepare_command("setAll", "26,0,1,on") == ("setAll", "26,0,1,on")
    assert isinstance(prepare_command("setAll", "41,1,1,on"), str)
    assert prepare_command("setPosition", "0,ff,80") == ("setPosition", "0,ff,80")
    assert isinstance(prepare_command("setPosition", "0,ff,101"), str)
    assert isinstance(prepare_command("setPosition", "up;60"), str)
    assert isinstance(prepare_command("setPosition", "50"), str)
    assert min_gap_seconds(8, 10000) >= 120


def _list(devices_rows):
    return {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceList": devices_rows, "infraredRemoteList": []},
    }


def test_outdoor_meter_is_not_reported_as_absent(tmp_path):
    router = Router()
    router.add("/WO1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "WO1", "deviceType": "WoIOSensor", "temperature": 31.0, "humidity": 40},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "WO1", "deviceType": "WoIOSensor"}]))
    out = json.loads(watch(deps(tmp_path, router, temperature_high_c=30), {}))
    assert "temperature is 31.0" in out["message"]
    assert "No meter" not in out["message"]
    assert any("/WO1/status" in call["url"] for call in router.calls)


def test_manual_bad_list_does_not_consume_the_next_cron_failure(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, {"statusCode": 100, "message": "success", "body": {}})
    plugin = deps(tmp_path, router)
    manual = json.loads(watch(plugin, {}, advance=False))
    assert manual["ok"] is False
    assert manual["error"] == "bad_list"
    assert "did not update the cron failure record" in manual["message"]
    assert not (tmp_path / "watch_fail.json").exists()
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    cron = json.loads(watch(plugin, {}))
    assert cron["notify"] is True
    assert cron["ok"] is False


def test_manual_unreadable_watch_does_not_claim_a_stored_baseline(tmp_path):
    (tmp_path / "watch.json").write_text("{", encoding="utf-8")
    router = Router()
    router.add("/CONTACT1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "CONTACT1", "deviceType": "Contact Sensor", "openState": "close"},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "CONTACT1", "deviceType": "Contact Sensor"}]))
    out = json.loads(watch(deps(tmp_path, router), {}, advance=False))
    assert "could not be read" in out["message"]
    assert "stored as the baseline" not in out["message"]
    assert "did not update the cron watch" in out["message"]
    assert (tmp_path / "watch.json").read_text(encoding="utf-8") == "{"


def test_unreadable_watch_file_is_not_called_no_change(tmp_path):
    (tmp_path / "watch.json").write_text("{", encoding="utf-8")
    router = Router()
    router.add("/CONTACT1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "CONTACT1", "deviceType": "Contact Sensor", "openState": "close"},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "CONTACT1", "deviceType": "Contact Sensor"}]))
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert "could not be read" in out["message"]
    assert "does not say that nothing changed" in out["message"]
    assert "No threshold crossing" not in out["message"]
    assert out["notify"] is True


def test_dropping_to_zero_devices_is_not_a_normal_empty_account(tmp_path):
    (tmp_path / "watch.json").write_text(
        json.dumps({"devices": {"C271111EC0AB": {"deviceType": "Meter", "temperature": 20}}}),
        encoding="utf-8",
    )
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert "not a normal empty account" in out["message"]
    assert out["notify"] is True
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert "C271111EC0AB" in saved["devices"]


def test_plain_plug_power_change_is_reported(tmp_path):
    (tmp_path / "watch.json").write_text(
        json.dumps({"devices": {"PLUG1": {"deviceType": "Plug", "power": "off"}}}),
        encoding="utf-8",
    )
    router = Router()
    router.add("/PLUG1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "PLUG1", "deviceType": "Plug", "power": "on"},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "PLUG1", "deviceType": "Plug"}]))
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert "power changed from off to on" in out["message"]


def test_plug_mini_power_state_is_not_reported(tmp_path):
    (tmp_path / "watch.json").write_text(
        json.dumps({"devices": {"PLUG1": {"deviceType": "Plug Mini (US)", "powerState": "off"}}}),
        encoding="utf-8",
    )
    router = Router()
    router.add("/PLUG1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {
            "deviceId": "PLUG1",
            "deviceType": "Plug Mini (US)",
            "powerState": "on",
            "weight": 1.2,
            "voltage": 120,
            "electricCurrent": 10,
        },
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "PLUG1", "deviceType": "Plug Mini (US)"}]))
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert "powerState" not in out["message"]
    assert "power changed" not in out["message"]
    assert "Plug Mini on/off is not watched" in out["message"]
    assert "numeric power field is not compared" in out["message"]
    assert out["notify"] is False
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert "powerState" not in saved["devices"]["PLUG1"]


def test_numeric_plug_power_change_is_not_reported(tmp_path):
    (tmp_path / "watch.json").write_text(
        json.dumps({"devices": {"PLUG1": {"deviceType": "Plug Mini (EU)", "power": 1.0}}}),
        encoding="utf-8",
    )
    router = Router()
    router.add("/PLUG1/status", 200, {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "PLUG1", "deviceType": "Plug Mini (EU)", "power": 2.0, "switchStatus": 1},
    })
    router.add("/v1.1/devices", 200, _list([{"deviceId": "PLUG1", "deviceType": "Plug Mini (EU)"}]))
    out = json.loads(watch(deps(tmp_path, router), {}))
    assert "power changed" not in out["message"]
    assert "switchStatus" not in out["message"]
    assert "numeric power field is not compared" in out["message"]
    assert out["notify"] is False


@pytest.mark.parametrize("name", [
    "_is_cron_approval_context",
    "_yolo_active",
    "_get_approval_mode",
    "_is_single_query_approval_context",
    "_is_unattended_platform_approval_context",
    "request_tool_approval",
])
def test_each_private_helper_missing_or_raising_sends_no_command(name, tmp_path, monkeypatch):
    def fake(module, attr):
        if attr == name:
            return "missing", None
        if attr == "_get_approval_mode":
            return "ok", (lambda: "manual")
        if attr == "request_tool_approval":
            return "ok", (lambda *args, **kwargs: {"approved": True})
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)
    router = Router()
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot"}]))
    missing = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert missing["moved"] is False
    assert router.calls == []

    def raising(module, attr):
        if attr == name:
            return "ok", (lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
        if attr == "_get_approval_mode":
            return "ok", (lambda: "manual")
        if attr == "request_tool_approval":
            return "ok", (lambda *args, **kwargs: {"approved": True})
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", raising)
    router.calls.clear()
    raised = json.loads(command(deps(tmp_path, router, approver=None), {"device_id": "BOT1", "command": "turnOn"}))
    assert raised["moved"] is False
    assert not any(call["method"] == "POST" for call in router.calls)


def test_second_unlock_after_always_still_asks(tmp_path, monkeypatch):
    asked = []
    stuck = set()

    def approval(_tool, reason, rule_key=""):
        if rule_key in stuck:
            asked.append({"stuck": True, "reason": reason, "rule_key": rule_key})
            return {"approved": True}
        stuck.add(rule_key)
        asked.append({"stuck": False, "reason": reason, "rule_key": rule_key})
        return {"approved": True}

    def fake(_module, attr):
        if attr == "_get_approval_mode":
            return "ok", (lambda: "manual")
        if attr == "request_tool_approval":
            return "ok", approval
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "LOCK1", "deviceType": "Smart Lock", "deviceName": "Front"},
    ]))
    plugin = deps(tmp_path, router, approver=None, safety_devices=True)
    for _ in range(2):
        out = json.loads(command(plugin, {"device_id": "LOCK1", "command": "unlock"}))
        assert out["ok"] is True
    assert len(asked) == 2
    assert asked[0]["stuck"] is False
    assert asked[1]["stuck"] is False
    assert asked[0]["rule_key"] != asked[1]["rule_key"]
    assert "Front" in asked[0]["reason"]
    assert "Smart Lock" in asked[0]["reason"]
    assert "parameter default" in asked[0]["reason"]
    assert asked[0]["rule_key"].endswith(asked[0]["rule_key"].rsplit(":", 1)[-1])
    assert ":default:" in asked[0]["rule_key"]


def test_set_position_only_for_curtain_types(tmp_path):
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"},
        {"deviceId": "CUR1", "deviceType": "Curtain", "deviceName": "Left"},
    ]))
    refused = json.loads(command(
        deps(tmp_path, router),
        {"device_id": "BOT1", "command": "setPosition", "parameter": "0,ff,0"},
    ))
    assert refused["ok"] is False
    assert "Curtain" in refused["message"]
    assert not any(call["method"] == "POST" for call in router.calls)
    sent = json.loads(command(
        deps(tmp_path, router),
        {"device_id": "CUR1", "command": "setPosition", "parameter": "0,ff,100"},
    ))
    assert sent["ok"] is True
    post = [call for call in router.calls if call["method"] == "POST"]
    assert len(post) == 1


def test_host_process_refuses_a_command_before_http(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_PLUGIN_HOST_PROCESS", "1")
    router = Router()
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot"}]))
    out = json.loads(command(deps(tmp_path, router), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is False
    assert out["error"] == "host_isolation"
    assert router.calls == []


def test_empty_list_notifies_once_and_an_offline_device_keeps_the_rest(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    plugin = deps(tmp_path, router)
    first = json.loads(watch(plugin, {}))
    second = json.loads(watch(plugin, {}))
    assert first["notify"] is True
    assert "Cloud Services" in first["message"]
    assert "not a healthy watch" in first["message"]
    assert "sent once" in first["message"]
    assert second["notify"] is False
    assert "already announced" in second["message"]
    assert "sent once" not in second["message"]
    router.routes.clear()
    router.add("/OFF1/status", 200, {"statusCode": 161, "message": "device offline", "body": {}})
    router.add("/METER1/status", 200, METER)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "OFF1", "deviceType": "Meter"},
        {"deviceId": "METER1", "deviceType": "Meter"},
    ]))
    mixed = json.loads(watch(plugin, {}))
    assert mixed["notify"] is True
    assert "statusCode 161" in mixed["message"]
    assert mixed["readings"] == 1
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert "METER1" in saved["devices"]
    assert "OFF1" not in saved["devices"]
    assert not (tmp_path / "watch.json.tmp").exists()
    router.routes.clear()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    again = json.loads(watch(plugin, {}))
    assert again["notify"] is True
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    failed = json.loads(watch(plugin, {}))
    assert failed["notify"] is True
    router.routes.clear()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    after_failure = json.loads(watch(plugin, {}))
    assert after_failure["notify"] is True
    assert "previous watch file" in after_failure["message"]
    assert "has cleared" in after_failure["message"]


def test_one_status_failure_does_not_hide_another_door(tmp_path):
    router = Router()
    closed = {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "DOOR1", "deviceType": "Contact Sensor", "openState": "close"},
    }
    opened = {
        "statusCode": 100,
        "message": "success",
        "body": {"deviceId": "DOOR1", "deviceType": "Contact Sensor", "openState": "open"},
    }
    listing = _list([
        {"deviceId": "BAD1", "deviceType": "Meter"},
        {"deviceId": "DOOR1", "deviceType": "Contact Sensor"},
    ])
    router.add("/BAD1/status", 200, METER)
    router.add("/DOOR1/status", 200, closed)
    router.add("/v1.1/devices", 200, listing)
    plugin = deps(tmp_path, router)
    baseline = json.loads(watch(plugin, {}))
    assert baseline["readings"] == 2
    router.routes.clear()
    router.add("/BAD1/status", 200, {"statusCode": 190, "message": "Wrong deviceId, No this device", "body": {}})
    router.add("/DOOR1/status", 200, opened)
    router.add("/v1.1/devices", 200, listing)
    opened_tick = json.loads(watch(plugin, {}))
    assert opened_tick["ok"] is True
    assert opened_tick["notify"] is True
    assert "BAD1" in opened_tick["message"]
    assert "statusCode 190" in opened_tick["message"]
    assert "DOOR1" in opened_tick["message"]
    assert "openState changed from close to open" in opened_tick["message"]
    saved = json.loads((tmp_path / "watch.json").read_text(encoding="utf-8"))
    assert saved["devices"]["DOOR1"]["openState"] == "open"
    assert saved["faults"]["BAD1"] == 190
    repeat = json.loads(watch(plugin, {}))
    assert repeat["notify"] is False
    assert "statusCode 190" in repeat["message"]
    router.routes.clear()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    gap = json.loads(watch(plugin, {}))
    assert gap["notify"] is True
    assert "previous watch file" in gap["message"]
    quiet_gap = json.loads(watch(plugin, {}))
    assert quiet_gap["notify"] is False
    assert "previous watch file" in quiet_gap["message"]


def test_watch_failure_notifies_only_the_first_of_a_streak(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    plugin = deps(tmp_path, router, approver=lambda _d, _c: (True, ""))
    first = json.loads(watch(plugin, {}))
    second = json.loads(watch(plugin, {}))
    assert first["notify"] is True
    assert first["ok"] is False
    assert second["notify"] is False
    router.routes.clear()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    ok = json.loads(watch(plugin, {}))
    assert ok["ok"] is True
    assert ok["notify"] is True
    assert "has cleared" in ok["message"]
    quiet = json.loads(watch(plugin, {}))
    assert quiet["notify"] is False
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    again = json.loads(watch(plugin, {}))
    assert again["notify"] is True


@pytest.mark.parametrize("first", ["every", "Every", "in", "5m", "10", "*/5", "@daily", "monday", "daily"])
def test_schedule_refuses_a_schedule_word_as_the_delivery_target(first, tmp_path):
    from service import slash_schedule_args

    created = []

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            created.append(kwargs)
            return {"id": "job1"}

    when, deliver = slash_schedule_args(["schedule", first, "5m"])
    out = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), when, deliver))
    assert out["ok"] is False
    assert out["error"] == "deliver_looks_like_schedule"
    assert "schedule telegram every 10m" in out["next_step"]
    assert created == []


def test_schedule_still_accepts_a_real_delivery_target(tmp_path):
    from service import slash_schedule_args

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            return {"id": "job1", "schedule_display": kwargs["schedule"], "deliver": kwargs["deliver"]}

    for parts in (["schedule", "telegram", "every", "10m"], ["schedule", "discord:123", "*/5", "*", "*", "*", "*"]):
        when, deliver = slash_schedule_args(parts)
        out = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), when, deliver))
        assert out["ok"] is True
        assert out["deliver"] == parts[1]


def test_bad_number_config_stops_list_command_watch_and_schedule(tmp_path):
    router = Router()
    plugin = deps(tmp_path, router, config_problem="temperature_high_c is not a number, so no API call was made.")
    for out in (
        devices(plugin, {}),
        command(plugin, {"device_id": "BOT1", "command": "press"}),
        watch(plugin, {}),
        schedule(plugin, "*/5 * * * *", "local"),
    ):
        body = json.loads(out)
        assert body["ok"] is False
        assert body["error"] == "bad_config"
    assert router.calls == []


def test_watch_bad_arguments_do_not_start_a_failure_streak(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    plugin = deps(tmp_path, router)
    wrong = json.loads(watch(plugin, {"device_id": "X"}))
    assert wrong["ok"] is False
    assert wrong["error"] == "bad_args"
    assert wrong["notify"] is False
    assert not (tmp_path / "watch_fail.json").exists()
    assert router.calls == []
    first_real = json.loads(watch(plugin, {}))
    assert first_real["notify"] is True


def _approval_reasons(monkeypatch):
    asked = []

    def approval(_tool, reason, rule_key=""):
        asked.append(reason)
        return {"approved": True}

    def fake(_module, attr):
        if attr == "_get_approval_mode":
            return "ok", (lambda: "manual")
        if attr == "request_tool_approval":
            return "ok", approval
        return "ok", (lambda: False)

    monkeypatch.setattr(safety, "_load", fake)
    return asked


def test_curtain_approval_says_turn_off_closes_and_turn_on_opens(tmp_path, monkeypatch):
    asked = _approval_reasons(monkeypatch)
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "CUR1", "deviceType": "Curtain3", "deviceName": "Left"},
        {"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"},
    ]))
    plugin = deps(tmp_path, router, approver=None)
    for device_id, name, parameter in (
        ("CUR1", "turnOff", None),
        ("CUR1", "turnOn", None),
        ("CUR1", "setPosition", "0,ff,30"),
        ("BOT1", "turnOff", None),
    ):
        args = {"device_id": device_id, "command": name}
        if parameter:
            args["parameter"] = parameter
        assert json.loads(command(plugin, args))["ok"] is True
    assert "close the curtain (position 100)" in asked[0]
    assert "open the curtain (position 0)" in asked[1]
    assert "position 30 (0 is open, 100 is closed)" in asked[2]
    assert "curtain" not in asked[3]


def test_blind_tilt_refusal_does_not_give_the_curtain_direction(tmp_path):
    router = Router()
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BT1", "deviceType": "Blind Tilt", "deviceName": "Study"}]))
    out = json.loads(command(deps(tmp_path, router), {"device_id": "BT1", "command": "setPosition", "parameter": "0,ff,0"}))
    assert out["ok"] is False
    assert "Blind Tilt" in out["message"]
    assert "0 is open" not in out["message"] + out["next_step"]
    assert not any(call["method"] == "POST" for call in router.calls)


def test_command_post_timeout_says_it_may_have_moved(tmp_path):
    calls = []

    def transport(method, url, headers, body, timeout, read_limit):
        calls.append(method)
        if method == "POST":
            raise TimeoutError("timed out")
        return 200, {}, body_of(**_list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"}]))

    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is False
    assert out["error"] == "network"
    assert "may have reached the device" in out["message"]
    assert "Check the device state first" in out["next_step"]
    assert "try again later" not in out["next_step"]
    assert calls == ["GET", "POST"]


def test_list_timeout_is_still_a_plain_network_failure(tmp_path):
    def transport(method, url, headers, body, timeout, read_limit):
        raise TimeoutError("timed out")

    out = json.loads(devices(deps(tmp_path, transport), {}))
    assert out["error"] == "network"
    assert "may have" not in out["message"]


def _post_reply(status, payload: bytes):
    calls = []

    def transport(method, url, headers, body, timeout, read_limit):
        calls.append(method)
        if method == "POST":
            return status, {}, payload
        return 200, {}, body_of(**_list([{"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Coffee"}]))

    return transport, calls


@pytest.mark.parametrize("status,payload", [
    (502, b"<html>Bad Gateway</html>"),
    (504, b'{"message": "Gateway Timeout"}'),
    (200, b"<html>not json</html>"),
    (200, body_of(**MISSING_COMMAND)),
])
def test_unclear_command_reply_says_it_may_have_moved(status, payload, tmp_path):
    transport, calls = _post_reply(status, payload)
    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is False
    assert "may have reached the device and moved it" in out["message"]
    assert "Check the device state first" in out["next_step"]
    assert "Send the command again only if it did not move" in out["next_step"]
    assert calls == ["GET", "POST"]


@pytest.mark.parametrize("status,payload", [
    (401, body_of(**UNAUTHORIZED)),
    (400, b'{"message": "Bad Request"}'),
    (403, b'{"message": "Forbidden"}'),
    (404, b'{"message": "Not Found"}'),
])
def test_rejected_command_reply_does_not_say_it_may_have_moved(status, payload, tmp_path):
    transport, _calls = _post_reply(status, payload)
    out = json.loads(command(deps(tmp_path, transport), {"device_id": "BOT1", "command": "press"}))
    assert out["ok"] is False
    assert "may have reached" not in out["message"]


def test_status_read_502_does_not_say_it_may_have_moved(tmp_path):
    router = Router()
    router.add("/BOT1/status", 502, {"message": "Bad Gateway"})
    router.add("/v1.1/devices", 200, _list([{"deviceId": "BOT1", "deviceType": "Bot"}]))
    out = json.loads(devices(deps(tmp_path, router), {"device_id": "BOT1"}))
    assert out["ok"] is False
    assert "may have" not in out["message"]


def test_watch_failure_streak_notifies_again_after_24_hours(tmp_path):
    clock = [1_800_000_000.0]
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    plugin = deps(tmp_path, router, now=lambda: clock[0])
    assert json.loads(watch(plugin, {}))["notify"] is True
    clock[0] += 23 * 3600
    assert json.loads(watch(plugin, {}))["notify"] is False
    clock[0] += 3600
    assert json.loads(watch(plugin, {}))["notify"] is True
    clock[0] += 600
    assert json.loads(watch(plugin, {}))["notify"] is False
    clock[0] += 24 * 3600
    assert json.loads(watch(plugin, {}))["notify"] is True


def test_watch_failure_with_a_future_notice_time_notifies(tmp_path):
    clock = [1_800_000_000.0]
    router = Router()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    (tmp_path / "watch_fail.json").write_text(
        json.dumps({"streak": 3, "empty": 0, "notified_at": clock[0] + 7 * 86400}), encoding="utf-8",
    )
    plugin = deps(tmp_path, router, now=lambda: clock[0])
    assert json.loads(watch(plugin, {}))["notify"] is True
    assert json.loads(watch(plugin, {}))["notify"] is False


class _RecordingJobs:
    def __init__(self):
        self.created = []

    def list_jobs(self, include_disabled=True):
        return []

    def create_job(self, **kwargs):
        self.created.append(kwargs)
        return {"id": "job1", "schedule_display": kwargs["schedule"]}


def _install_live_deliver_set(monkeypatch, names):
    import sys
    import types

    cron_pkg = types.ModuleType("cron")
    cron_pkg.__path__ = []
    delivery = types.ModuleType("cron.scheduler_delivery")
    delivery._KNOWN_DELIVERY_PLATFORMS = frozenset(names)
    monkeypatch.setitem(sys.modules, "cron", cron_pkg)
    monkeypatch.setitem(sys.modules, "cron.scheduler_delivery", delivery)


def _install_plugin_registry(monkeypatch, entries):
    import sys
    import types

    gateway_pkg = types.ModuleType("gateway")
    gateway_pkg.__path__ = []
    registry_mod = types.ModuleType("gateway.platform_registry")

    class Registry:
        def registered_names(self):
            return list(entries)

        def get(self, name):
            env = entries.get(name)
            if env is None and name not in entries:
                return None

            class Entry:
                cron_deliver_env_var = env

            return Entry()

    registry_mod.platform_registry = Registry()
    monkeypatch.setitem(sys.modules, "gateway", gateway_pkg)
    monkeypatch.setitem(sys.modules, "gateway.platform_registry", registry_mod)


def test_schedule_refuses_homeassistant_when_the_running_hermes_does_not_deliver_it(tmp_path, monkeypatch):
    _install_live_deliver_set(monkeypatch, {"telegram", "discord"})
    _install_plugin_registry(monkeypatch, {"homeassistant": ""})
    jobs = _RecordingJobs()
    out = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "homeassistant"))
    assert out["ok"] is False and out["error"] == "bad_deliver"
    assert jobs.created == []
    chat = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "homeassistant:mobile_app"))
    assert chat["ok"] is False and chat["error"] == "bad_deliver"
    assert jobs.created == []
    kept = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "telegram"))
    assert kept["ok"] is True and kept["deliver"] == "telegram"
    assert jobs.created[0]["deliver"] == "telegram"


def test_schedule_accepts_homeassistant_when_the_running_hermes_lists_it(tmp_path, monkeypatch):
    _install_live_deliver_set(monkeypatch, {"telegram", "homeassistant"})
    jobs = _RecordingJobs()
    out = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "homeassistant"))
    assert out["ok"] is True and out["deliver"] == "homeassistant"
    assert jobs.created[0]["deliver"] == "homeassistant"


def test_schedule_accepts_a_plugin_platform_with_a_cron_env_var(tmp_path, monkeypatch):
    _install_live_deliver_set(monkeypatch, {"telegram"})
    _install_plugin_registry(monkeypatch, {"ntfy": "NTFY_HOME_CHANNEL"})
    jobs = _RecordingJobs()
    out = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "ntfy"))
    assert out["ok"] is True and out["deliver"] == "ntfy"
    assert jobs.created[0]["deliver"] == "ntfy"


def test_schedule_keeps_the_floor_list_when_hermes_delivery_cannot_be_read(tmp_path, monkeypatch):
    import builtins
    import sys

    monkeypatch.delitem(sys.modules, "cron.scheduler_delivery", raising=False)
    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "cron.scheduler_delivery":
            raise ImportError("hermes delivery list is unreadable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    jobs = _RecordingJobs()
    out = json.loads(schedule(deps(tmp_path, cron_module=jobs), "*/5 * * * *", "homeassistant"))
    assert out["ok"] is True and out["deliver"] == "homeassistant"
    assert jobs.created[0]["deliver"] == "homeassistant"


@pytest.mark.parametrize("target", ["cli", "cron", "api_server", "telegarm", "bot-chat:"])
def test_unknown_deliver_targets_are_refused(tmp_path, target):
    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            raise AssertionError(kwargs)

    out = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "*/5 * * * *", target))
    assert out["ok"] is False and out["error"] == "bad_deliver"


def test_bot_chat_deliver_says_it_starts_a_model_turn(tmp_path):
    made = {}

    class Jobs:
        def list_jobs(self, include_disabled=True):
            return []

        def create_job(self, **kwargs):
            made["deliver"] = kwargs["deliver"]
            return {"id": "job1", "schedule_display": kwargs["schedule"]}

    out = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "*/5 * * * *", "bot-chat"))
    assert out["ok"] is True and made["deliver"] == "bot-chat"
    assert "one model turn" in out["message"] and "agent can act" in out["message"]
    both = json.loads(schedule(deps(tmp_path, cron_module=Jobs()), "*/5 * * * *", "origin,all"))
    assert both["ok"] is True and both["deliver"] == "origin,all"


def _contact_routes(open_state: str):
    return [
        ("/CONTACT1/status", 200, body_of(
            statusCode=100, message="success",
            body={"deviceId": "CONTACT1", "deviceType": "Contact Sensor", "openState": open_state},
        )),
        ("/v1.1/devices", 200, body_of(
            statusCode=100, message="success",
            body={"deviceList": [{"deviceId": "CONTACT1", "deviceType": "Contact Sensor"}], "infraredRemoteList": []},
        )),
    ]


def _load_switchbot(tmp_path, router, monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("SWITCHBOT_TOKEN", TOKEN)
    monkeypatch.setenv("SWITCHBOT_SECRET", SECRET)
    spec = importlib.util.spec_from_file_location(
        "switchbot_fix3_plugin", root / "__init__.py", submodule_search_locations=[str(root)],
    )
    module = importlib.util.module_from_spec(spec)
    module.__path__ = [str(root)]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    class Ctx:
        def __init__(self):
            self.tools = {}
            self.command = None
            self.cli = None

        def register_tool(self, name, toolset, schema, handler, **kwargs):
            self.tools[name] = handler

        def register_command(self, name, handler, description=""):
            self.command = handler

        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            self.cli = handler_fn

        def get_config(self, key, default=None):
            return default

    ctx = Ctx()
    module.register(ctx)
    service_mod = sys.modules[spec.name + ".service"]
    client_mod = sys.modules[spec.name + ".client"]
    monkeypatch.setattr(service_mod, "plugin_data_dir", lambda: tmp_path)
    if router is not None:
        def client(deps):
            return client_mod.SwitchBot(deps.token, deps.secret, router, deps.now)

        monkeypatch.setattr(service_mod, "_client", client)
    return ctx, service_mod, client_mod


def _capture_cli(handler, args) -> str:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        handler(args)
    return buf.getvalue()


def test_plugin_host_watch_does_not_report_devices_unchanged(tmp_path, monkeypatch):
    router = Router()
    ctx, _service_mod, _client_mod = _load_switchbot(tmp_path, router, monkeypatch)
    monkeypatch.setenv("HERMES_PLUGIN_HOST_PROCESS", "1")
    body = json.loads(ctx.tools["switchbot_watch"]({}))
    assert body["ok"] is False
    assert body["error"] == "plugin_host"
    assert body["notify"] is True
    assert "cannot watch" in body["message"]
    assert "unchanged" in body["message"]
    assert "cron mark" in body["message"]
    assert not (tmp_path / "watch.json").exists()
    assert router.calls == []


def test_tool_watch_without_a_cron_mark_does_not_report_unchanged(tmp_path, monkeypatch):
    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    ctx, service_mod, _client_mod = _load_switchbot(tmp_path, router, monkeypatch)
    monkeypatch.setattr(service_mod, "cron_mark", lambda: "unknown")
    body = json.loads(ctx.tools["switchbot_watch"]({}))
    assert body["ok"] is False
    assert body["error"] == "cron_mark"
    assert body["notify"] is True
    assert "cannot watch" in body["message"]
    assert "unchanged" in body["message"]
    assert router.calls == []
    assert not (tmp_path / "watch.json").exists()
    assert not (tmp_path / "watch_fail.json").exists()


def test_manual_paths_do_not_consume_a_cron_event(tmp_path, monkeypatch):
    import asyncio

    router = Router()
    router.routes = _contact_routes("close")
    ctx, service_mod, _client_mod = _load_switchbot(tmp_path, router, monkeypatch)
    cron_on = {"value": True}
    monkeypatch.setattr(service_mod, "cron_mark", lambda: "cron" if cron_on["value"] else "manual")

    def baseline():
        router.routes = _contact_routes("close")
        cron_on["value"] = True
        first = json.loads(ctx.tools["switchbot_watch"]({}))
        assert first["ok"] is True and "changed" not in first["message"]
        assert (tmp_path / "watch.json").is_file()

    def manual_then_cron(manual):
        router.routes = _contact_routes("open")
        before = (tmp_path / "watch.json").read_text(encoding="utf-8")
        cron_on["value"] = False
        seen = json.loads(manual())
        assert "openState changed from close to open" in seen["message"]
        assert (tmp_path / "watch.json").read_text(encoding="utf-8") == before
        cron_on["value"] = True
        again = json.loads(ctx.tools["switchbot_watch"]({}))
        assert "openState changed from close to open" in again["message"]

    baseline()
    manual_then_cron(lambda: asyncio.run(ctx.command("watch")))
    (tmp_path / "watch.json").unlink()
    baseline()

    class Args:
        switchbot_command = "watch"

    manual_then_cron(lambda: _capture_cli(ctx.cli, Args()))
    (tmp_path / "watch.json").unlink()
    baseline()
    manual_then_cron(lambda: ctx.tools["switchbot_watch"]({}))


def test_manual_failure_does_not_silence_the_next_cron(tmp_path, monkeypatch):
    import asyncio

    router = Router()
    router.add("/v1.1/devices", 200, LIST_EMPTY)
    ctx, service_mod, _client_mod = _load_switchbot(tmp_path, router, monkeypatch)
    cron_on = {"value": True}
    monkeypatch.setattr(service_mod, "cron_mark", lambda: "cron" if cron_on["value"] else "manual")
    assert json.loads(ctx.tools["switchbot_watch"]({}))["ok"] is True
    router.routes.clear()
    router.add("/v1.1/devices", 401, UNAUTHORIZED)
    for manual in (
        lambda: asyncio.run(ctx.command("watch")),
        lambda: _capture_cli(ctx.cli, type("A", (), {"switchbot_command": "watch"})()),
        lambda: ctx.tools["switchbot_watch"]({}),
    ):
        fail_path = tmp_path / "watch_fail.json"
        if fail_path.exists():
            fail_path.unlink()
        cron_on["value"] = False
        seen = json.loads(manual())
        assert seen["notify"] is True
        assert not fail_path.exists()
        cron_on["value"] = True
        cron = json.loads(ctx.tools["switchbot_watch"]({}))
        assert cron["notify"] is True
        assert fail_path.exists()


def test_v0214_dispatch_awaits_a_slow_slash_without_blocking_the_loop(tmp_path, monkeypatch):
    import asyncio
    import time
    from pathlib import Path

    started = {"value": False}

    class Slow(Router):
        def __call__(self, method, url, headers, body, timeout, read_limit):
            started["value"] = True
            time.sleep(0.4)
            payload = b'{"statusCode":100,"message":"success","body":{"deviceList":[],"infraredRemoteList":[]}}'
            return 200, {"content-type": "application/json"}, payload

    ctx, _service_mod, _client_mod = _load_switchbot(tmp_path, Slow(), monkeypatch)
    source_path = Path(__file__).resolve().parents[2] / "hermes-agent-ref-v0214" / "gateway" / "run_inbound.py"
    if source_path.is_file():
        source = source_path.read_text(encoding="utf-8")
        assert "if asyncio.iscoroutine(result):" in source
        assert "result = await result" in source

    async def run():
        flag = {"ran": False}

        async def sibling():
            await asyncio.sleep(0.05)
            flag["ran"] = True

        task = asyncio.create_task(sibling())
        result = ctx.command("watch")
        if asyncio.iscoroutine(result):
            result = await result
        await task
        return flag["ran"], result

    ran, text = asyncio.run(run())
    assert ran is True and started["value"] is True
    assert "Read" in text or "empty" in text or "could not" in text
