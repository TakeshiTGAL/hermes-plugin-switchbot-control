"""Argument shapes a model is likely to send. No network."""
import json

from test_plugin import COMMAND_OK, Router, _list, command, deps


def _curtain(tmp_path):
    router = Router()
    router.add("/commands", 200, COMMAND_OK)
    router.add("/v1.1/devices", 200, _list([
        {"deviceId": "CUR1", "deviceType": "Curtain", "deviceName": "Left"},
        {"deviceId": "BOT1", "deviceType": "Bot", "deviceName": "Lamp"},
    ]))
    return router, deps(tmp_path, router)


def test_unique_command_case_and_device_width_are_sent(tmp_path):
    router, plugin = _curtain(tmp_path)
    seen = []
    plugin.approver = lambda device, cmd: seen.append((device, cmd)) or (True, "")
    out = json.loads(command(plugin, {"device_id": "ＢＯＴ1", "command": "turnon", "parameter": "Default"}))
    assert out["ok"] is True
    assert out["accepted"] is True
    assert seen == [("BOT1", "turnOn")]
    posted = [call for call in router.calls if call["method"] == "POST"]
    sent = json.loads(posted[0]["body"].decode())
    assert sent["command"] == "turnOn"
    assert sent["parameter"] == "default"


def test_integral_position_forms_are_sent_as_integers(tmp_path):
    router, plugin = _curtain(tmp_path)
    for parameter in ("0,ff,10.0", "０,ff,１０"):
        router.calls.clear()
        out = json.loads(command(plugin, {"device_id": "CUR1", "command": "setPosition", "parameter": parameter}))
        assert out["ok"] is True, parameter
        posted = [call for call in router.calls if call["method"] == "POST"]
        sent = json.loads(posted[0]["body"].decode())
        assert sent == {"command": "setPosition", "parameter": "0,ff,10", "commandType": "command"}


def test_extra_argument_is_refused_without_the_name(tmp_path):
    router, plugin = _curtain(tmp_path)
    out = json.loads(command(plugin, {"device_id": "BOT1", "command": "turnOn", "safety_devices": True}))
    text = json.dumps(out)
    assert out["ok"] is False
    assert out["error_type"] == "bad_args"
    assert "for example command turnOn" in out["message"]
    assert "safety_devices" not in text
    assert router.calls == []


def test_missing_command_names_an_example(tmp_path):
    router, plugin = _curtain(tmp_path)
    out = json.loads(command(plugin, {"device_id": "LAMP9"}))
    text = json.dumps(out)
    assert out["ok"] is False
    assert out["error_type"] == "bad_args"
    assert "device_id and command are required" in out["message"]
    assert "for example device_id BOT1 and command turnOn" in out["message"]
    assert "LAMP9" not in text
    assert router.calls == []


def test_fractional_and_out_of_range_positions_are_refused(tmp_path):
    router, plugin = _curtain(tmp_path)
    for parameter in ("0,ff,10.5", "0,ff,101"):
        router.calls.clear()
        out = json.loads(command(plugin, {"device_id": "CUR1", "command": "setPosition", "parameter": parameter}))
        text = json.dumps(out)
        assert out["ok"] is False
        assert out["error_type"] == "bad_command"
        assert "0,ff,0" in out["message"]
        assert "10.5" not in text
        assert "101" not in text
        assert not any(call["method"] == "POST" for call in router.calls)


def test_nonzero_curtain_index_is_refused(tmp_path):
    router, plugin = _curtain(tmp_path)
    out = json.loads(command(plugin, {"device_id": "CUR1", "command": "setPosition", "parameter": "1,ff,40"}))
    text = json.dumps(out)
    assert out["ok"] is False
    assert out["error_type"] == "bad_command"
    assert "must be 0" in out["message"]
    assert "0,ff,40" in out["message"]
    assert "1,ff,40" not in text
    assert not any(call["method"] == "POST" for call in router.calls)
