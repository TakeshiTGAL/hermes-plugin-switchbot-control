"""SwitchBot OpenAPI v1.1 client.

Checked against api.switch-bot.com on 2026-10-06 with an account that had
zero devices. The sign that was accepted is the Python 3 example in the
official README: base64(HMAC-SHA256(token + timestamp + nonce, secret)).
The short uppercase HMAC(token + timestamp) example was not sent.

Observed bodies, with secrets not included:

- Valid list: HTTP 200, statusCode 100, message success, body.deviceList
  and body.infraredRemoteList (both empty on that account).
- Wrong token, wrong secret, wrong sign, and a timestamp 10 minutes old:
  HTTP 401, JSON {"message": "Unauthorized"}, no statusCode key.
- Unknown device status: HTTP 200, statusCode 100, message success, body {}.
- Unknown device command: HTTP 200, statusCode 190, message
  "Wrong deviceId, No this device", body {}.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

HOST = "https://" + "api.switch-bot.com"
TIMEOUT_SECONDS = 20.0
MAX_BYTES = 1_000_000
MAY_HAVE_MOVED = "The command may have reached the device and moved it."
CHECK_BEFORE_RESEND = (
    "No retry was made. Check the device state first, with switchbot_devices and that device_id "
    "or by looking at the device. Send the command again only if it did not move."
)

Transport = Callable[[str, str, Mapping[str, str], bytes | None, float, int], tuple[int, Mapping[str, str], bytes]]


class ApiError(Exception):
    def __init__(self, code: str, message: str, *, next_step: str = "", http: int | None = None, status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_step = next_step
        self.http = http
        self.status_code = status_code


def sign(token: str, secret: str, timestamp_ms: int, nonce: str) -> str:
    material = f"{token}{timestamp_ms}{nonce}".encode()
    digest = hmac.new(secret.encode(), material, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def redact(text: str, token: str, secret: str) -> str:
    for value in (token, secret):
        if value:
            text = text.replace(value, "[redacted]")
    return text


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):  # noqa: ANN001
        return response

    https_response = http_response


def _urllib_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float, limit: int):
    req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            payload = resp.read(limit + 1)
            return status, dict(resp.headers.items()), payload
    except urllib.error.HTTPError as exc:
        payload = exc.read(limit + 1)
        hdrs = dict(exc.headers.items()) if exc.headers else {}
        return exc.code, hdrs, payload


class SwitchBot:
    def __init__(self, token: str, secret: str, transport: Transport | None = None, now: Callable[[], float] | None = None):
        self.token = token
        self.secret = secret
        self.transport = transport or _urllib_transport
        self.now = now or time.time

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            return self._request(method, path, body)
        except ApiError as err:
            if method == "POST" and _post_may_have_run(err):
                err.message = f"{err.message} {MAY_HAVE_MOVED}"
                err.next_step = CHECK_BEFORE_RESEND
            raise

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        if not path.startswith("/v1.1/") or ".." in path:
            raise ApiError("bad_path", "This plugin only calls SwitchBot v1.1 device paths.", next_step="Use a device id from the account list.")
        timestamp_ms = int(self.now() * 1000)
        nonce = str(uuid.uuid4())
        headers = {
            "Authorization": self.token,
            "Content-Type": "application/json",
            "charset": "utf8",
            "t": str(timestamp_ms),
            "sign": sign(self.token, self.secret, timestamp_ms, nonce),
            "nonce": nonce,
        }
        raw_body = None if body is None else json.dumps(body).encode()
        try:
            status, _hdrs, payload = self.transport(method, HOST + path, headers, raw_body, TIMEOUT_SECONDS, MAX_BYTES)
        except Exception as exc:
            raise ApiError(
                "network",
                f"The SwitchBot API call did not finish ({type(exc).__name__}).",
                next_step="No retry was made. Check the network and try again later.",
            ) from None
        if len(payload) > MAX_BYTES:
            raise ApiError(
                "too_large",
                "The response was over 1000000 bytes, so it was discarded.",
                http=status,
                next_step="Nothing from that body was saved.",
            )
        text = redact(payload.decode("utf-8", "replace"), self.token, self.secret)
        if 300 <= status < 400:
            raise ApiError(
                "redirect",
                f"HTTP {status} was a redirect, which this plugin does not follow.",
                http=status,
                next_step="No second request was made.",
            )
        try:
            parsed = json.loads(text) if text.strip() else {}
        except json.JSONDecodeError:
            raise ApiError(
                "not_json",
                f"HTTP {status} was not a JSON object.",
                http=status,
                next_step="Nothing was treated as a device state.",
            ) from None
        if not isinstance(parsed, dict):
            raise ApiError("not_json", f"HTTP {status} was not a JSON object.", http=status, next_step="Nothing was treated as a device state.")
        status_code = parsed.get("statusCode")
        message = parsed.get("message")
        if status == 401 or message == "Unauthorized":
            raise ApiError(
                "unauthorized",
                "HTTP 401, message Unauthorized. The body had no statusCode.",
                http=status,
                next_step=(
                    "Check the token, the secret, and the clock. "
                    "A timestamp 10 minutes old got this same body. "
                    "The SwitchBot README says that more than 10000 calls in a day returns Unauthorized. "
                    "Other programs can share that account cap. "
                    "No device command was sent by this response."
                ),
            )
        if status != 200 or status_code != 100 or message != "success":
            shown = message if isinstance(message, str) else "no message"
            code_text = status_code if isinstance(status_code, int) else "none"
            raise ApiError(
                "api_error",
                f"HTTP {status}, statusCode {code_text}, message {shown}.",
                http=status,
                status_code=status_code if isinstance(status_code, int) else None,
                next_step="This plugin does not treat that as success.",
            )
        return parsed


def _post_may_have_run(err: ApiError) -> bool:
    """False only when the reply says the command was not run.

    That is a path this plugin refused before sending, an Unauthorized reply, or
    an HTTP 4xx other than 408. Everything else (a timeout, a 5xx, a body that is
    not JSON, a redirect, or HTTP 200 with a statusCode other than 100) may have
    reached the device.
    """
    if err.code in {"bad_path", "unauthorized"}:
        return False
    if isinstance(err.http, int) and 400 <= err.http < 500 and err.http != 408:
        return False
    return True
