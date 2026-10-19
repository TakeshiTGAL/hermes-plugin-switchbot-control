# Changelog

## 0.1.2

Scheduling to telegram (and the other chat platforms) works again on Hermes main, which no longer lists those names in `_KNOWN_DELIVERY_PLATFORMS` until plugins are discovered. Hermes v0.22.2 was not affected.

With Tool Search left at its default, this plugin's tools are hidden, so the skill no longer sets requires_toolsets and stays in the model's skill list.

A unique command in any letter case, and a position written as 10.0 or fullwidth digits, are accepted. Extra arguments, a missing command, and a position outside the range are refused with a fix and an example, and the caller's value is not copied into the message.

setPosition refuses a first value other than 0, and an empty value gets the usual 0,ff,0 through 0,ff,100 message. The refusal says to send 0, then the mode (0, 1, or ff), then a position from 0 to 100, for example 0,ff,40. Nothing is sent.

The first sentence Tool Search shows now uses the words a person would ask with. A sentence that starts by describing the mechanism is not found, and the model falls through to the built-in web_search.

## 0.1.1

`SWITCHBOT_TOKEN` and `SWITCHBOT_SECRET` were read from `os.environ` on each call. One Hermes process can serve more than one profile, so that read can use another profile's token and secret. Each call now reads them with `agent.secret_scope.get_secret`. An HTTP proxy set in the environment is not used for API requests.

