"""SwitchBot OpenAPI tools for Hermes. This does not use Home Assistant or BLE."""

import asyncio


def register(ctx) -> None:
    if __package__:
        from .service import (
            DEFAULT_SCHEDULE,
            TOOLSET,
            command,
            deps_from_config,
            devices,
            schedule,
            slash_schedule_args,
            unschedule,
            watch,
        )
    else:
        from service import (
            DEFAULT_SCHEDULE,
            TOOLSET,
            command,
            deps_from_config,
            devices,
            schedule,
            slash_schedule_args,
            unschedule,
            watch,
        )

    def _deps():
        import os
        return deps_from_config(
            ctx.get_config,
            token=os.environ.get("SWITCHBOT_TOKEN", ""),
            secret=os.environ.get("SWITCHBOT_SECRET", ""),
        )

    def _devices(args, **_kwargs):
        return devices(_deps(), args or {})

    def _command(args, **_kwargs):
        return command(_deps(), args or {})

    def _watch(args, **_kwargs):
        if __package__:
            from . import service as svc
        else:
            import service as svc
        return watch(_deps(), args or {}, advance=svc._is_cron_turn())

    ctx.register_tool(
        name="switchbot_devices",
        toolset=TOOLSET,
        schema={
            "name": "switchbot_devices",
            "description": (
                "List SwitchBot devices and infrared remotes on the configured account. "
                "Pass device_id to also read that device's status. "
                "An empty status body is not reported as a device state. Does not send a command."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string", "description": "Optional device id from the account list."},
                },
            },
        },
        handler=_devices,
        emoji="🏠",
    )
    ctx.register_tool(
        name="switchbot_command",
        toolset=TOOLSET,
        schema={
            "name": "switchbot_command",
            "description": (
                "Send one whitelisted SwitchBot command. Each call asks Hermes for approval with a new rule, so a previous always or session choice does not cover the next call. "
                "lock, unlock, and deadbolt, and lock, keypad, garage, or door device types, "
                "are refused unless safety_devices is enabled, and still ask for approval. "
                "Does nothing from cron, yolo, approvals off, a single-query session, an unattended session, "
                "or when an approval helper is missing, renamed, or raises. "
                "The API accepted the command only when the response is HTTP 200, statusCode 100, and message success. "
                "That does not mean the device was observed to move."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "command": {"type": "string"},
                    "parameter": {
                        "type": "string",
                        "description": (
                            "default, or a Curtain or Curtain3 position from 0,ff,0 through 0,ff,100, with mode 0, 1, or ff. "
                            "0 is open and 100 is closed (0=開、100=閉). "
                            "Sent only when the device type is Curtain or Curtain3. "
                            "Blind Tilt's up;60 and Roller Shade's 0 through 100 are refused. setAll, or a channel."
                        ),
                    },
                },
                "required": ["device_id", "command"],
            },
        },
        handler=_command,
        emoji="⏻",
    )
    ctx.register_tool(
        name="switchbot_watch",
        toolset=TOOLSET,
        schema={
            "name": "switchbot_watch",
            "description": (
                "Read meters (including WoIOSensor), contact sensors, and plugs and compare them with the previous sample. "
                "Reports a temperature, humidity, or plug-weight threshold only when config sets one, "
                "and reports contact openState or the plain Plug power field only after it changes. "
                "It does not report Plug Mini on or off. Does not send a command. Takes no arguments. "
                "A chat, slash, or CLI check does not update the cron watch. Only a cron turn writes watch.json and watch_fail.json."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_watch,
        emoji="👀",
    )

    def _slash_sync(raw_args: str) -> str:
        parts = (raw_args or "").split()
        cmd = parts[0] if parts else "devices"
        if cmd == "devices":
            return _devices({})
        if cmd == "watch":
            return watch(_deps(), {}, advance=False)
        if cmd == "schedule":
            when, deliver = slash_schedule_args(parts)
            return schedule(_deps(), when, deliver)
        if cmd == "unschedule":
            return unschedule(_deps())
        return (
            "Usage: /switchbot-control devices | watch | "
            "schedule <deliver> [schedule] | unschedule. "
            "Put the delivery target first, as in schedule telegram every 10m. "
            "Commands stay on the switchbot_command tool, which asks for approval."
        )

    async def _slash(raw_args: str) -> str:
        return await asyncio.to_thread(_slash_sync, raw_args)

    ctx.register_command(
        "switchbot-control",
        handler=_slash,
        description="List SwitchBot devices or schedule a watch. Commands ask for approval.",
    )

    def _setup(parser) -> None:
        subs = parser.add_subparsers(dest="switchbot_command")
        subs.add_parser("devices", help="List devices and infrared remotes. Does not send a command.")
        subs.add_parser("watch", help="Compare meters, contacts, and plugs. Does not send a command.")
        scheduled = subs.add_parser(
            "schedule",
            help="Create a cron job whose prompt calls switchbot_watch only. The toolset still includes switchbot_command. Cron cannot send a command.",
        )
        scheduled.add_argument("--deliver", default="", help="telegram, discord, slack, local, or platform:chat_id. Required.")
        scheduled.add_argument("--schedule", default=DEFAULT_SCHEDULE, help="No faster than the daily cap allows.")
        subs.add_parser(
            "unschedule",
            help="Remove the cron job. Keeps usage.json, watch.json, and watch_fail.json.",
        )

    def _cli(args) -> None:
        cmd = getattr(args, "switchbot_command", None) or "devices"
        deps = _deps()
        if cmd == "watch":
            print(watch(deps, {}, advance=False))
        elif cmd == "schedule":
            print(schedule(deps, args.schedule, args.deliver))
        elif cmd == "unschedule":
            print(unschedule(deps))
        else:
            print(devices(deps, {}))

    ctx.register_cli_command(
        name="switchbot-control",
        help="List SwitchBot devices and schedule a watch.",
        setup_fn=_setup,
        handler_fn=_cli,
        description="Read the SwitchBot OpenAPI. Commands stay on the tool, which asks for approval.",
    )


__all__ = ["register"]
