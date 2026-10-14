# Changelog

## 0.1.1

`SWITCHBOT_TOKEN` and `SWITCHBOT_SECRET` were read from `os.environ` on each call. One Hermes process can serve more than one profile, so that read can use another profile's token and secret. Each call now reads them with `agent.secret_scope.get_secret`. An HTTP proxy set in the environment is not used for API requests.
