---
name: agent-understudy-credentials
description: Use when a command needs an API key, token or password for this project. Never ask the user to paste a secret into the chat; get it through agent-understudy so you only ever see Hide(NAME).
---

# Project credentials with agent-understudy

You never see credential values. You see `Hide(NAME)`; shell commands read `$AGENT_SECRET_<NAME>`.

1. Call the `secret_list` tool. If the credential is listed, use `"$AGENT_SECRET_<NAME>"` in the command. Done.
2. Otherwise call `secret_request` with an UPPER_SNAKE_CASE `name` and a one-line `description` (what it is for, where to get it).
   - If it answers `askInTerminal: true`, call `request_user_input` with **exactly** the `request_user_input` argument it
     returned (keep `"isSecret": true` and the `agent_secret__<NAME>` id). The user picks where to keep it and types the
     value into a masked field. The result you get back says whether it was stored; it never contains the value.
   - If `request_user_input` is unavailable in this mode, call `secret_request` again with `fallback: true`
     (the user gets a system dialog instead).
3. Use the credential only as `"$AGENT_SECRET_<NAME>"` inside shell commands. Never write `Hide(NAME)` where the value is
   needed, never print the variable, never write it into files.
