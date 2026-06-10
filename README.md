# SecureScripts Luau Logger

Defensive runtime monitor for Roblox script analysis. Run it **before** a suspected script (autoexec, or execute first). It hooks the executor + Roblox APIs and logs what the next script does in the live game — RemoteEvent fires, HTTP requests, file writes, loadstring — so you can spot item-stealers, trade scams and cookie loggers. In-game GUI, console, or live-stream to the SecureScripts app. Auto-blocks Discord RPC. Defensive monitoring only; never breaks the game.

## Usage

```lua
getgenv().SS_LOGGER_CONFIG = { mode = "gui", blockRPC = true, httpLogger = true, remoteLogger = true }
loadstring(game:HttpGet("https://raw.githubusercontent.com/RealSlimShady2000/SecureScriptsLogger/main/logger.lua"))()
```

Toggles (all default true): `httpLogger`, `remoteLogger`, `fsLogger`, `loadstringLogger`, `clipboardLogger`, `persistLogger`, `gameLogger`. Plus `mode` (gui/console/both), `blockRPC`, `endpoint` (stream to the app), `toggleKey`.

Generated and managed by the SecureScripts desktop app (Luau Logger tab).
