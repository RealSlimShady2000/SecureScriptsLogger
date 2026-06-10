# SecureScripts — Luau Logger

A **stealth runtime monitor** for analyzing obfuscated / malicious Roblox scripts
*inside the live game*. Run it **before** a suspect script and it silently hooks
the executor + Roblox APIs, logging exactly what the script does — every
RemoteEvent it fires (with **full arguments**), HTTP request, file write,
`loadstring`, base64/crypt call, memory scrape, and more.

It's the runtime companion to the **SecureScripts** desktop app, which generates
this script, streams its events into a live colour-coded feed, and gives a
verdict. You can also use it standalone via the one-liner below.

> **Defensive analysis only.** Every hook is `pcall`-guarded and falls back to the
> original — it never breaks the game. Even so: **run unknown scripts on an alt
> account**, ideally in a throwaway environment.

## Quick start

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/RealSlimShady2000/SecureScriptsLogger/main/logger.lua"))()
```

That runs with defaults (in-game GUI, everything logged, Discord RPC blocked). To
configure it, set `getgenv().SS_LOGGER_CONFIG` **before** the loadstring:

```lua
getgenv().SS_LOGGER_CONFIG = {
  mode = "gui",          -- where output goes
  blockRPC = true,       -- block Discord RPC
  remoteLogger = true,   -- ...see the toggles below
}
loadstring(game:HttpGet("https://raw.githubusercontent.com/RealSlimShady2000/SecureScriptsLogger/main/logger.lua"))()
```

Then execute the suspect script and watch the in-game GUI (toggle with
**RightShift**), your executor console, or the SecureScripts app's live feed.

The app's **Luau Logger** tab builds this whole block for you from checkboxes —
including the live-stream endpoint + token — so you usually don't write the
config by hand.

## Configuration

All options live in `getgenv().SS_LOGGER_CONFIG`. The config is **scrubbed from
`getgenv()` the instant the logger reads it**, so a script that inspects
`getgenv()` can't see your settings or even that the logger is present.

### Output

| Option | Default | What it does | When to use |
|---|---|---|---|
| `mode` | `"gui"` | Where events show: `"gui"` (in-game overlay), `"console"` (executor console), or `"both"`. | `gui` for quick visual triage; `console` for the **stealthiest** option (creates no Instance); `both` to read along live. |
| `toggleKey` | `"RightShift"` | Key to show/hide the in-game GUI. | Change it if the script or game already uses RightShift. |
| `blockRPC` | `true` | Drops requests to the Discord RPC port (`127.0.0.1:6463`) and logs a `block` event. | Leave **on** — Discord RPC is used to fingerprint/grief you, never for anything legit. |
| `endpoint` | `""` | Local URL to stream events to (the app sets this, e.g. `http://127.0.0.1:7777/log`). Empty = no streaming. | Only when using the app's live feed. Streaming makes one localhost request per event — slightly **less stealthy** than gui/console. |
| `streamToken` | `""` | Anti-spoof token the app's listener requires. Set automatically alongside `endpoint`. | Leave it to the app; don't set by hand. |

### What to log (feature toggles)

All default **on**. Turn one **off** to cut noise when a specific obfuscator
floods that channel.

| Toggle | Catches | When to turn it off |
|---|---|---|
| `remoteLogger` | `:FireServer` / `:InvokeServer` with **full arguments** — the channel item-stealers and trade-scams use. | Rarely — this is the single most important toggle for MM2 / trade scams. |
| `httpLogger` | `request` / `http_request` / `game:HttpGet` / `HttpPost` and **WebSocket** connections — exfiltration + C2. | Rarely. |
| `cryptLogger` | `base64encode/decode`, `crypt.encrypt/decrypt`, and `HttpService:JSONEncode` — captures **inputs and outputs**, so it reveals the real exfil payload (cookie, webhook, player data) even when the URL is obfuscated. | If the script uses base64 heavily for its *own* deobfuscation and floods the log. |
| `reconLogger` | `getgc` / `filtergc` / `getreg` / `getrenv` / `getsenv` / `getrawmetatable` — memory scraping (hunting RemoteEvents & secrets) and anti-analysis re-hooking. | If you only care about the final sinks, not how it finds them. |
| `fsLogger` | `writefile` / `appendfile` / `makefolder` / `readfile` / `delfile` — flags writes to `autoexec` (persistence). | Rarely. |
| `loadstringLogger` | `loadstring` / `load` — dumps each decoded layer the script executes. | If a multi-layer VM `loadstring`s thousands of times and floods the feed. |
| `clipboardLogger` | `setclipboard` — scam-link / crypto-address swaps. | Rarely. |
| `persistLogger` | `queue_on_teleport` — code that re-runs after a teleport (persistence). | Rarely. |
| `gameLogger` | `game:GetService`, plus the global `fireproximityprompt` / `fireclickdetector` / `firetouchinterest` / `firesignal`. | If `GetService` spam is noisy and you only want sinks. |

## Reading the events

Each event has a **type**, a **severity** (red = high, amber = medium, grey =
info), the **function**, details, and — where the executor supports it — the
**calling script / line** (`src`) that made the call.

| Type | Meaning |
|---|---|
| `remote` | `FireServer` / `InvokeServer`. The args reveal *what* is sent, e.g. `{give="all", to="Attacker"}`. |
| `http` | An outbound HTTP request. Tagged `[webhook]`, `[raw-ip]`, `[roblox-api]`, `[file-read]`, `[paste]`, etc. |
| `websocket` | A WebSocket C2 connection. |
| `crypt` / `encode` | base64 / crypt / `JSONEncode` in **and** out — the decoded or encoded payload. |
| `danger` | A blocklisted service method — account-token theft, purchases, screenshots, browser-JS, MessageBus, … |
| `fs` | A file / folder operation; `autoexec` writes are flagged high. |
| `loadstring` | A decoded code layer being executed. |
| `recon` | Memory / environment scraping. |
| `clipboard` | A clipboard write. |
| `persist` | `queue_on_teleport` persistence. |
| `signal` | `fire*` automated in-game actions. |
| `block` | The logger blocked something (e.g. Discord RPC). |

## Stealth notes

- The config is **removed from `getgenv()`** immediately after it's read.
- Hooks are wrapped with `newcclosure` so they read as C closures, and the
  originals are captured **before** anything is hooked.
- The GUI is parented via `gethui()`, `protect_gui`'d where supported, and given a
  randomized name — so it's hidden from `CoreGui` enumeration.
- A re-entrancy guard means the logger never logs **itself**.
- For **maximum stealth**, use `mode = "console"` and leave `endpoint = ""` —
  that creates no Instance and no network traffic.

## License

MIT — defensive / educational use.
