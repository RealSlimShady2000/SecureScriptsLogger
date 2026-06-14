--[[============================================================================
  SecureScripts — Luau Logger (runtime companion)
  ----------------------------------------------------------------------------
  Run this BEFORE a suspected script (put it in your executor's autoexec folder,
  or execute it first). It silently hooks the executor + Roblox APIs and logs
  what the next script does *inside the live game*: every RemoteEvent it fires,
  HTTP request it makes, file it writes, payload it loadstrings, etc. — so you
  can spot item-stealers / trade scams / cookie loggers that an offline scan
  can't fully see.

  Defensive monitoring only. It never breaks the game: every hook is pcall-
  guarded and falls back to the original. Config is injected via
  getgenv().SS_LOGGER_CONFIG by the SecureScripts app.
============================================================================]]--

if getgenv and getgenv().__SS_LOGGER_ACTIVE then return end

local CFG = (getgenv and getgenv().SS_LOGGER_CONFIG) or {}
-- Stealth: lift config into locals, then scrub it from getgenv so a script that
-- reads getgenv() can't see SS_LOGGER_CONFIG (endpoint / toggles) or our presence.
if getgenv then
  getgenv().__SS_LOGGER_ACTIVE = true
  pcall(function() getgenv().SS_LOGGER_CONFIG = nil end)
end

local MODE = CFG.mode or "gui"               -- "gui" | "console" | "both"
local BLOCK_RPC = CFG.blockRPC ~= false      -- default true
local ENDPOINT = CFG.endpoint or ""           -- "" disables streaming to the app
local TOKEN = CFG.streamToken or ""           -- anti-spoof token for the local listener
local TOGGLE_KEY = CFG.toggleKey or "RightShift"
local AUTODECODE = CFG.autoDecode ~= false    -- decode application/json response bodies

-- User-supplied URL blocklist (substring match) — ported from HttpSpy's BlockedURLs.
-- A matching request is dropped with a 403-shaped table and never hits the network.
local BLOCKLIST = {}
do
  local src = CFG.blockedURLs or CFG.BlockedURLs
  if type(src) == "table" then
    for _, u in pairs(src) do
      if type(u) == "string" and u ~= "" then BLOCKLIST[#BLOCKLIST + 1] = u end
    end
  end
end

-- per-feature global toggles (all default ON)
local F = {
  http        = CFG.httpLogger ~= false,
  responses   = CFG.responseLogger ~= false,
  remotes     = CFG.remoteLogger ~= false,
  fs          = CFG.fsLogger ~= false,
  loadstrings = CFG.loadstringLogger ~= false,
  clipboard   = CFG.clipboardLogger ~= false,
  persist     = CFG.persistLogger ~= false,
  game        = CFG.gameLogger ~= false,
  recon       = CFG.reconLogger ~= false,
  crypt       = CFG.cryptLogger ~= false,
  vmdump      = CFG.vmDumpLogger ~= false,   -- table.concat constant dump (VM obfuscators)
}

-- dangerous service methods executors block (Myriad blocklist) — flag by category
local DANGER = {
  AccountService = { cat = "account-token", m = { GetCredentialsHeaders = 1, GetDeviceAccessToken = 1, GetDeviceIntegrityToken = 1, GetDeviceIntegrityTokenYield = 1 } },
  MarketplaceService = { cat = "purchase", m = { GetRobuxBalance = 1, PerformPurchase = 1, PromptRobloxPurchase = 1, PromptBulkPurchase = 1, PerformBulkPurchase = 1 } },
  BrowserService = { cat = "browser-js", m = { ExecuteJavaScript = 1, OpenBrowserWindow = 1, SendCommand = 1, OpenWeChatAuthWindow = 1 } },
  LinkingService = { cat = "open-url", m = { OpenUrl = 1, RegisterLuaUrl = 1 } },
  HttpRbxApiService = { cat = "roblox-api", m = { PostAsync = 1, GetAsync = 1, RequestAsync = 1, PostAsyncFullUrl = 1, GetAsyncFullUrl = 1 } },
  OpenCloudService = { cat = "roblox-api", m = { HttpRequestAsync = 1 } },
  CaptureService = { cat = "screenshot", m = { CaptureScreenshot = 1, SaveScreenshotCapture = 1, SaveCaptureToExternalStorage = 1 } },
  CoreGui = { cat = "screenshot", m = { TakeScreenshot = 1, ToggleRecording = 1 } },
  MessageBusService = { cat = "messagebus", m = { Call = 1, Publish = 1, MakeRequest = 1 } },
  InsertService = { cat = "local-file", m = { GetLocalFileContents = 1 } },
  ContentProvider = { cat = "asset-mitm", m = { SetBaseUrl = 1 } },
  ScriptContext = { cat = "core-inject", m = { AddCoreScriptLocal = 1 } },
}

-- ---- capture originals (before anything is hooked) ----
local ok_services, Players, HttpService, UserInput = pcall(function()
  return game:GetService("Players"), game:GetService("HttpService"), game:GetService("UserInputService")
end)
local realRequest = (syn and syn.request) or (http and http.request) or http_request or request or (fluxus and fluxus.request)
local realHookFunction = hookfunction or replaceclosure
local realHookMeta = hookmetamethod
local realNamecall = getnamecallmethod
local realCheckCaller = checkcaller or function() return true end
local realNewCC = newcclosure or function(f) return f end
local realGetHui = gethui
local realWritefile, realReadfile, realMakefolder, realAppend, realDelfile, realListfiles =
  writefile, readfile, makefolder, appendfile, delfile, listfiles
local realLoadstring = loadstring or load
local realSetClipboard = setclipboard or toclipboard or (syn and syn.write_clipboard)
local realQueueTeleport = queue_on_teleport or queueonteleport or (syn and syn.queue_on_teleport)
local realIdentify = identifyexecutor or getexecutorname
-- memory scraping / reflection (recon)
local realGetgc, realFiltergc, realGetreg = getgc, filtergc, getreg
local realGetrenv, realGetsenv, realGetRawMeta = getrenv, getsenv, getrawmetatable
-- signal firing (global executor funcs, distinct from the namecall variants)
local realFireProx, realFireClick, realFireTouch, realFireSignal =
  fireproximityprompt, fireclickdetector, firetouchinterest, firesignal
-- encoding / crypt (exfil prep — capturing in/out reveals the payload)
local realB64enc = (crypt and crypt.base64encode) or base64encode or (base64 and base64.encode) or (syn and syn.crypt and syn.crypt.base64encode)
local realB64dec = (crypt and crypt.base64decode) or base64decode or (base64 and base64.decode) or (syn and syn.crypt and syn.crypt.base64decode)
local realCryptEnc, realCryptDec = (crypt and crypt.encrypt), (crypt and crypt.decrypt)
local realWebSocket = (WebSocket and WebSocket.connect) or (websocket and websocket.connect)
-- caller attribution
local realDebugInfo = debug and debug.info
local realGetCallingScript = getcallingscript
-- anti-analysis probes (a script checking for / undoing our hooks is itself a signal)
local realRestoreFn = restorefunction or hookrestore or restorefunc
local realGetFnHash = getfunctionhash
-- modern sUNC surface used for evasion / privilege / recon
local realSetIdentity = setthreadidentity or setidentity or setthreadcontext
local realCloneRef = cloneref
local realGetConnections = getconnections
local realGetBytecode = getscriptbytecode or dumpstring
local realSetHiddenProp = sethiddenproperty
-- the local player's identity, so exfil of it is detectable even by a different channel
local LP_NAME, LP_ID, LP_DISPLAY
pcall(function()
  local lp = Players and Players.LocalPlayer
  if lp then LP_NAME, LP_ID, LP_DISPLAY = lp.Name, tostring(lp.UserId), lp.DisplayName end
end)

local busy = false        -- reentrancy guard so the logger never logs itself
local seq = 0
local lastRemoteSig = nil -- dedup so a remote logged via __namecall isn't re-logged via its function hook
local vt = 0
local function now() vt = vt + 0.001 return vt end

-- ============================================================================
-- Flagging
-- ============================================================================
local WEBHOOK = "discord[%w]-%.?com/api/[%w/]-webhooks/"
local function classify(text)
  if type(text) ~= "string" then return nil end
  local low = string.lower(text)
  if string.find(low, "discord") and string.find(low, "/api/") and string.find(low, "webhooks/") then return "webhook", "high" end
  if string.find(low, "127%.0%.0%.1:6463") or string.find(low, "/rpc") and string.find(low, "discord") then return "discord-rpc", "high" end
  if string.match(text, "https?://%d+%.%d+%.%d+%.%d+") then return "raw-ip", "high" end
  if string.find(low, "%.workers%.dev") then return "cloudflare-worker", "high" end
  if string.find(low, "pastefy") or string.find(low, "pastebin") or string.find(low, "hastebin") or string.find(low, "raw.githubusercontent") then return "paste", "med" end
  if string.find(low, "file://") then return "file-read", "high" end
  if string.find(low, "%.roblox%.com") and (string.find(low, "economy") or string.find(low, "apis%.") or string.find(low, "accountsettings") or string.find(low, "auth%.roblox") or string.find(low, "/currency")) then return "roblox-api", "high" end
  return nil
end
local function bodyFlags(s)
  if type(s) ~= "string" then return nil end
  if string.find(s, "ROBLOSECURITY") then return "cookie", "high" end
  if string.find(string.lower(s), "hwid") then return "hwid", "high" end
  -- P7: the body carries the local player's identity → exfil of who you are
  if LP_NAME and #LP_NAME > 2 and string.find(s, LP_NAME, 1, true) then return "player-name", "high" end
  if LP_ID and #LP_ID > 4 and string.find(s, LP_ID, 1, true) then return "player-id", "high" end
  return nil
end

-- ============================================================================
-- Output: console / GUI / stream
-- ============================================================================
local gui  -- forward declare; set up below if needed

local function streamEvent(ev)
  if ENDPOINT == "" or not realRequest then return end
  task.spawn(function()
    pcall(function()
      realRequest({
        Url = ENDPOINT,
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json", ["x-ss-token"] = TOKEN },
        Body = HttpService:JSONEncode(ev),
      })
    end)
  end)
end

local consoleReady = false
local function consoleLine(ev)
  local line = string.format("[%s] %s %s %s", ev.severity:sub(1, 1):upper(), ev.type, ev.fn or "", ev.detail or "")
  if rconsoleprint then
    if not consoleReady then pcall(function() rconsolename("SecureScripts — Luau Logger") end) consoleReady = true end
    pcall(rconsoleprint, line .. "\n")
  else
    pcall(print, "[SS] " .. line)
  end
end

local function emit(etype, severity, fn, detail, extra)
  if busy then return end
  -- dedup: the colon call (remote:FireServer) is caught by __namecall; if the same
  -- call also surfaces through the function hook (via="fn"), drop the duplicate.
  if etype == "remote" then
    if extra and extra.via == "fn" and detail == lastRemoteSig then return end
    lastRemoteSig = detail
  end
  busy = true
  seq = seq + 1
  local ev = { seq = seq, ts = now(), type = etype, severity = severity or "info", fn = fn, detail = detail }
  if extra then for k, v in pairs(extra) do ev[k] = v end end
  pcall(function()
    if MODE == "console" or MODE == "both" then consoleLine(ev) end
    if (MODE == "gui" or MODE == "both") and gui then gui.add(ev) end
    streamEvent(ev)
  end)
  busy = false
end

-- ============================================================================
-- In-game GUI (lightweight, draggable, hidden from the game via gethui)
-- ============================================================================
local function buildGui()
  local okGui, api = pcall(function()
    -- modern Instance.new: never pass the deprecated 2nd (parent) arg
    local inew = Instance.new
    local function mk(class, parent) local o = inew(class); if parent then o.Parent = parent end; return o end
    local sg = mk("ScreenGui")
    sg.Name = (HttpService and HttpService.GenerateGUID) and HttpService:GenerateGUID(false) or "\0"
    sg.ResetOnSpawn = false
    sg.IgnoreGuiInset = true
    sg.DisplayOrder = 999999
    local parent = (realGetHui and realGetHui()) or (gethui and gethui())
    if not parent then local ok2 = pcall(function() parent = game:GetService("CoreGui") end) end
    sg.Parent = parent or game:GetService("CoreGui")
    -- protect the GUI from game-side enumeration where the executor supports it
    pcall(function()
      local pg = (syn and syn.protect_gui) or protectgui or protect_gui
      if pg then pg(sg) end
    end)

    local frame = mk("Frame", sg)
    frame.Size = UDim2.fromOffset(440, 300)
    frame.Position = UDim2.fromOffset(20, 80)
    frame.BackgroundColor3 = Color3.fromRGB(13, 14, 17)
    frame.BorderSizePixel = 0
    frame.Active = true
    mk("UICorner", frame).CornerRadius = UDim.new(0, 8)
    local stroke = mk("UIStroke", frame)
    stroke.Color = Color3.fromRGB(38, 42, 49)

    local bar = mk("TextLabel", frame)
    bar.Size = UDim2.new(1, 0, 0, 30)
    bar.BackgroundColor3 = Color3.fromRGB(21, 23, 28)
    bar.BorderSizePixel = 0
    bar.Font = Enum.Font.GothamBold
    bar.TextSize = 13
    bar.TextColor3 = Color3.fromRGB(52, 200, 184)
    bar.Text = "  SecureScripts — Luau Logger"
    bar.TextXAlignment = Enum.TextXAlignment.Left
    mk("UICorner", bar).CornerRadius = UDim.new(0, 8)

    local count = mk("TextLabel", bar)
    count.Size = UDim2.fromOffset(120, 30)
    count.Position = UDim2.new(1, -124, 0, 0)
    count.BackgroundTransparency = 1
    count.Font = Enum.Font.Gotham
    count.TextSize = 12
    count.TextColor3 = Color3.fromRGB(154, 161, 171)
    count.Text = "0 events"
    count.TextXAlignment = Enum.TextXAlignment.Right

    local list = mk("ScrollingFrame", frame)
    list.Size = UDim2.new(1, -10, 1, -38)
    list.Position = UDim2.fromOffset(5, 34)
    list.BackgroundTransparency = 1
    list.BorderSizePixel = 0
    list.ScrollBarThickness = 4
    list.CanvasSize = UDim2.new()
    list.AutomaticCanvasSize = Enum.AutomaticSize.Y
    local layout = mk("UIListLayout", list)
    layout.Padding = UDim.new(0, 2)

    -- drag
    local dragging, dragStart, startPos
    bar.InputBegan:Connect(function(i)
      if i.UserInputType == Enum.UserInputType.MouseButton1 then
        dragging = true dragStart = i.Position startPos = frame.Position
      end
    end)
    bar.InputEnded:Connect(function(i)
      if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
    end)
    if UserInput then
      UserInput.InputChanged:Connect(function(i)
        if dragging and i.UserInputType == Enum.UserInputType.MouseMovement then
          local d = i.Position - dragStart
          frame.Position = UDim2.fromOffset(startPos.X.Offset + d.X, startPos.Y.Offset + d.Y)
        end
      end)
    end

    local COLORS = {
      high = Color3.fromRGB(248, 81, 73), med = Color3.fromRGB(210, 153, 34),
      info = Color3.fromRGB(154, 161, 171), low = Color3.fromRGB(52, 200, 184),
    }
    local n = 0
    return {
      frame = frame,
      add = function(ev)
        n = n + 1
        count.Text = n .. " events"
        local lbl = mk("TextLabel", list)
        lbl.Size = UDim2.new(1, -6, 0, 16)
        lbl.BackgroundTransparency = 1
        lbl.Font = Enum.Font.Code
        lbl.TextSize = 12
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.TextTruncate = Enum.TextTruncate.AtEnd
        lbl.TextColor3 = COLORS[ev.severity] or COLORS.info
        lbl.Text = string.format("%s  %s %s", ev.type, ev.fn or "", ev.detail or "")
        if n > 250 and list:FindFirstChildWhichIsA("TextLabel") then
          list:FindFirstChildWhichIsA("TextLabel"):Destroy()
        end
        list.CanvasPosition = Vector2.new(0, 1e6)
      end,
      toggle = function() frame.Visible = not frame.Visible end,
    }
  end)
  if okGui then return api end
  return nil
end

if MODE == "gui" or MODE == "both" then
  gui = buildGui()
  if not gui then MODE = "console" end
  if UserInput and gui then
    pcall(function()
      UserInput.InputBegan:Connect(function(i, gpe)
        if not gpe and i.KeyCode == Enum.KeyCode[TOGGLE_KEY] then gui.toggle() end
      end)
    end)
  end
end

-- ============================================================================
-- Hooks
-- ============================================================================
-- Depth-capped, cycle-safe serializer so RemoteEvent / exfil table args are fully
-- revealed (e.g. {give="all", to="Attacker"}) instead of an opaque "{table}".
local function ser(v, depth, seen)
  local t = type(v)
  if t == "string" then return '"' .. (#v > 120 and (v:sub(1, 120) .. "…") or v) .. '"'
  elseif t == "number" or t == "boolean" or t == "nil" then return tostring(v)
  elseif t == "function" then return "fn"
  elseif t == "userdata" or t == "vector" then
    local ok, full = pcall(function() return v.GetFullName and v:GetFullName() end)
    return (ok and full) and ("<" .. full .. ">") or tostring(v)
  elseif t == "table" then
    if depth <= 0 then return "{…}" end
    seen = seen or {}
    if seen[v] then return "{cycle}" end
    seen[v] = true
    local parts, n = {}, 0
    for k, val in pairs(v) do
      n = n + 1
      if n > 16 then parts[#parts + 1] = "…"; break end
      parts[#parts + 1] = tostring(k) .. "=" .. ser(val, depth - 1, seen)
    end
    seen[v] = nil
    return "{" .. table.concat(parts, ", ") .. "}"
  end
  return tostring(v)
end
local function summarizeArgs(args)
  local parts = {}
  for i = 1, math.min(#args, 8) do parts[i] = ser(args[i], 3) end
  return table.concat(parts, ", ")
end
-- Attribute a call to the script / line that made it (defeats payload anonymity).
local function whoCalled()
  if realGetCallingScript then
    local ok, sc = pcall(realGetCallingScript)
    if ok and sc then local ok2, n = pcall(function() return sc:GetFullName() end); if ok2 and n then return n end end
  end
  if realDebugInfo then
    local ok, src, line = pcall(realDebugInfo, 3, "sl")
    if ok and src then return tostring(src) .. ":" .. tostring(line) end
  end
  return nil
end

-- P3: a Discord-webhook-shaped body — catches webhooks proxied through a
-- non-Discord host (attacker VPS / Cloudflare worker) where the URL looks benign.
local function looksLikeWebhookPayload(body)
  if type(body) ~= "string" or #body < 8 then return false end
  local low = string.lower(body)
  if string.find(low, '"embeds"', 1, true) and (string.find(low, '"title"', 1, true) or string.find(low, '"fields"', 1, true) or string.find(low, '"description"', 1, true)) then return true end
  if string.find(low, '"content"', 1, true) and (string.find(low, '"username"', 1, true) or string.find(low, '"avatar_url"', 1, true)) then return true end
  return false
end
-- P6: an opaque, whitespace-free, high-base64-density blob — likely custom-encoded exfil.
local function looksEncoded(body)
  if type(body) ~= "string" or #body < 80 then return false end
  if string.find(body, "[%s{}]") then return false end
  local _, b64 = string.gsub(body, "[%w%+/=]", "")
  return (b64 / #body) > 0.95
end

-- A request *carrying* the session cookie / HWID / player identity in its headers
-- or Cookies field is a smoking-gun exfil that a plain URL+body view would miss.
local function headerFlag(headers, cookies)
  if type(headers) == "table" then
    for _, v in pairs(headers) do
      if type(v) == "string" then local f = bodyFlags(v); if f then return f end end
    end
  end
  if type(cookies) == "string" then return bodyFlags(cookies) end
  return nil
end

local function logHttp(fn, url, method, body, headers, cookies)
  local tag, sev = classify(url)
  local bf, bsev = bodyFlags(body)
  if bf then sev = bsev end
  local m = string.upper(tostring(method or "GET"))
  if m == "POST" and looksLikeWebhookPayload(body) and tag ~= "webhook" then tag, sev = "proxied-webhook", "high" end
  if m == "POST" and not tag and looksEncoded(body) then tag, sev = "encoded-payload", sev or "med" end
  local hf = headerFlag(headers, cookies)
  if hf then tag, sev = tag or (hf .. "-header"), "high" end
  local detail = (method or "GET") .. " " .. tostring(url)
  if tag then detail = "[" .. tag .. "] " .. detail end
  if bf then detail = detail .. "  (body has " .. bf .. ")" end
  if hf then detail = detail .. "  (header has " .. hf .. ")" end
  emit("http", sev or "med", fn, detail, { url = url, method = method, body = body and tostring(body):sub(1, 4096), flag = tag or bf or hf })
  return tag
end

-- Ported from HttpSpy's response view: capture each request's response, decode
-- application/json (case-insensitive content-type + nil-safe — fixes HttpSpy's
-- exact-case "Content-Type" crash), and flag it. reqTag is the request's own
-- classification (webhook / raw-ip / …) so a flagged request that gets a 2xx is
-- surfaced as "exfil delivered".
local function logResponse(url, reqTag, resp)
  if type(resp) ~= "table" or busy then return end
  local status = tonumber(resp.StatusCode or resp.Status or resp.status_code or resp.statusCode)
  local headers = resp.Headers or resp.headers
  local body = resp.Body or resp.body
  local decoded
  if AUTODECODE and HttpService and type(body) == "string" and #body <= 200000 and type(headers) == "table" then
    local ct
    for k, v in pairs(headers) do
      if type(k) == "string" and string.lower(k) == "content-type" then ct = tostring(v); break end
    end
    if ct and string.find(string.lower(ct), "application/json", 1, true) then
      busy = true
      local ok, res = pcall(function() return HttpService:JSONDecode(body) end)
      busy = false
      if ok then decoded = res end
    end
  end
  local sev, tag = "info", nil
  local bf = bodyFlags(type(body) == "string" and body or nil)
  if bf then sev, tag = "high", bf .. "-in-response" end
  if reqTag and status and status >= 200 and status < 300 then
    tag = tag or (reqTag .. "-ack")
    if sev == "info" then
      sev = (reqTag == "webhook" or reqTag == "proxied-webhook" or reqTag == "raw-ip") and "high" or "med"
    end
  end
  local preview = ""
  if decoded ~= nil then preview = ser(decoded, 4)
  elseif type(body) == "string" then preview = (#body > 400 and (body:sub(1, 400) .. "…") or body) end
  emit("response", sev, "request",
    "<- " .. tostring(status or "?") .. (tag and ("  [" .. tag .. "]") or "") .. (preview ~= "" and ("  " .. preview) or ""),
    { url = url, status = status, flag = tag, body = type(body) == "string" and body:sub(1, 4096) or nil, decoded = decoded ~= nil or nil })
end

local function isRpc(url)
  if type(url) ~= "string" then return false end
  return string.find(url, "127%.0%.0%.1:6463") ~= nil or string.find(url, "localhost:6463") ~= nil
    or (string.find(string.lower(url), "discord") and string.find(url, "/rpc"))
end

local function isBlocked(url)
  if type(url) ~= "string" or #BLOCKLIST == 0 then return false end
  for _, b in ipairs(BLOCKLIST) do
    if string.find(url, b, 1, true) then return true end
  end
  return false
end

-- HTTP spy on the request family (P4: hook EVERY distinct alias, not just one).
-- Ported from HttpSpy: also capture + decode the RESPONSE — but without its
-- coroutine dance. We reuse the single orig() call the hook already makes and keep
-- its result, so there's no extra request and nothing new for a script to detect.
if F.http and realHookFunction then
  local seenReq = {}
  local function hookReq(fn)
    if type(fn) ~= "function" or seenReq[fn] then return end
    seenReq[fn] = true
    local orig
    orig = realHookFunction(fn, realNewCC(function(opts, ...)
      local logged, url, reqTag = false, nil, nil
      if type(opts) == "table" and not busy then
        url = opts.Url or opts.url
        -- never log our own stream POSTs to the local listener (would loop)
        if not (ENDPOINT ~= "" and url and string.sub(tostring(url), 1, #ENDPOINT) == ENDPOINT) then
          logged = true
          reqTag = logHttp("request", url, opts.Method or opts.method or "GET", opts.Body or opts.body,
            opts.Headers or opts.headers, opts.Cookies or opts.cookies)
          if BLOCK_RPC and isRpc(url) then
            emit("block", "high", "request", "BLOCKED Discord RPC " .. tostring(url))
            return { StatusCode = 403, StatusMessage = "Blocked", Success = false, Headers = {}, Body = "" }
          end
          if isBlocked(url) then
            emit("block", "high", "request", "BLOCKED " .. tostring(url) .. " (blocklist)")
            return { StatusCode = 403, StatusMessage = "Blocked by SecureScripts", Success = false, Headers = {}, Body = "" }
          end
        end
      end
      -- not capturing responses: behave exactly as before (single tail call)
      if not (F.responses and logged) then return orig(opts, ...) end
      -- capturing: reuse the one orig() call, keep the response, log it, return it
      local resp = orig(opts, ...)
      pcall(logResponse, url, reqTag, resp)
      return resp
    end))
  end
  hookReq(request); hookReq(http_request)
  hookReq(syn and syn.request); hookReq(http and http.request)
  hookReq(fluxus and fluxus.request); hookReq(krnl and krnl.request)
  hookReq(getgenv and getgenv().request)
end

-- __namecall: remotes, HttpGet, services, etc.
if realHookMeta and realNamecall then
  local origNamecall
  origNamecall = realHookMeta(game, "__namecall", realNewCC(function(self, ...)
    local ok, method = pcall(realNamecall)
    if ok and not busy and realCheckCaller() then
      local args = { ... }
      pcall(function()
        local cls
        pcall(function() cls = self.ClassName end)
        local dm = cls and DANGER[cls]
        if dm and dm.m[method] then
          emit("danger", "high", cls .. ":" .. method, "blocklisted method (" .. dm.cat .. ")", { category = dm.cat })
        end
        local path = self.GetFullName and self:GetFullName() or tostring(self)
        if (method == "FireServer" or method == "fireServer") and F.remotes then
          emit("remote", "high", "FireServer", path .. "(" .. summarizeArgs(args) .. ")", { path = path, args = summarizeArgs(args), src = whoCalled() })
        elseif method == "InvokeServer" and F.remotes then
          emit("remote", "high", "InvokeServer", path .. "(" .. summarizeArgs(args) .. ")", { path = path, args = summarizeArgs(args), src = whoCalled() })
        elseif (method == "Fire" or method == "Invoke") and F.remotes then
          emit("bindable", "med", method, path .. "(" .. summarizeArgs(args) .. ")")
        elseif (method == "HttpGet" or method == "HttpGetAsync") and F.http then
          logHttp("game:HttpGet", args[1], "GET")
        elseif method == "GetObjects" and F.http then
          logHttp("game:GetObjects", args[1], "GET")
        elseif (method == "HttpPost" or method == "HttpPostAsync") and F.http then
          logHttp("game:HttpPost", args[1], "POST", args[2])
        elseif method == "RequestAsync" and cls == "HttpService" and F.http then
          local o = args[1]
          if type(o) == "table" then logHttp("HttpService:RequestAsync", o.Url or o.url, o.Method or o.method or "GET", o.Body or o.body) end
        elseif method == "GetAsync" and cls == "HttpService" and F.http then
          logHttp("HttpService:GetAsync", args[1], "GET")
        elseif method == "PostAsync" and cls == "HttpService" and F.http then
          logHttp("HttpService:PostAsync", args[1], "POST", args[2])
        elseif method == "JSONEncode" and F.crypt then
          emit("encode", "med", "JSONEncode", ser(args[1], 3), { preview = ser(args[1], 4), src = whoCalled() })
        elseif (method == "GetService" or method == "service") and F.game then
          emit("game", "info", "GetService", tostring(args[1]))
        elseif (method == "FireClickDetector" or method == "FireProximityPrompt" or method == "FireTouchInterest") and F.game then
          emit("signal", "med", method, path)
        end
      end)
    end
    return origNamecall(self, ...)
  end))
end

-- P1: also hook FireServer/InvokeServer as FUNCTIONS, so the __index-cache bypass
-- (local f = remote.FireServer; f(remote, ...)) can't skip the __namecall hook.
-- The emit() dedup drops the duplicate when a colon call routes through both.
if F.remotes and realHookFunction then
  local function hookRemoteFn(className, methodName)
    local ok, inst = pcall(Instance.new, className)
    if not ok or not inst then return end
    local ok2, fn = pcall(function() return inst[methodName] end)
    if not ok2 or type(fn) ~= "function" then return end
    local orig
    orig = realHookFunction(fn, realNewCC(function(self, ...)
      if not busy then
        local a = { ... }
        pcall(function()
          local path = (self and self.GetFullName) and self:GetFullName() or tostring(self)
          emit("remote", "high", methodName, path .. "(" .. summarizeArgs(a) .. ")", { path = path, args = summarizeArgs(a), src = whoCalled(), via = "fn" })
        end)
      end
      return orig(self, ...)
    end))
  end
  hookRemoteFn("RemoteEvent", "FireServer")
  hookRemoteFn("RemoteFunction", "InvokeServer")
end

-- filesystem
local function fsSpy(name, fn, sev)
  if type(fn) ~= "function" or not realHookFunction then return end
  local orig
  orig = realHookFunction(fn, realNewCC(function(path, content, ...)
    if not busy then
      local p = tostring(path)
      local s = sev
      if string.find(string.lower(p), "autoexec") then s = "high" end
      emit("fs", s, name, p .. (content and ("  (" .. #tostring(content) .. "b)") or ""), { path = p, content = content and tostring(content):sub(1, 4096), autoexec = string.find(string.lower(p), "autoexec") ~= nil })
    end
    return orig(path, content, ...)
  end))
end
if F.fs then
  fsSpy("writefile", realWritefile, "high")
  fsSpy("appendfile", realAppend, "high")
  fsSpy("makefolder", realMakefolder, "info")
  fsSpy("delfile", realDelfile, "med")
  fsSpy("readfile", realReadfile, "med")
end

-- loadstring (decoded payloads)
if F.loadstrings and realLoadstring and realHookFunction then
  local orig
  orig = realHookFunction(realLoadstring, realNewCC(function(src, ...)
    if not busy and type(src) == "string" then
      local tag = bodyFlags(src)
      emit("loadstring", tag and "high" or "med", "loadstring", "#" .. #src .. " bytes" .. (tag and (" (" .. tag .. ")") or ""), { bytes = #src, preview = src:sub(1, 4096) })
    end
    return orig(src, ...)
  end))
end

-- clipboard
if F.clipboard and realSetClipboard and realHookFunction then
  local orig
  orig = realHookFunction(realSetClipboard, realNewCC(function(v, ...)
    if not busy then
      local tag = classify(tostring(v))
      emit("clipboard", tag and "high" or "med", "setclipboard", tostring(v):sub(1, 200))
    end
    return orig(v, ...)
  end))
end

-- queue_on_teleport (persistence)
if F.persist and realQueueTeleport and realHookFunction then
  local orig
  orig = realHookFunction(realQueueTeleport, realNewCC(function(src, ...)
    if not busy then emit("persist", "high", "queue_on_teleport", "#" .. #tostring(src) .. " bytes", { preview = tostring(src):sub(1, 2048) }) end
    return orig(src, ...)
  end))
end

-- WebSocket (C2 channel)
if F.http and realWebSocket and realHookFunction then
  local orig
  orig = realHookFunction(realWebSocket, realNewCC(function(url, ...)
    if not busy then
      local tag = classify(tostring(url))
      emit("websocket", tag and "high" or "med", "WebSocket.connect", tostring(url), { url = url, src = whoCalled() })
    end
    return orig(url, ...)
  end))
end

-- memory / env scraping (hunting RemoteEvents & secrets, or re-hooking to detect us)
if F.recon and realHookFunction then
  local function reconSpy(name, fn)
    if type(fn) ~= "function" then return end
    local orig
    orig = realHookFunction(fn, realNewCC(function(...)
      if not busy then emit("recon", "med", name, "scans the running environment / GC", { src = whoCalled() }) end
      return orig(...)
    end))
  end
  reconSpy("getgc", realGetgc)
  reconSpy("filtergc", realFiltergc)
  reconSpy("getreg", realGetreg)
  reconSpy("getrenv", realGetrenv)
  reconSpy("getsenv", realGetsenv)
  reconSpy("getrawmetatable", realGetRawMeta)
end

-- P5: anti-analysis — a script that UNDOES or FINGERPRINTS hooks is checking for us
if F.recon and realHookFunction then
  if type(realRestoreFn) == "function" then
    local orig
    orig = realHookFunction(realRestoreFn, realNewCC(function(...)
      if not busy then emit("anti-analysis", "high", "restorefunction", "tries to UNDO a function hook", { src = whoCalled() }) end
      return orig(...)
    end))
  end
  if type(realGetFnHash) == "function" then
    local orig
    orig = realHookFunction(realGetFnHash, realNewCC(function(...)
      if not busy then emit("anti-analysis", "med", "getfunctionhash", "fingerprints a function (hook check)", { src = whoCalled() }) end
      return orig(...)
    end))
  end
end

-- modern sUNC recon / anti-analysis surface (identity spoofing, ref-cloning, etc.)
if F.recon and realHookFunction then
  local function probe(name, fn, sev, note)
    if type(fn) ~= "function" then return end
    local orig
    orig = realHookFunction(fn, realNewCC(function(...)
      if not busy then emit("anti-analysis", sev, name, note, { src = whoCalled() }) end
      return orig(...)
    end))
  end
  probe("setthreadidentity", realSetIdentity, "high", "spoofs thread identity (checkcaller / privilege)")
  probe("cloneref", realCloneRef, "med", "clones a ref to dodge hook / identity checks")
  probe("getconnections", realGetConnections, "med", "enumerates signal connections (disconnect AC / find remotes)")
  probe("getscriptbytecode", realGetBytecode, "med", "dumps script bytecode (recon / theft)")
  probe("sethiddenproperty", realSetHiddenProp, "med", "writes a hidden property")
end

-- global signal-firing funcs (automated in-game actions — distinct from namecall)
if F.game and realHookFunction then
  local function fireSpy(name, fn)
    if type(fn) ~= "function" then return end
    local orig
    orig = realHookFunction(fn, realNewCC(function(target, ...)
      if not busy then
        local p = "?"
        pcall(function() p = (target and target.GetFullName) and target:GetFullName() or tostring(target) end)
        emit("signal", "med", name, p, { src = whoCalled() })
      end
      return orig(target, ...)
    end))
  end
  fireSpy("fireproximityprompt", realFireProx)
  fireSpy("fireclickdetector", realFireClick)
  fireSpy("firetouchinterest", realFireTouch)
  fireSpy("firesignal", realFireSignal)
end

-- crypt / base64 (capturing in + out reveals exfil payloads & decoded configs)
if F.crypt and realHookFunction then
  local function cryptSpy(name, fn, kind)
    if type(fn) ~= "function" then return end
    local orig
    orig = realHookFunction(fn, realNewCC(function(input, ...)
      local out = orig(input, ...)
      if not busy then
        local inS = tostring(input)
        local tag = classify(inS) or classify(tostring(out)) or bodyFlags(inS) or bodyFlags(tostring(out))
        emit("crypt", tag and "high" or "med", name, kind .. " " .. inS:sub(1, 160), { input = inS:sub(1, 1024), output = tostring(out):sub(1, 1024), src = whoCalled() })
      end
      return out
    end))
  end
  cryptSpy("base64decode", realB64dec, "decode")
  cryptSpy("base64encode", realB64enc, "encode")
  cryptSpy("crypt.decrypt", realCryptDec, "decrypt")
  cryptSpy("crypt.encrypt", realCryptEnc, "encrypt")
end

-- VM constant dump (table.concat) — bytecode-VM obfuscators (PSU / IronBrew /
-- Luraph / MoonSec) keep their real strings encoded and only rebuild them at
-- runtime, almost always by table.concat-ing a freshly-decoded byte/char array.
-- Hooking table.concat and surfacing the results that look like real Lua source
-- or network IOCs exposes the payload the VM otherwise hides. Unlike our offline
-- scan this WORKS, because the decode runs in a genuine executor env where the
-- env-sensitive values come back non-nil instead of corrupting into base85 noise —
-- it's the one reliable read we have on these families. table.concat is the choke
-- point: even a constant cached as `local c = table.concat` before we load still
-- routes through the hook, since hookfunction patches the closure object itself.
if F.vmdump and realHookFunction and type(table) == "table" and type(table.concat) == "function" then
  pcall(function()
    -- tell a DECODED constant blob (real source / IOCs) from ordinary concat noise
    -- (UI text, still-encoded base85/base64 chunks). All scans are plain-string
    -- (Boyer–Moore in C) and run on a bounded head+tail probe, never the whole blob.
    local function looksDecoded(s)
      if string.find(s, "loadstring", 1, true) then return "loadstring" end
      if string.find(s, "GetService", 1, true) then return "GetService" end
      if string.find(s, "FireServer", 1, true) or string.find(s, "InvokeServer", 1, true) then return "remote" end
      if string.find(s, "HttpGet", 1, true) or string.find(s, "HttpPost", 1, true) then return "http" end
      if string.find(s, "://", 1, true) and (string.find(s, "http", 1, true) or string.find(s, "discord", 1, true)) then return "url" end
      if string.find(s, "function", 1, true) and string.find(s, "end", 1, true) then return "lua-source" end
      if string.find(s, "local ", 1, true) and string.find(s, "=", 1, true) then return "lua-source" end
      return nil
    end
    local seenBlob, blobCount, budget, inConcat = {}, 0, 20000, false
    local origConcat
    origConcat = realHookFunction(table.concat, realNewCC(function(...)
      local out = origConcat(...)
      -- fast path: skip our own concats (busy), re-entry, exhausted budget, and tiny joins
      if (not inConcat) and (not busy) and F.vmdump and budget > 0 and type(out) == "string" then
        local n = #out
        if n >= 24 then
          inConcat = true
          budget = budget - 1
          pcall(function()
            -- only ever scan/serialize a bounded slice, no matter how big the blob
            local probe = out
            if n > 20480 then probe = string.sub(out, 1, 16384) .. "\n" .. string.sub(out, n - 4096) end
            local tag = looksDecoded(probe)
            local ctag, csev = classify(probe)   -- reuse: webhook / raw-ip / workers.dev / paste / file:// / roblox-api
            if tag or ctag then
              local sig = n .. "|" .. string.sub(out, 1, 48)   -- dedup VM loops re-concatenating the same constant
              if (not seenBlob[sig]) and blobCount < 80 then
                seenBlob[sig] = true
                blobCount = blobCount + 1
                local label = ctag or tag
                local bf = bodyFlags(probe)
                local hi = bf or csev == "high" or tag == "url" or tag == "http" or tag == "remote" or tag == "loadstring"
                emit("vmdump", hi and "high" or "med", "table.concat",
                  "decoded VM constant (" .. label .. (bf and (", " .. bf) or "") .. ", " .. n .. "b)",
                  { tag = label, bytes = n, preview = string.sub(out, 1, 4096), src = whoCalled() })
              end
            end
          end)
          inConcat = false
        end
      end
      return out
    end))
  end)
end

emit("ready", "low", "logger", (realIdentify and ("on " .. tostring(select(1, pcall(realIdentify)) and realIdentify() or "executor")) or "ready") .. " — watching. Toggle GUI: " .. TOGGLE_KEY)
