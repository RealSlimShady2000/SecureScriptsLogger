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
if getgenv then getgenv().__SS_LOGGER_ACTIVE = true end

local CFG = (getgenv and getgenv().SS_LOGGER_CONFIG) or {}
local MODE = CFG.mode or "gui"               -- "gui" | "console" | "both"
local BLOCK_RPC = CFG.blockRPC ~= false      -- default true
local ENDPOINT = CFG.endpoint or ""           -- "" disables streaming to the app
local TOGGLE_KEY = CFG.toggleKey or "RightShift"

-- per-feature global toggles (all default ON)
local F = {
  http        = CFG.httpLogger ~= false,
  remotes     = CFG.remoteLogger ~= false,
  fs          = CFG.fsLogger ~= false,
  loadstrings = CFG.loadstringLogger ~= false,
  clipboard   = CFG.clipboardLogger ~= false,
  persist     = CFG.persistLogger ~= false,
  game        = CFG.gameLogger ~= false,
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

local busy = false        -- reentrancy guard so the logger never logs itself
local seq = 0
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
        Headers = { ["Content-Type"] = "application/json" },
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
    local sg = Instance.new("ScreenGui")
    sg.Name = "\0"
    sg.ResetOnSpawn = false
    sg.IgnoreGuiInset = true
    sg.DisplayOrder = 999999
    local parent = (realGetHui and realGetHui()) or (gethui and gethui())
    if not parent then local ok2 = pcall(function() parent = game:GetService("CoreGui") end) end
    sg.Parent = parent or game:GetService("CoreGui")

    local frame = Instance.new("Frame", sg)
    frame.Size = UDim2.fromOffset(440, 300)
    frame.Position = UDim2.fromOffset(20, 80)
    frame.BackgroundColor3 = Color3.fromRGB(13, 14, 17)
    frame.BorderSizePixel = 0
    frame.Active = true
    Instance.new("UICorner", frame).CornerRadius = UDim.new(0, 8)
    local stroke = Instance.new("UIStroke", frame)
    stroke.Color = Color3.fromRGB(38, 42, 49)

    local bar = Instance.new("TextLabel", frame)
    bar.Size = UDim2.new(1, 0, 0, 30)
    bar.BackgroundColor3 = Color3.fromRGB(21, 23, 28)
    bar.BorderSizePixel = 0
    bar.Font = Enum.Font.GothamBold
    bar.TextSize = 13
    bar.TextColor3 = Color3.fromRGB(52, 200, 184)
    bar.Text = "  SecureScripts — Luau Logger"
    bar.TextXAlignment = Enum.TextXAlignment.Left
    Instance.new("UICorner", bar).CornerRadius = UDim.new(0, 8)

    local count = Instance.new("TextLabel", bar)
    count.Size = UDim2.fromOffset(120, 30)
    count.Position = UDim2.new(1, -124, 0, 0)
    count.BackgroundTransparency = 1
    count.Font = Enum.Font.Gotham
    count.TextSize = 12
    count.TextColor3 = Color3.fromRGB(154, 161, 171)
    count.Text = "0 events"
    count.TextXAlignment = Enum.TextXAlignment.Right

    local list = Instance.new("ScrollingFrame", frame)
    list.Size = UDim2.new(1, -10, 1, -38)
    list.Position = UDim2.fromOffset(5, 34)
    list.BackgroundTransparency = 1
    list.BorderSizePixel = 0
    list.ScrollBarThickness = 4
    list.CanvasSize = UDim2.new()
    list.AutomaticCanvasSize = Enum.AutomaticSize.Y
    local layout = Instance.new("UIListLayout", list)
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
        local lbl = Instance.new("TextLabel", list)
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
local function summarizeArgs(args)
  local parts = {}
  for i = 1, math.min(#args, 6) do
    local a = args[i]
    local t = type(a)
    if t == "string" then parts[i] = '"' .. (a:sub(1, 48)) .. '"'
    elseif t == "table" then parts[i] = "{table}"
    elseif t == "userdata" then parts[i] = tostring(a)
    else parts[i] = tostring(a) end
  end
  return table.concat(parts, ", ")
end

local function logHttp(fn, url, method, body)
  local tag, sev = classify(url)
  local bf, bsev = bodyFlags(body)
  if bf then sev = bsev end
  local detail = (method or "GET") .. " " .. tostring(url)
  if tag then detail = "[" .. tag .. "] " .. detail end
  if bf then detail = detail .. "  (body has " .. bf .. ")" end
  emit("http", sev or "med", fn, detail, { url = url, method = method, body = body and tostring(body):sub(1, 4096), flag = tag or bf })
  return tag
end

local function isRpc(url)
  if type(url) ~= "string" then return false end
  return string.find(url, "127%.0%.0%.1:6463") ~= nil or string.find(url, "localhost:6463") ~= nil
    or (string.find(string.lower(url), "discord") and string.find(url, "/rpc"))
end

-- HTTP spy on the request family
if F.http and realRequest and realHookFunction then
  local origRequest
  origRequest = realHookFunction(realRequest, realNewCC(function(opts, ...)
    if type(opts) == "table" and not busy then
      local url = opts.Url or opts.url
      logHttp("request", url, opts.Method or opts.method or "GET", opts.Body or opts.body)
      if BLOCK_RPC and isRpc(url) then
        emit("block", "high", "request", "BLOCKED Discord RPC " .. tostring(url))
        return { StatusCode = 403, StatusMessage = "Blocked", Success = false, Headers = {}, Body = "" }
      end
    end
    return origRequest(opts, ...)
  end))
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
          emit("remote", "high", "FireServer", path .. "(" .. summarizeArgs(args) .. ")", { path = path, args = summarizeArgs(args) })
        elseif method == "InvokeServer" and F.remotes then
          emit("remote", "high", "InvokeServer", path .. "(" .. summarizeArgs(args) .. ")", { path = path })
        elseif (method == "Fire" or method == "Invoke") and F.remotes then
          emit("bindable", "med", method, path .. "(" .. summarizeArgs(args) .. ")")
        elseif (method == "HttpGet" or method == "HttpGetAsync") and F.http then
          logHttp("game:HttpGet", args[1], "GET")
        elseif (method == "HttpPost" or method == "HttpPostAsync") and F.http then
          logHttp("game:HttpPost", args[1], "POST", args[2])
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

emit("ready", "low", "logger", (realIdentify and ("on " .. tostring(select(1, pcall(realIdentify)) and realIdentify() or "executor")) or "ready") .. " — watching. Toggle GUI: " .. TOGGLE_KEY)
