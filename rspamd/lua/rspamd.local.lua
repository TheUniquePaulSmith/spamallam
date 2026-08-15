--[[
SpamAllam rspamd plugin.

Reads the X-SpamAllam-* headers added by the spamallam AI service and converts
them into weighted rspamd symbols. Headers are only trusted when their HMAC
signature (shared HEADER_HMAC_KEY, written to spamallam.config.lua at container
start) verifies — inbound mail has these headers stripped by spamallam before
they are re-added, so a valid signature proves the values came from spamallam.

Symbols:
  SPAMALLAM_SPAM        AI verdict spam       (dynamic weight = confidence)
  SPAMALLAM_PHISH       AI verdict phishing   (dynamic weight = confidence)
  SPAMALLAM_MALICIOUS   AI verdict malicious  (dynamic weight = confidence)
  SPAMALLAM_HAM         AI verdict ham        (negative score)
  SPAMALLAM_WHITELIST   admin whitelist override -> forces "no action"
  SPAMALLAM_SIG_INVALID header present but signature bad/stale (small positive)
  SPAMALLAM_SKIPPED     AI analysis skipped or errored (informational)
]]

local rspamd_logger = require "rspamd_logger"
local hash = require "rspamd_cryptobox_hash"

local ok, cfg = pcall(dofile, "/etc/rspamd/spamallam.config.lua")
if not ok or type(cfg) ~= "table" then
  rspamd_logger.errx(rspamd_config, "spamallam: cannot load spamallam.config.lua: %s", cfg)
  cfg = { hmac_key = "", spam_weight = 6.0, phish_weight = 8.0,
          malicious_weight = 12.0, ham_weight = -3.0, max_age = 3600 }
end

-- ---------------------------------------------------------------------------
-- HMAC-SHA256 (rspamd exposes sha256 but not hmac; RFC 2104 by hand)
-- ---------------------------------------------------------------------------
local bit = require "bit"

local function sha256_bin(data)
  local h = hash.create_specific("sha256")
  h:update(data)
  return h:bin()
end

local function hmac_sha256_hex(key, msg)
  local block = 64
  if #key > block then key = sha256_bin(key) end
  key = key .. string.rep("\0", block - #key)
  local opad = key:gsub(".", function(c) return string.char(bit.bxor(c:byte(), 0x5c)) end)
  local ipad = key:gsub(".", function(c) return string.char(bit.bxor(c:byte(), 0x36)) end)
  local h = hash.create_specific("sha256")
  h:update(opad .. sha256_bin(ipad .. msg))
  return h:hex()
end

-- constant-time-ish comparison (both are short hex strings)
local function digest_eq(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end

-- ---------------------------------------------------------------------------
-- Header parsing
-- ---------------------------------------------------------------------------
local function get_header(task, name)
  local v = task:get_header(name)
  if v then v = v:gsub("^%s+", ""):gsub("%s+$", "") end
  return v
end

-- X-SpamAllam-Signature: v=1; ts=1723750000; sig=<hex>
local function parse_signature(raw)
  if not raw then return nil end
  local out = {}
  for k, v in raw:gmatch("(%w+)=([%w%.]+)") do out[k] = v end
  if out.v == "1" and out.ts and out.sig then return out end
  return nil
end

local function spamallam_cb(task)
  local verdict = get_header(task, "X-SpamAllam-Verdict")
  if not verdict then
    return -- message never passed through spamallam (or headers stripped)
  end
  verdict = verdict:upper()

  local confidence = tonumber(get_header(task, "X-SpamAllam-Confidence") or "") or 0.0
  if confidence < 0 then confidence = 0.0 end
  if confidence > 1 then confidence = 1.0 end
  local category = get_header(task, "X-SpamAllam-Category") or ""
  local whitelisted = (get_header(task, "X-SpamAllam-Whitelisted") or ""):lower()

  -- ---- verify signature ----------------------------------------------------
  local sig = parse_signature(get_header(task, "X-SpamAllam-Signature"))
  local valid = false
  if sig and cfg.hmac_key ~= "" then
    local now = os.time()
    local ts = tonumber(sig.ts) or 0
    if math.abs(now - ts) <= (cfg.max_age or 3600) then
      -- canonical string must match spamallam/app/pipeline/headers.py
      local canonical = table.concat({
        "v1", sig.ts, verdict,
        string.format("%.2f", confidence),
        category, whitelisted,
      }, "\n")
      valid = digest_eq(hmac_sha256_hex(cfg.hmac_key, canonical), sig.sig:lower())
    end
  end

  if not valid then
    task:insert_result("SPAMALLAM_SIG_INVALID", 1.0, verdict)
    rspamd_logger.infox(task, "spamallam: header signature invalid/stale (verdict=%s)", verdict)
    return
  end

  -- ---- whitelist override --------------------------------------------------
  if whitelisted:find("yes", 1, true) then
    task:insert_result("SPAMALLAM_WHITELIST", 1.0, category)
    task:set_pre_result("no action", "spamallam whitelist override", "spamallam")
    return
  end

  -- ---- verdict scoring (dynamic weight scaled by AI confidence) ------------
  if verdict == "SPAM" then
    task:insert_result("SPAMALLAM_SPAM", confidence, category)
  elseif verdict == "PHISHING" then
    task:insert_result("SPAMALLAM_PHISH", confidence, category)
  elseif verdict == "MALICIOUS" then
    task:insert_result("SPAMALLAM_MALICIOUS", confidence, category)
  elseif verdict == "HAM" then
    task:insert_result("SPAMALLAM_HAM", confidence, category)
  else -- SKIPPED / ERROR / unknown
    task:insert_result("SPAMALLAM_SKIPPED", 1.0, verdict)
  end
end

-- ---------------------------------------------------------------------------
-- Registration
-- ---------------------------------------------------------------------------
local id = rspamd_config:register_symbol{
  name = "SPAMALLAM_CHECK",
  type = "callback",
  callback = spamallam_cb,
  group = "spamallam",
}

local function reg(name, score, description)
  rspamd_config:register_symbol{
    name = name, type = "virtual", parent = id, group = "spamallam",
  }
  rspamd_config:set_metric_symbol{
    name = name, score = score, description = description, group = "spamallam",
  }
end

reg("SPAMALLAM_SPAM", cfg.spam_weight, "AI analysis classified message as spam")
reg("SPAMALLAM_PHISH", cfg.phish_weight, "AI analysis classified message as phishing")
reg("SPAMALLAM_MALICIOUS", cfg.malicious_weight, "AI analysis classified message as malicious")
reg("SPAMALLAM_HAM", cfg.ham_weight, "AI analysis classified message as ham")
reg("SPAMALLAM_WHITELIST", 0.0, "Admin whitelist override (forces delivery as ham)")
reg("SPAMALLAM_SIG_INVALID", 1.0, "X-SpamAllam headers present but signature invalid")
reg("SPAMALLAM_SKIPPED", 0.0, "AI analysis skipped or errored")
