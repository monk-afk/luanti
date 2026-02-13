local modname = core.get_current_modname()
local builtin = core.builtin_auth_handler
local http = core.request_http_api()

if not http then
	error("[" .. modname .. "] request_http_api() returned nil. " ..
		"Add this mod name to secure.http_mods.")
end

local cfg_url = core.settings:get(modname .. ".url") or "http://127.0.0.1:8085/auth"
local cfg_timeout = tonumber(core.settings:get(modname .. ".timeout")) or 10
local cfg_use_remote_privs = core.settings:get_bool(modname .. ".use_remote_privileges", false)
local cfg_log_pending_polls = core.settings:get_bool(modname .. ".log_pending_polls", false)
local log_prefix = "[" .. modname .. "] "

local inflight = {}
local cache = {}

local function log(level, msg)
	core.log(level, log_prefix .. msg)
end

local function clone_entry(entry)
	local privs = {}
	for priv, enabled in pairs(entry.privileges or {}) do
		if enabled then
			privs[priv] = true
		end
	end

	return {
		password = entry.password,
		privileges = privs,
		last_login = entry.last_login or 0,
	}
end

local function normalize_privs(raw_privs)
	local out = {}

	if type(raw_privs) == "table" then
		local saw_numeric = false
		for k, v in pairs(raw_privs) do
			if type(k) == "number" and type(v) == "string" then
				saw_numeric = true
				out[v] = true
			end
		end

		if not saw_numeric then
			for k, v in pairs(raw_privs) do
				if type(k) == "string" and v then
					out[k] = true
				end
			end
		end
	end

	return out
end

local function get_local_privs(name)
	local entry = builtin.get_auth(name)
	if entry and type(entry.privileges) == "table" then
		return normalize_privs(entry.privileges)
	end

	local default_privs = core.settings:get("default_privs") or ""
	return normalize_privs(core.string_to_privs(default_privs))
end

local function build_auth_entry(name, payload)
	if type(payload) ~= "table" or payload.allow ~= true then
		return nil
	end

	local password = payload.password_srp
	if type(password) ~= "string" and type(payload.password) == "string" then
		password = core.get_password_hash(name, payload.password)
	end
	if type(password) ~= "string" or password == "" then
		return nil
	end

	return {
		password = password,
		privileges = cfg_use_remote_privs and
			normalize_privs(payload.privileges) or
			get_local_privs(name),
		last_login = tonumber(payload.last_login) or 0,
	}
end

local handler = {
	get_auth = function(name)
		assert(type(name) == "string")
		local entry = cache[name]
		if entry then
			log("verbose", "get_auth cache hit for " .. name)
			return clone_entry(entry)
		end
		log("verbose", "get_auth delegating to builtin for " .. name)
		return builtin.get_auth(name)
	end,

	begin_auth = function(name, ip)
		assert(type(name) == "string")
		log("action", "begin_auth name=" .. name .. " ip=" .. tostring(ip or ""))

		-- Keep existing local accounts working during testing.
		local local_entry = builtin.get_auth(name)
		if local_entry then
			log("action", "begin_auth resolved by local builtin auth for " .. name)
			return local_entry
		end

		local url = cfg_url ..
			"?name=" .. core.urlencode(name) ..
			"&ip=" .. core.urlencode(ip or "")

		local req = {
			url = url,
			method = "GET",
			timeout = cfg_timeout,
		}

		local handle = http.fetch_async(req)
		inflight[handle] = {
			name = name,
			started = os.time(),
		}
		log("action", "begin_auth queued async request for " .. name .. " handle=" .. handle)
		return handle
	end,

	poll_auth = function(name, handle)
		assert(type(name) == "string")
		assert(type(handle) == "string")

		local req = inflight[handle]
		if not req or req.name ~= name then
			log("warning", "poll_auth invalid handle for " .. name .. " handle=" .. handle)
			return false
		end

		local res = http.fetch_async_get(handle)
		if not res.completed then
			if cfg_log_pending_polls then
				log("verbose", "poll_auth pending for " .. name .. " handle=" .. handle)
			end
			return nil
		end

		inflight[handle] = nil

		if not res.succeeded or res.code ~= 200 then
			log("warning", "HTTP auth failed for " .. name ..
				", succeeded=" .. tostring(res.succeeded) ..
				", code=" .. tostring(res.code))
			return false
		end

		local payload, err = core.parse_json(res.data, nil, true)
		if not payload then
			log("warning", "JSON parse failed for " .. name ..
				": " .. tostring(err))
			return false
		end

		local entry = build_auth_entry(name, payload)
		if not entry then
			log("action", "auth denied or invalid payload for " .. name)
			return false
		end

		cache[name] = entry
		local priv_count = 0
		for _ in pairs(entry.privileges or {}) do
			priv_count = priv_count + 1
		end
		log("action", "auth success for " .. name .. " (cached, privs=" .. priv_count .. ")")
		return clone_entry(entry)
	end,

	create_auth = function(name, password)
		log("action", "create_auth " .. name)
		return builtin.create_auth(name, password)
	end,

	delete_auth = function(name)
		cache[name] = nil
		log("action", "delete_auth " .. name)
		return builtin.delete_auth(name)
	end,

	set_password = function(name, password)
		cache[name] = nil
		log("action", "set_password " .. name)
		return builtin.set_password(name, password)
	end,

	set_privileges = function(name, privileges)
		log("action", "set_privileges " .. name)
		local ok = builtin.set_privileges(name, privileges)
		local entry = cache[name]
		if ok and entry then
			entry.privileges = normalize_privs(privileges)
		end
		return ok
	end,

	reload = function()
		cache = {}
		log("action", "reload")
		return true
	end,

	record_login = function(name)
		local entry = cache[name]
		if entry then
			entry.last_login = os.time()
		end
		log("verbose", "record_login " .. name)
		return true
	end,

	iterate = function()
		return builtin.iterate()
	end,
}

core.register_authentication_handler(handler)
log("action", "registered async authentication handler " ..
	"(url=" .. cfg_url .. ", timeout=" .. tostring(cfg_timeout) ..
	", use_remote_privileges=" .. tostring(cfg_use_remote_privs) ..
	", log_pending_polls=" .. tostring(cfg_log_pending_polls) .. ")")
