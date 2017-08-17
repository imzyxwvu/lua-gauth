local sha1 = require "sha1"
local band = (bit32 or bit).band

local function base32dec(str)
	local function map(ch)
		if ch > 49 and ch <= 55 then return ch - 24 end
		if ch > 64 and ch <= 90 then return ch - 65 end
		if ch > 96 and ch <= 122 then return ch - 97 end
		error("invalid character in Base32 secret")
	end
	local function b32halfdec(s, z)
		local a, b, c, d = s:byte(z + 1, z + 4)
		local e, f, g, h = s:byte(z + 5, z + 8)
		a, b, c, d = map(a), map(b), map(c), map(d)
		e, f, g, h = map(e), map(f), map(g), map(h)
		local i = a * 8 + band(b, 0x1C) / 4
		local j = band(b, 0x3) * 0x40 + c * 2 + band(d, 0x10) / 0x10
		local k = band(d, 0xF) * 0x10 + band(e, 0x1E) / 2
		local l = band(e, 1) * 0x80 + f * 4 + band(g, 0x18) / 8
		local m = band(g, 7) * 0x20 + h
		return string.char(i, j, k, l, m)
	end
	if #str == 8 then
		return b32halfdec(str, 0)
	else
		return b32halfdec(str, 0) .. b32halfdec(str, 8)
	end
end

local function generate_code(skey, value)
	value = string.char(
		0, 0, 0, 0,
		band(value, 0xFF000000) / 0x1000000,
		band(value, 0xFF0000) / 0x10000,
		band(value, 0xFF00) / 0x100,
		band(value, 0xFF))
	local hash = sha1.hmac_binary(skey, value)
	local offset = band(hash:byte(-1), 0xF)
	local function bytesToInt(a,b,c,d)
		return a*0x1000000 + b*0x10000 + c*0x100 + d
	end
	hash = bytesToInt(hash:byte(offset + 1, offset + 4))
	hash = band(hash, 0x7FFFFFFF) % 1000000
	return ("%06d"):format(hash)
end

local gauth = {}

function gauth.gencode(skey)
	return generate_code(base32dec(skey), math.floor(os.time() / 30))
end

function gauth.check(skey, value)
	local base = math.floor(os.time() / 30)
	skey = base32dec(skey)
	if generate_code(skey, base) == value then return true end
	if generate_code(skey, base - 1) == value then return true end
	if generate_code(skey, base + 1) == value then return true end
	return false
end

return gauth
