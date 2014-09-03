Lua Google Authenticator
=========

This library can be used to check or generate the Google Authenticator's dynamic password. It also contains a fast base32 implement for Lua.

```
gauth = require "gauth"
seckey = "TESTtestTESTtest"
gauth.GenCode(seckey, math.floor(os.time() / 30))
if gauth.Check(seckey, io.read()) then
  print "Pass"
else
  print "Bad code"
end
```
