gauth = require "gauth"

seckey = "SECRET"
print(gauth.GenCode(seckey, math.floor(os.time() / 30)))

if gauth.Check(seckey, io.read()) then
    print "Pass"
else
    print "Bad code"
end

