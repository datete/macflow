module("luci.controller.macflow", package.seeall)

local nixio = require "nixio"

function index()
    if not nixio.fs.access("/opt/macflow") then
        return
    end

    entry({"admin", "services", "macflow"}, firstchild(), _("MACFlow"), 60).dependent = false
    entry({"admin", "services", "macflow", "selfcheck"}, template("macflow/selfcheck"), _("Self Check"), 10).leaf = true
    entry({"admin", "services", "macflow", "run_selfcheck"}, call("run_selfcheck")).leaf = true
end

function run_selfcheck()
    local http = require "luci.http"
    local util = require "luci.util"

    http.prepare_content("application/json")
    local mode = http.formvalue("mode") or "quick"
    if mode ~= "quick" and mode ~= "full" then
        mode = "quick"
    end

    local cmd = string.format("/usr/bin/macflow-selfcheck %s 2>&1", mode)
    local out = util.exec(cmd)
    local ok = out and out:match("STATUS:%s+ALL SYSTEMS GO") ~= nil
    if mode == "full" then
        ok = out and out:match("ALL TEST SUITES PASSED") ~= nil
    end
    http.write_json({ ok = ok and true or false, mode = mode, output = out or "" })
end
