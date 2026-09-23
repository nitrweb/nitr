-- SPDX-License-Identifier: MIT OR Apache-2.0
-- This file is part of Nitr.
-- See https://nitrweb.com/ for more information
-- Copyright (C) 2024-present Jose Quintana <joseluisq.net>

-- The `nitr test` framework, loaded into every test state before the test
-- file runs. Assertions, hooks and the client's cookie jar are Lua on
-- purpose: they must be readable and extensible by the people writing
-- tests. The request path, the doubles, the clock and the report stay in
-- Rust — a test that bypasses the router tests nothing.
--
-- Execution is collect, then run: `t.it` only registers; when the file's
-- chunk returns, the runner plans the list (`t._plan`) and calls each test
-- with its own budgeted call (`t._run`), so every test has its own
-- instruction budget, timeout, duration, log capture and fresh doubles.
--
-- A test file may also be a bare script of asserts (the pre-framework
-- style); it registers nothing and passes if it runs to completion.

local t = nitr.test

t._tests = {}
-- Set by the runner before this file loads: --filter substring and the
-- current file's name.
t._filter = t._filter or ""
t._file = t._file or ""
-- Whether any `t.only` is in this file.
t._focused = false

local root = {
    prefix = "",
    before_each = {},
    after_each = {},
    before_all = {},
    after_all = {},
}
local current = root

-- Bounds for rendered values: a large response body or table must not
-- drown the report.
local MAX_STRING = 256
local MAX_ENTRIES = 40
local MAX_DEPTH = 3

-- Renders a value for a failure message: strings quoted, tables serialized
-- with sorted keys, everything bounded (depth, entries, string length).
local function render(value, depth)
    depth = depth or 0
    local kind = type(value)
    if kind == "string" then
        if #value > MAX_STRING then
            return string.format("%q", value:sub(1, MAX_STRING)) .. "..."
        end
        return string.format("%q", value)
    elseif kind ~= "table" then
        return tostring(value)
    elseif depth >= MAX_DEPTH then
        return "{...}"
    end
    local keys = {}
    for k in pairs(value) do
        keys[#keys + 1] = k
    end
    table.sort(keys, function(a, b)
        return tostring(a) < tostring(b)
    end)
    local parts = {}
    for i, k in ipairs(keys) do
        if i > MAX_ENTRIES then
            parts[#parts + 1] = "... (" .. (#keys - MAX_ENTRIES) .. " more)"
            break
        end
        local key = type(k) == "string" and k or ("[" .. tostring(k) .. "]")
        parts[#parts + 1] = key .. " = " .. render(value[k], depth + 1)
    end
    return "{ " .. table.concat(parts, ", ") .. " }"
end
t._render = render

-- Deep equality for to_equal: tables compare by structure, not identity.
local function deep_eq(a, b)
    if a == b then
        return true
    end
    if type(a) ~= "table" or type(b) ~= "table" then
        return false
    end
    for k, v in pairs(a) do
        if not deep_eq(v, b[k]) then
            return false
        end
    end
    for k in pairs(b) do
        if a[k] == nil then
            return false
        end
    end
    return true
end

-- Subset equality for to_match_object: every key of `subset` deep-equals
-- (recursively, as a subset again) the same key in `actual`; extra keys in
-- `actual` are ignored.
local function match_object(actual, subset)
    if type(subset) ~= "table" then
        return deep_eq(actual, subset)
    end
    if type(actual) ~= "table" then
        return false
    end
    for k, v in pairs(subset) do
        if not match_object(actual[k], v) then
            return false
        end
    end
    return true
end

-- The failure carries file:line (error level 3 points at the assertion in
-- the test, not at the matcher) plus both rendered values. A matcher that
-- fails through a helper passes how many frames the helper adds.
local function fail(message, helpers)
    error(message, 3 + (helpers or 0))
end

local function is_response(value)
    return type(value) == "table" and math.type(value.status) ~= nil and type(value.body) == "string"
end

-- A response's explanation for a failure message: a bounded body excerpt
-- and, when the handler raised, the error the server classified.
local function explain_response(resp)
    local lines = {}
    local body = resp.body
    if #body > 512 then
        body = body:sub(1, 512) .. "..."
    end
    if #body > 0 then
        lines[#lines + 1] = "body: " .. body
    end
    local err = resp.error
    if type(err) == "table" then
        local where = err.source and (" (" .. tostring(err.source) .. ":" .. tostring(err.line) .. ")") or ""
        local handled = err.handled and " [handled by on_error]" or ""
        lines[#lines + 1] = tostring(err.kind) .. ": " .. tostring(err.message) .. where .. handled
        if type(err.traceback) == "string" then
            local shown = 0
            for line in err.traceback:gmatch("[^\n]+") do
                shown = shown + 1
                if shown > 6 then
                    break
                end
                lines[#lines + 1] = "  " .. line
            end
        end
    end
    if #lines == 0 then
        return ""
    end
    return "\n" .. table.concat(lines, "\n")
end

-- Every value of a header: from `raw_headers` on a `t.request` response,
-- from `headers` (any case) on a table a handler returned.
local function header_values(resp, name)
    local values = {}
    name = name:lower()
    if resp.raw_headers == nil then
        for key, value in pairs(type(resp.headers) == "table" and resp.headers or {}) do
            if type(key) == "string" and key:lower() == name then
                if type(value) == "table" then
                    for _, item in ipairs(value) do
                        values[#values + 1] = tostring(item)
                    end
                else
                    values[#values + 1] = tostring(value)
                end
            end
        end
        return values
    end
    for _, pair in ipairs(resp.raw_headers) do
        if pair[1] == name then
            values[#values + 1] = pair[2]
        end
    end
    return values
end

function t.expect(actual)
    local m = {}
    function m.to_equal(expected)
        if not deep_eq(actual, expected) then
            fail("expected " .. render(actual) .. " to equal " .. render(expected))
        end
    end
    function m.to_not_equal(expected)
        if deep_eq(actual, expected) then
            fail("expected " .. render(actual) .. " to differ from " .. render(expected))
        end
    end
    function m.to_be_nil()
        if actual ~= nil then
            fail("expected " .. render(actual) .. " to be nil")
        end
    end
    function m.to_not_be_nil()
        if actual == nil then
            fail("expected a value, got nil")
        end
    end
    function m.to_be_truthy()
        if not actual then
            fail("expected " .. render(actual) .. " to be truthy")
        end
    end
    function m.to_be_false()
        if actual ~= false then
            fail("expected " .. render(actual) .. " to be false")
        end
    end
    function m.to_be_a(kind)
        local actual_kind = type(actual)
        if kind == "integer" or kind == "float" then
            actual_kind = math.type(actual) or actual_kind
        end
        if actual_kind ~= kind then
            fail("expected " .. render(actual) .. " to be a " .. kind .. ", got a " .. actual_kind)
        end
    end
    function m.to_have_length(n)
        if type(actual) ~= "string" and type(actual) ~= "table" then
            fail("expected a string or table with length " .. n .. ", got " .. render(actual))
        elseif #actual ~= n then
            fail("expected length " .. n .. ", got " .. #actual .. ": " .. render(actual))
        end
    end
    local function compare(op, n, holds)
        if type(actual) ~= "number" or type(n) ~= "number" then
            fail("expected a number " .. op .. " " .. render(n) .. ", got " .. render(actual), 1)
        elseif not holds(actual, n) then
            fail("expected " .. render(actual) .. " " .. op .. " " .. render(n), 1)
        end
    end
    function m.to_be_greater_than(n)
        compare("to be greater than", n, function(a, b) return a > b end)
    end
    function m.to_be_greater_than_or_equal(n)
        compare("to be greater than or equal to", n, function(a, b) return a >= b end)
    end
    function m.to_be_less_than(n)
        compare("to be less than", n, function(a, b) return a < b end)
    end
    function m.to_be_less_than_or_equal(n)
        compare("to be less than or equal to", n, function(a, b) return a <= b end)
    end
    function m.to_have_key(key)
        if type(actual) ~= "table" then
            fail("expected a table with key " .. render(key) .. ", got " .. render(actual))
        elseif actual[key] == nil then
            fail("expected " .. render(actual) .. " to have key " .. render(key))
        end
    end
    function m.to_match_object(subset)
        if not match_object(actual, subset) then
            fail("expected " .. render(actual) .. " to match " .. render(subset))
        end
    end
    function m.to_match(pattern)
        if type(actual) ~= "string" or not actual:find(pattern) then
            fail("expected " .. render(actual) .. " to match " .. render(pattern))
        end
    end
    function m.to_not_match(pattern)
        if type(actual) == "string" and actual:find(pattern) then
            fail("expected " .. render(actual) .. " not to match " .. render(pattern))
        end
    end
    local function contains(needle)
        if type(actual) == "string" then
            return actual:find(needle, 1, true) ~= nil
        elseif type(actual) == "table" then
            for _, v in pairs(actual) do
                if deep_eq(v, needle) then
                    return true
                end
            end
            return false
        end
        return nil
    end
    function m.to_contain(needle)
        local found = contains(needle)
        if found == nil then
            fail("expected a string or table, got " .. render(actual))
        elseif not found then
            fail("expected " .. render(actual) .. " to contain " .. render(needle))
        end
    end
    function m.to_not_contain(needle)
        local found = contains(needle)
        if found == nil then
            fail("expected a string or table, got " .. render(actual))
        elseif found then
            fail("expected " .. render(actual) .. " not to contain " .. render(needle))
        end
    end
    function m.to_throw(pattern)
        if type(actual) ~= "function" then
            fail("expected a function to call, got " .. render(actual))
        end
        local ok, err = pcall(actual)
        if ok then
            fail("expected the function to throw, but it did not throw")
        end
        local message = tostring(err)
        if pattern ~= nil and not message:find(pattern, 1, true) then
            fail("expected the error to contain " .. render(pattern) .. ", got " .. render(message))
        end
    end
    function m.to_not_throw()
        if type(actual) ~= "function" then
            fail("expected a function to call, got " .. render(actual))
        end
        local ok, err = pcall(actual)
        if not ok then
            fail("expected the function not to throw, but it threw " .. render(tostring(err)))
        end
    end
    function m.to_contain_log(subset)
        if type(actual) ~= "table" then
            fail("expected a list of log entries (t.logs()), got " .. render(actual))
        end
        for _, entry in ipairs(actual) do
            if match_object(entry, subset) then
                return
            end
        end
        fail("expected a log entry matching " .. render(subset) .. " among " .. #actual .. " entries: " .. render(actual))
    end
    function m.to_have_status(status)
        if not is_response(actual) then
            fail("expected a response, got " .. render(actual))
        end
        if actual.status ~= status then
            fail("expected status " .. tostring(status) .. ", got " .. tostring(actual.status) .. explain_response(actual))
        end
    end
    function m.to_have_header(name, expected)
        if not is_response(actual) then
            fail("expected a response, got " .. render(actual))
        end
        local values = header_values(actual, name)
        if #values == 0 then
            fail("expected header " .. name .. ", but it is absent")
        end
        if expected == nil then
            return
        end
        for _, value in ipairs(values) do
            if value == expected or value:find(expected) then
                return
            end
        end
        fail("expected header " .. name .. " to match " .. render(expected) .. ", got " .. render(values))
    end
    function m.to_have_json(subset)
        if not is_response(actual) then
            fail("expected a response, got " .. render(actual))
        end
        -- A `t.request` response decodes itself; a table a handler
        -- returned (through `t.app()`) has only its body.
        local ok, decoded
        if type(actual.json) == "function" then
            ok, decoded = pcall(actual.json, actual)
        else
            ok, decoded = pcall(t._decode_json, actual.body)
        end
        if not ok then
            fail("expected a JSON body, but it does not decode: " .. tostring(decoded) .. explain_response(actual))
        end
        if not match_object(decoded, subset) then
            fail("expected the JSON body " .. render(decoded) .. " to match " .. render(subset))
        end
    end
    return m
end

-- ------------------------------------------------------------ structure

-- The groups enclosing `current`, outermost first.
local function group_chain()
    local chain = {}
    local g = current
    while g do
        table.insert(chain, 1, g)
        g = g.parent
    end
    return chain
end

-- Registers one test. Hooks are snapshotted now: a `before_each` applies
-- to the tests registered after it, as it always has.
local function register(name, fn, kind, reason)
    if type(name) ~= "string" then
        error("a test name must be a string, got " .. type(name), 3)
    end
    if fn ~= nil and type(fn) ~= "function" then
        error("the body of test " .. string.format("%q", name) .. " must be a function", 3)
    end
    local chain = group_chain()
    local before, after = {}, {}
    for _, g in ipairs(chain) do
        for _, hook in ipairs(g.before_each) do
            before[#before + 1] = hook
        end
    end
    for i = #chain, 1, -1 do
        for _, hook in ipairs(chain[i].after_each) do
            after[#after + 1] = hook
        end
    end
    local test = {
        name = current.prefix .. name,
        fn = fn,
        kind = kind,
        reason = reason,
        before = before,
        after = after,
        groups = chain,
        site = t._site(),
    }
    t._tests[#t._tests + 1] = test
    return test
end

function t.it(name, fn)
    if type(fn) ~= "function" then
        error("t.it(name, fn) needs a function body", 2)
    end
    register(name, fn, "it")
end

-- A skipped test, reported apart from --filter's "filtered out": a skip
-- is in the file, a filter is on the command line. The optional second
-- argument is the body (kept for later) or the reason.
function t.skip(name, fn_or_reason)
    local reason = type(fn_or_reason) == "string" and fn_or_reason or "skipped"
    local fn = type(fn_or_reason) == "function" and fn_or_reason or nil
    register(name, fn, "skip", reason)
end

-- A test not written yet; `--list` shows it.
function t.todo(name)
    register(name, nil, "todo", "todo")
end

-- Focuses the run: the file's other tests are skipped with the reason
-- `only`, and the run fails while any `only` is left in place, so a
-- focused file cannot land in CI green.
function t.only(name, fn)
    if type(fn) ~= "function" then
        error("t.only(name, fn) needs a function body", 2)
    end
    t._focused = true
    register(name, fn, "only")
end

-- Fails the current test from anywhere.
function t.fail(message)
    error(message or "t.fail() called", 2)
end

-- `string.format` with arguments made safe for a test name: tables
-- rendered, long strings cut, a bad pattern falling back to the case's
-- number.
local function case_name(pattern, values, index)
    local args = {}
    for i = 1, values.n or #values do
        local v = values[i]
        if type(v) == "table" then
            v = render(v)
        elseif type(v) == "string" and #v > 60 then
            v = v:sub(1, 60) .. "..."
        elseif v == nil then
            v = "nil"
        end
        args[i] = v
    end
    local ok, name = pcall(string.format, pattern, table.unpack(args, 1, values.n or #values))
    if ok then
        return name
    end
    return pattern .. " [" .. index .. "]"
end

-- t.each(cases)(name, fn): one test per case. A positional case (a list)
-- is formatted into `name` and unpacked into `fn`; a named case (a table
-- with string keys) is passed whole, and `name` formats its `name` field.
function t.each(cases)
    if type(cases) ~= "table" then
        error("t.each(cases) takes a list of cases", 2)
    end
    return function(pattern, fn)
        if type(fn) ~= "function" then
            error("t.each(cases)(name, fn) needs a function body", 2)
        end
        for i, case in ipairs(cases) do
            local args
            local label
            -- Positional when the case has any positive integer key, so
            -- `{ nil, "CODE" }` (a nil input, the classic validation case)
            -- stays positional; `n` is the highest index, holes included.
            local n = 0
            if type(case) == "table" then
                for k in pairs(case) do
                    if math.type(k) == "integer" and k > n then
                        n = k
                    end
                end
            end
            if type(case) == "table" and n == 0 then
                args = { case, n = 1 }
                label = case_name(pattern, { case.name or ("case " .. i), n = 1 }, i)
            elseif type(case) == "table" then
                args = { table.unpack(case, 1, n) }
                args.n = n
                label = case_name(pattern, args, i)
            else
                args = { case, n = 1 }
                label = case_name(pattern, args, i)
            end
            register(label, function()
                return fn(table.unpack(args, 1, args.n))
            end, "it")
        end
    end
end

local function hook_adder(field)
    return function(fn)
        if type(fn) ~= "function" then
            error("t." .. field .. "(fn) needs a function", 2)
        end
        local list = current[field]
        list[#list + 1] = fn
    end
end

-- Hooks attach to the enclosing describe (or the file): `before_*` run
-- outer to inner, `after_*` inner to outer. `before_all`/`after_all` run
-- once per group, around its first and last test that actually runs.
t.before_each = hook_adder("before_each")
t.after_each = hook_adder("after_each")
t.before_all = hook_adder("before_all")
t.after_all = hook_adder("after_all")

-- Groups tests under a name prefix. The body runs under pcall: a throw
-- fails the tests the body registered so far plus one synthetic
-- `<name> (describe body)` failure, and the file carries on with the next
-- group rather than aborting every later one.
function t.describe(name, fn)
    if type(fn) ~= "function" then
        error("t.describe(name, fn) needs a function body", 2)
    end
    local group = {
        name = name,
        prefix = current.prefix .. name .. " > ",
        parent = current,
        before_each = {},
        after_each = {},
        before_all = {},
        after_all = {},
    }
    local previous = current
    local first = #t._tests + 1
    current = group
    local ok, err = pcall(fn)
    current = previous
    if not ok then
        local message = tostring(err)
        for i = first, #t._tests do
            t._tests[i].preset_error = "the enclosing describe body failed: " .. message
        end
        local synthetic = register(name .. " (describe body)", nil, "error")
        synthetic.preset_error = message
    end
end

-- ------------------------------------------------------------ the runner's side

local function matches_filter(name)
    return t._filter == "" or name:find(t._filter, 1, true) ~= nil or t._file:find(t._filter, 1, true) ~= nil
end

-- Decides every test's fate before any runs, and where each group's
-- `before_all`/`after_all` belong: around its first and last test that
-- runs (a group left with none runs neither).
function t._plan()
    local out = {}
    for i, test in ipairs(t._tests) do
        local status, reason
        if test.preset_error then
            status = "failed"
        elseif not matches_filter(test.name) then
            -- The command line narrows first: a skip or a todo the filter
            -- excludes is noise, not news.
            status = "filtered"
        elseif test.kind == "todo" then
            status, reason = "todo", "todo"
        elseif test.kind == "skip" then
            status, reason = "skipped", test.reason
        elseif t._focused and test.kind ~= "only" then
            status, reason = "skipped", "only"
        else
            status = "run"
        end
        test.status = status
        out[i] = {
            name = test.name,
            status = status,
            reason = reason,
            site = test.site,
            error = test.preset_error,
            only = test.kind == "only",
        }
    end
    for i, test in ipairs(t._tests) do
        if test.status == "run" then
            for _, g in ipairs(test.groups) do
                g.first = g.first or i
                g.last = i
            end
        end
    end
    return out
end

local function call_hooks(hooks)
    for _, hook in ipairs(hooks) do
        local ok, err = pcall(hook)
        if not ok then
            return false, tostring(err)
        end
    end
    return true
end

-- Runs test `i` with its hooks; returns true, or false and the failure.
-- The runner calls this once per test, each call under its own budget.
function t._run(i)
    local test = t._tests[i]
    local ok, err = true, nil
    for _, g in ipairs(test.groups) do
        if g.first == i and not g.started then
            g.started = true
            -- Marked first: a before_all that exhausts the budget never
            -- returns here, and the group's other tests must not then run
            -- against setup that never happened.
            g.failed = "before_all did not complete (it ran out of the first test's budget)"
            local hook_ok, hook_err = call_hooks(g.before_all)
            if hook_ok then
                g.failed = nil
            else
                g.failed = "before_all failed: " .. hook_err
            end
        end
        if ok and g.failed then
            ok, err = false, g.failed
        end
    end
    if ok then
        ok, err = call_hooks(test.before)
    end
    if ok then
        local test_ok, test_err = pcall(test.fn)
        if not test_ok then
            ok, err = false, tostring(test_err)
        end
    end
    -- after_each always runs; its own failure marks the test failed only
    -- when the test itself had passed.
    for _, hook in ipairs(test.after) do
        local hook_ok, hook_err = pcall(hook)
        if ok and not hook_ok then
            ok, err = false, tostring(hook_err)
        end
    end
    for j = #test.groups, 1, -1 do
        local g = test.groups[j]
        if g.last == i then
            for _, hook in ipairs(g.after_all) do
                local hook_ok, hook_err = pcall(hook)
                if ok and not hook_ok then
                    ok, err = false, "after_all failed: " .. tostring(hook_err)
                end
            end
        end
    end
    return ok, err
end

-- ------------------------------------------------------------ the client

local METHODS = { "get", "post", "put", "patch", "delete", "head", "options" }

-- t.get(path, opts) and friends: t.request with the method filled in.
for _, method in ipairs(METHODS) do
    t[method] = function(path, opts)
        return t.request(method:upper(), path, opts)
    end
end

-- A cookie jar: cookies by name and path; Max-Age=0 and a past Expires
-- delete; expiry follows t.clock. Secure and Domain are stored and
-- reported, not enforced: there is no transport and one host.
local function new_jar()
    local jar = { _cookies = {} }

    local function expired(cookie)
        return cookie.expires_at ~= nil and cookie.expires_at <= t.clock.now()
    end

    local function path_matches(cookie_path, request_path)
        if cookie_path == "/" or cookie_path == request_path then
            return true
        end
        if request_path:sub(1, #cookie_path) ~= cookie_path then
            return false
        end
        return cookie_path:sub(-1) == "/" or request_path:sub(#cookie_path + 1, #cookie_path + 1) == "/"
    end

    -- RFC 6265 §5.1.4 default-path: the request path up to, not
    -- including, its last "/" — or "/" when that leaves nothing.
    local function default_path(request_path)
        local bare = request_path:match("^[^?]*")
        local dir = bare:match("^(.*)/[^/]*$")
        if dir == nil or dir == "" or bare:sub(1, 1) ~= "/" then
            return "/"
        end
        return dir
    end

    -- Stores what a response set, one `Set-Cookie` line at a time (a
    -- name may be set at two paths); a deletion removes the stored cookie.
    function jar:_store(resp, request_path)
        for _, cookie in ipairs(resp._set_cookies or {}) do
            local name = cookie.name
            local path = cookie.path
            if path == nil or path:sub(1, 1) ~= "/" then
                path = default_path(request_path)
            end
            local key = name .. "\0" .. path
            local expires_at = nil
            if cookie.max_age ~= nil then
                expires_at = t.clock.now() + cookie.max_age
            elseif cookie.expires ~= nil then
                expires_at = cookie.expires
            end
            local entry = {
                name = name,
                value = cookie.value,
                path = path,
                domain = cookie.domain,
                secure = cookie.secure,
                http_only = cookie.http_only,
                same_site = cookie.same_site,
                expires_at = expires_at,
            }
            if expired(entry) then
                self._cookies[key] = nil
            else
                self._cookies[key] = entry
            end
        end
    end

    -- The stored cookie (a table) or nil; with several paths, the most
    -- specific.
    function jar:get(name)
        local best
        for _, cookie in pairs(self._cookies) do
            if cookie.name == name and not expired(cookie) then
                if best == nil or #cookie.path > #best.path then
                    best = cookie
                end
            end
        end
        return best
    end

    -- Forges a cookie (a signed one: nitr.cookie.sign, or
    -- t.session_cookie).
    function jar:set(name, value, opts)
        opts = opts or {}
        local path = opts.path or "/"
        self._cookies[name .. "\0" .. path] = {
            name = name,
            value = value,
            path = path,
            http_only = opts.http_only,
            secure = opts.secure,
        }
    end

    function jar:clear()
        self._cookies = {}
    end

    -- The `cookies` option for a request to `path`.
    function jar:_for_path(path)
        local out = {}
        local found = false
        local bare = path:match("^[^?]*")
        for key, cookie in pairs(self._cookies) do
            if expired(cookie) then
                self._cookies[key] = nil
            elseif path_matches(cookie.path, bare) then
                local current_best = out[cookie.name]
                if current_best == nil or #cookie.path > #current_best.path then
                    out[cookie.name] = cookie
                end
                found = true
            end
        end
        if not found then
            return nil
        end
        local cookies = {}
        for name, cookie in pairs(out) do
            cookies[name] = cookie.value
        end
        return cookies
    end

    return jar
end

-- t.client(opts): defaults merged under every call (`base` path prefix,
-- `headers`, `remote_addr`) plus a cookie jar when `cookies = true`.
function t.client(defaults)
    defaults = defaults or {}
    local client = { jar = defaults.cookies and new_jar() or nil }

    function client:request(method, path, opts)
        opts = opts or {}
        local merged = {}
        for k, v in pairs(opts) do
            merged[k] = v
        end
        local headers = {}
        for k, v in pairs(defaults.headers or {}) do
            headers[k:lower()] = v
        end
        for k, v in pairs(opts.headers or {}) do
            headers[k:lower()] = v
        end
        merged.headers = headers
        if merged.remote_addr == nil then
            merged.remote_addr = defaults.remote_addr
        end
        local full = (defaults.base or "") .. path
        if self.jar then
            local from_jar = self.jar:_for_path(full)
            if from_jar then
                local cookies = {}
                for k, v in pairs(from_jar) do
                    cookies[k] = v
                end
                for k, v in pairs(opts.cookies or {}) do
                    cookies[k] = v
                end
                merged.cookies = cookies
            end
        end
        local resp = t.request(method, full, merged)
        if self.jar then
            self.jar:_store(resp, full)
        end
        return resp
    end

    for _, method in ipairs(METHODS) do
        client[method] = function(self, path, opts)
            return self:request(method:upper(), path, opts)
        end
    end
    return client
end

-- t.session_cookie(data, { secret, name?, max_age? }): exactly what
-- `session:save` would write, for a client's jar.
function t.session_cookie(data, opts)
    if type(data) ~= "table" or type(opts) ~= "table" then
        error("t.session_cookie(data, { secret = ... }) takes two tables", 2)
    end
    return t._session_value(data, opts.name or "session", opts.secret, opts.max_age)
end

-- t.app(): the application loaded into this test state, once per file.
local loaded_app
function t.app()
    if loaded_app == nil then
        loaded_app = t._load_app()
    end
    return loaded_app
end
