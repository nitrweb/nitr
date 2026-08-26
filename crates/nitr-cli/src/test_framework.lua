-- SPDX-License-Identifier: MIT OR Apache-2.0
-- This file is part of Nitr.
-- See https://nitrweb.com/ for more information
-- Copyright (C) 2024-present Jose Quintana <joseluisq.net>

-- The `nitr test` framework, loaded into every test state before the test
-- file runs. Assertions are Lua on purpose: they must be readable and
-- extensible by the people writing tests. `nitr.test.request` stays Rust —
-- a test that bypasses the router tests nothing.
--
-- A test file may also be a bare script of asserts (the pre-framework
-- style); it passes if it runs to completion.

local t = nitr.test

t._results = {}
t._before_each = {}
t._after_each = {}
t._prefix = ""
-- Set by the runner: --filter substring and the current file's name.
t._filter = t._filter or ""
t._file = t._file or ""

-- Renders a value for a failure message: strings quoted, tables serialized
-- with sorted keys, bounded depth so a huge value cannot drown the report.
local function render(value, depth)
    depth = depth or 0
    local kind = type(value)
    if kind == "string" then
        return string.format("%q", value)
    elseif kind ~= "table" then
        return tostring(value)
    elseif depth >= 3 then
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
    for _, k in ipairs(keys) do
        local key = type(k) == "string" and k or ("[" .. tostring(k) .. "]")
        parts[#parts + 1] = key .. " = " .. render(value[k], depth + 1)
    end
    return "{ " .. table.concat(parts, ", ") .. " }"
end

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

-- The failure carries file:line (error level 3 points at the assertion in
-- the test, not at the matcher) plus both rendered values.
local function fail(message)
    error(message, 3)
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
    function m.to_be_truthy()
        if not actual then
            fail("expected " .. render(actual) .. " to be truthy")
        end
    end
    function m.to_match(pattern)
        if type(actual) ~= "string" or not actual:find(pattern) then
            fail("expected " .. render(actual) .. " to match " .. render(pattern))
        end
    end
    function m.to_contain(needle)
        if type(actual) == "string" then
            if not actual:find(needle, 1, true) then
                fail("expected " .. render(actual) .. " to contain " .. render(needle))
            end
            return
        elseif type(actual) == "table" then
            for _, v in pairs(actual) do
                if deep_eq(v, needle) then
                    return
                end
            end
            fail("expected " .. render(actual) .. " to contain " .. render(needle))
        else
            fail("expected a string or table, got " .. render(actual))
        end
    end
    return m
end

function t.before_each(fn)
    t._before_each[#t._before_each + 1] = fn
end

function t.after_each(fn)
    t._after_each[#t._after_each + 1] = fn
end

function t.describe(name, fn)
    local previous = t._prefix
    t._prefix = previous .. name .. " > "
    fn()
    t._prefix = previous
end

function t.it(name, fn)
    local full = t._prefix .. name
    -- --filter matches against the test name or the file name.
    if t._filter ~= "" and not full:find(t._filter, 1, true) and not t._file:find(t._filter, 1, true) then
        t._results[#t._results + 1] = { name = full, skipped = true }
        return
    end
    for _, hook in ipairs(t._before_each) do
        hook()
    end
    local ok, err = pcall(fn)
    for _, hook in ipairs(t._after_each) do
        -- after_each always runs; its own failure marks the test failed
        -- only if the test itself had passed.
        local hook_ok, hook_err = pcall(hook)
        if ok and not hook_ok then
            ok, err = false, hook_err
        end
    end
    t._results[#t._results + 1] = {
        name = full,
        ok = ok,
        err = not ok and tostring(err) or nil,
    }
end
