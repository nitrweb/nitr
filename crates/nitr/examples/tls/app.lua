-- Handler for the `tls` example.
--
-- Nothing here knows about TLS, and that is the point: termination
-- happens in Rust, before a request ever reaches a Lua state, so a
-- handler written for plaintext serves over HTTPS unchanged.
local app = nitr.app()

app:get("/", function(req)
    return {
        status = 200,
        headers = { ["Content-Type"] = "text/plain" },
        body = "Served over TLS. The handler never had to care.\n",
    }
end)

-- What the server knows about the connection. `req.headers.host` is what
-- the client asked for, which is also the name the certificate had to
-- cover for the handshake to have got this far.
app:get("/whoami", function(req)
    return nitr.json({
        host = req.headers.host,
        path = req.path,
        method = req.method,
        -- Set this behind a terminating proxy instead; on a direct TLS
        -- listener the scheme is not in doubt.
        forwarded_proto = req.headers["x-forwarded-proto"],
    })
end)

return app
