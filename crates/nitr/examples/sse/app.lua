-- Server-Sent Events: nitr.sse(fn) builds a streaming text/event-stream
-- response; send(event, data) writes one event (tables are JSON-encoded).
--
-- `nitr.ext.time` is a custom Rust module registered by main.rs via
-- ServerBuilder::module() — nitr.ext.time.sleep(ms) suspends this state's
-- coroutine on the tokio timer, so the pacing costs no execution budget
-- and blocks nothing.

local app = nitr.app()

app:get("/", function(req)
    return nitr.html([[
<!doctype html>
<ul id="log"></ul>
<script>
  const es = new EventSource("/events");
  const log = (e) => {
    const li = document.createElement("li");
    li.textContent = e.type + ": " + e.data;
    document.getElementById("log").append(li);
  };
  es.addEventListener("tick", log);
  es.addEventListener("done", (e) => { log(e); es.close(); });
</script>
]])
end)

app:get("/events", function(req)
    return nitr.sse(function(send)
        for i = 1, 5 do
            send("tick", { count = i })
            nitr.ext.time.sleep(1000)
        end
        send("done", "stream finished")
    end)
end)

return app
