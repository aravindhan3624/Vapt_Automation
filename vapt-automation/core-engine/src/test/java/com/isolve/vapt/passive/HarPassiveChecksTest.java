package com.isolve.vapt.passive;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

/** Offline Phase 5 over a synthetic HAR (fake host, fake values). Reads the file only. */
public class HarPassiveChecksTest {

    @Test
    public void harChecksScopeAndRedaction() throws Exception {
        Path dir = Path.of("target", "har-passive-unit");
        Files.createDirectories(dir);
        Path har = dir.resolve("walk.har");

        List<Object> entries = new ArrayList<>();
        entries.add(entry("https://dev.example/app/", "document", 200, "text/html", "<html>x</html>", false,
                h("Content-Type", "text/html"), h("Set-Cookie", "SID=FAKE-SID-123; Path=/")));
        entries.add(entry("https://dev.example/api/customer?mobile=9876543210", "fetch", 200, "application/json",
                "{\"customerPan\":\"ABCPE1234F\",\"note\":\"ok\"}", true,
                h("Content-Type", "application/json"), h("Cache-Control", "no-store")));
        entries.add(entry("https://other.example/api/x", "fetch", 500, "application/json",
                "{\"error\":\"java.lang.NullPointerException\"}", false, h("Content-Type", "application/json")));
        Map<String, Object> log = new LinkedHashMap<>();
        log.put("version", "1.2");
        log.put("entries", entries);
        new ObjectMapper().writeValue(har.toFile(), Map.of("log", log));

        String[] paths = new String[2];
        PassiveCheckReport r = HarPassiveChecks.run("UNIT", List.of("dev.example"), List.of(har), dir, paths);
        assertEquals(r.observations, 2, "out-of-scope entry ignored");
        Map<String, PassiveChecks.Result> byId = new LinkedHashMap<>();
        r.checks.forEach(c -> byId.put(c.id, c));
        assertTrue(byId.get("P5-D01").names.contains("customerPan"), "base64 body decoded and checked");
        assertTrue(byId.get("P5-D03").names.contains("?mobile"), "mobile number in URL");
        assertTrue(byId.get("P5-C01").names.contains("SID"));
        assertEquals(byId.get("P5-E01").hits, 0, "error on the out-of-scope host is not counted");
        assertEquals(byId.get("P5-T02").status, PassiveChecks.NOT_CHECKED, "HAR has no TLS details");

        String all = Files.readString(Path.of(paths[0])) + Files.readString(Path.of(paths[1]));
        for (String v : List.of("FAKE-SID-123", "ABCPE1234F", "9876543210", "other.example")) {
            assertFalse(all.contains(v), v + " in report");
        }
    }

    private static Map<String, Object> h(String n, String v) {
        return Map.of("name", n, "value", v);
    }

    @SafeVarargs
    private static Map<String, Object> entry(String url, String type, int status, String mime, String body, boolean base64,
                                             Map<String, Object>... headers) {
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("mimeType", mime);
        content.put("text", base64 ? Base64.getEncoder().encodeToString(body.getBytes(StandardCharsets.UTF_8)) : body);
        if (base64) content.put("encoding", "base64");
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("_resourceType", type);
        e.put("request", Map.of("method", "GET", "url", url, "headers", List.of()));
        e.put("response", Map.of("status", status, "headers", List.of(headers), "content", content));
        return e;
    }
}
