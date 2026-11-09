package com.isolve.vapt.zap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.testng.Assert.*;

/**
 * Offline passive analysis of a synthetic HAR (fake host on loopback, fake secrets). Proves:
 * ZAP raises passive leads from the file, NO request reaches the "target" (a counting loopback
 * server named in the HAR), out-of-scope entries are dropped, no fake secret reaches any output
 * file, and the ZAP session holding raw traffic is deleted afterwards.
 *
 * Runs only with -Dzap.install.dir=C:\Tools\ZAP_2.17.0 (see ZapPassiveLocalIT).
 */
public class ZapHarPassiveLocalIT {

    private static final List<String> SECRETS = List.of(
            "FAKE-COOKIE-777", "FAKE-PASS-888", "FAKE-TOKEN-999", "FAKE-OTP-4321", "FAKE-QUERY-555");

    private HttpServer target;
    private final AtomicInteger hits = new AtomicInteger();
    private int port;
    private Path zapDir;
    private Path zapHome;

    private static String prop(String name) {
        String v = System.getProperty(name, "");
        return v.isBlank() || v.startsWith("${") ? "" : v;
    }

    @BeforeClass
    public void setUp() throws Exception {
        String installDir = prop("zap.install.dir");
        if (installDir.isEmpty()) throw new SkipException("zap.install.dir not set - ZAP HAR test skipped");
        zapDir = Path.of(installDir);
        String home = prop("zap.home.dir");
        zapHome = home.isEmpty() ? Path.of("target", "zap-home") : Path.of(home);
        // A real listener at the HAR's address: any request ZAP sent would be counted here.
        target = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        target.createContext("/", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        target.start();
        port = target.getAddress().getPort();
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (target != null) target.stop(0);
    }

    @Test
    public void harImportGivesRedactedLeadsWithoutTraffic() throws Exception {
        String base = "http://127.0.0.1:" + port;
        Path har = Path.of("target", "synthetic-walk.har");
        Files.createDirectories(har.getParent());
        writeHar(har, base);
        Path out = Path.of("target", "zap-har-it");

        ZapPassiveAnalysis.Result r = ZapPassiveAnalysis.analyzeHar(zapDir, zapHome, "LOCAL-FAKE",
                List.of("127.0.0.1:" + port), List.of(har), out);
        System.out.println("HAR PASSIVE: " + r + " -> " + r.html);

        assertEquals(hits.get(), 0, "passive analysis must not send any request to the target");
        assertTrue(r.messagesRecorded >= 3, "HAR entries imported into ZAP: " + r.messagesRecorded);
        assertTrue(r.leads > 0, "missing headers / cookie flags / error disclosure should raise leads");

        String html = Files.readString(r.html);
        String csv = Files.readString(r.csv);
        String json = Files.readString(r.json);
        assertTrue(html.contains("VAPT-010") || html.contains("VAPT-025") || html.contains("VAPT-014"),
                "leads linked to checklist items");
        assertTrue(json.contains("\"status\" : \"To verify\""), "every lead is To verify");
        assertFalse(html.contains("other.example"), "out-of-scope host must not be reported");
        for (String content : List.of(html, csv, json)) {
            for (String s : SECRETS) assertFalse(content.contains(s), s + " leaked into the report");
        }

        // The raw ZAP session (holds cookies/tokens) is deleted when the daemon closes.
        Path sessions = zapHome.resolve("run-sessions");
        try (Stream<Path> s = Files.exists(sessions) ? Files.list(sessions) : Stream.empty()) {
            List<String> left = s.map(p -> p.getFileName().toString()).filter(n -> n.endsWith(".data") || n.endsWith(".script")).toList();
            assertTrue(left.isEmpty(), "ZAP run session files should be deleted: " + left);
        }
    }

    // ---------------- synthetic HAR ----------------
    private static void writeHar(Path file, String base) throws Exception {
        List<Object> entries = new ArrayList<>();
        entries.add(entry("GET", base + "/home?ref=FAKE-QUERY-555", List.of(), null,
                200, "text/html",
                List.of(h("Content-Type", "text/html"), h("Server", "Apache/2.4.1 (Unix)"),
                        h("Set-Cookie", "SESSIONID=FAKE-COOKIE-777; Path=/")),
                "<html><body>home</body></html>"));
        entries.add(entry("POST", base + "/api/login",
                List.of(h("Content-Type", "application/json"), h("Authorization", "Bearer FAKE-TOKEN-999")),
                "{\"user\":\"tester\",\"password\":\"FAKE-PASS-888\",\"otp\":\"FAKE-OTP-4321\"}",
                500, "text/html", List.of(h("Content-Type", "text/html")),
                "<html><body>Internal Server Error java.lang.NullPointerException\n"
                        + "\tat com.example.LoginService.login(LoginService.java:42)\n"
                        + "\tat org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:199)</body></html>"));
        entries.add(entry("GET", base + "/api/customer/1001", List.of(h("Authorization", "Bearer FAKE-TOKEN-999")), null,
                200, "application/json", List.of(h("Content-Type", "application/json"), h("X-Powered-By", "Express")),
                "{\"id\":1001,\"name\":\"test\"}"));
        entries.add(entry("GET", "http://other.example/page", List.of(), null,
                200, "text/html", List.of(h("Content-Type", "text/html")), "<html>out of scope</html>"));

        Map<String, Object> log = new LinkedHashMap<>();
        log.put("version", "1.2");
        log.put("creator", Map.of("name", "vapt-it", "version", "1"));
        log.put("pages", List.of());
        log.put("entries", entries);
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(file.toFile(), Map.of("log", log));
    }

    private static Map<String, Object> h(String name, String value) {
        return Map.of("name", name, "value", value);
    }

    private static Map<String, Object> entry(String method, String url, List<Map<String, Object>> reqHeaders, String reqBody,
                                             int status, String mime, List<Map<String, Object>> respHeaders, String respBody) {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("method", method);
        req.put("url", url);
        req.put("httpVersion", "HTTP/1.1");
        List<Map<String, Object>> rh = new ArrayList<>(reqHeaders);
        rh.add(h("Host", url.replaceFirst("^https?://", "").replaceFirst("/.*$", "")));
        req.put("headers", rh);
        req.put("queryString", List.of());
        req.put("cookies", List.of());
        req.put("headersSize", -1);
        req.put("bodySize", reqBody == null ? 0 : reqBody.length());
        if (reqBody != null) req.put("postData", Map.of("mimeType", "application/json", "text", reqBody, "params", List.of()));

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", status);
        resp.put("statusText", status == 200 ? "OK" : "Internal Server Error");
        resp.put("httpVersion", "HTTP/1.1");
        resp.put("headers", respHeaders);
        resp.put("cookies", List.of());
        resp.put("content", Map.of("size", respBody.length(), "mimeType", mime, "text", respBody));
        resp.put("redirectURL", "");
        resp.put("headersSize", -1);
        resp.put("bodySize", respBody.length());

        Map<String, Object> e = new LinkedHashMap<>();
        e.put("startedDateTime", "2026-11-09T10:00:00.000Z");
        e.put("time", 10);
        e.put("request", req);
        e.put("response", resp);
        e.put("cache", Map.of());
        e.put("timings", Map.of("send", 1, "wait", 8, "receive", 1));
        return e;
    }
}
