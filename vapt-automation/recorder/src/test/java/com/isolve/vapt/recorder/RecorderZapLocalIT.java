package com.isolve.vapt.recorder;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.*;

/**
 * Recorder + live ZAP passive analysis against a LOCAL fake app (loopback only, headless Edge).
 * Proves: traffic goes through ZAP, ZAP raises passive leads, the app receives exactly the
 * requests the page itself made (ZAP adds none), and no fake secret reaches any output file.
 *
 * Runs only with Edge installed and -Dzap.install.dir=C:\Tools\ZAP_2.17.0.
 */
public class RecorderZapLocalIT {

    private static final String FAKE_COOKIE = "FAKE-COOKIE-4040";
    private static final String FAKE_TOKEN = "FAKE-TOKEN-5050";

    private HttpServer server;
    private int port;
    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    private Path zapDir;
    private Path zapHome;

    private static final String PAGE = """
            <!doctype html><html><head><title>loading</title><link rel="icon" href="data:,"></head>
            <body><h1>Fake app (local ZAP test)</h1><script>
            (async () => {
              const r = await fetch('/api/data', {headers: {'Authorization': 'Bearer %s'}});
              document.body.setAttribute('data-reply', await r.text());
              document.title = 'done';
            })();
            </script></body></html>
            """.formatted(FAKE_TOKEN);

    private static String prop(String name) {
        String v = System.getProperty(name, "");
        return v.isBlank() || v.startsWith("${") ? "" : v;
    }

    @BeforeClass
    public void setUp() throws IOException {
        boolean edge = new File("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe").isFile()
                || new File("C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe").isFile();
        if (!edge) throw new SkipException("Microsoft Edge not installed");
        String dir = prop("zap.install.dir");
        if (dir.isEmpty()) throw new SkipException("zap.install.dir not set - recorder+ZAP test skipped");
        zapDir = Path.of(dir);
        String home = prop("zap.home.dir");
        zapHome = home.isEmpty() ? Path.of("target", "zap-home") : Path.of(home);

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", ex -> {
            hits.computeIfAbsent(ex.getRequestURI().getPath(), k -> new AtomicInteger()).incrementAndGet();
            if (ex.getRequestURI().getPath().equals("/api/data")) {
                ex.getResponseHeaders().add("X-Powered-By", "Express");
                send(ex, 200, "application/json", "{\"customer\":\"test\",\"token\":\"" + FAKE_TOKEN + "\"}");
            } else {
                // No CSP / X-Frame-Options / X-Content-Type-Options, cookie without flags: passive leads.
                ex.getResponseHeaders().add("Set-Cookie", "SESSIONID=" + FAKE_COOKIE + "; Path=/");
                send(ex, 200, "text/html", PAGE);
            }
        });
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    public void recorderWithZapGivesPassiveLeadsAndAddsNoTraffic() throws Exception {
        RecorderConfig cfg = new RecorderConfig();
        cfg.project = "LOCAL-FAKE";
        cfg.role = "Maker";
        cfg.startUrl = "http://127.0.0.1:" + port + "/";
        cfg.outDir = Path.of("target", "recorder-zap-it");
        cfg.headless = true;
        cfg.zapInstallDir = zapDir;
        cfg.zapHomeDir = zapHome;
        cfg.resolve();

        Recorder.Summary s;
        try (Recorder rec = Recorder.start(cfg)) {
            rec.page().navigate(cfg.startUrl);
            rec.page().waitForFunction("document.title === 'done'");
            assertTrue(rec.page().getAttribute("body", "data-reply").contains("customer"), "app still works through ZAP");
            rec.waitAndStep(500);
            s = rec.stop();
        }
        System.out.println("SERVER HITS: " + hits);
        System.out.println("ZAP: " + s.zap + " -> " + s.zap.html);

        // Exactly the page's own requests: "/" once and "/api/data" once. ZAP added nothing.
        assertEquals(hits.keySet(), java.util.Set.of("/", "/api/data"), "unexpected paths: " + hits);
        assertEquals(hits.get("/").get(), 1);
        assertEquals(hits.get("/api/data").get(), 1);

        assertEquals(s.captured, 1, "recorder still captures the API call");
        assertNotNull(s.zap, "ZAP passive analysis ran");
        assertTrue(s.zap.messagesRecorded >= 2, "traffic went through ZAP: " + s.zap.messagesRecorded);
        assertTrue(s.zap.leads > 0, "missing headers / cookie flags raise passive leads");

        for (Path f : List.of(s.zap.html, s.zap.csv, s.zap.json, s.captureFile, s.reportHtml)) {
            String content = Files.readString(f);
            for (String secret : List.of(FAKE_COOKIE, FAKE_TOKEN)) {
                assertFalse(content.contains(secret), secret + " leaked into " + f.getFileName());
            }
        }
        String html = Files.readString(s.zap.html);
        assertTrue(html.contains("To verify"));
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
