package com.isolve.vapt.recorder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.testng.Assert.*;

/**
 * End-to-end recorder test against a LOCAL fake app (loopback only). The page encrypts its API
 * body with real WebCrypto AES-GCM and decrypts the encrypted reply, like CKYC 7.0. Edge runs
 * headless with a fresh profile; nothing leaves this PC.
 */
public class RecorderLocalIT {

    private static final ObjectMapper M = new ObjectMapper();
    private static final String FAKE_PASSWORD = "FAKE-PASS-111";
    private static final String FAKE_TOKEN = "FAKE-TOKEN-222";
    private static final String FAKE_PLAIN_PW = "FAKE-PW-333";

    private HttpServer server;
    private int port;
    private Path outDir;

    private static final String PAGE = """
            <!doctype html><html><head><title>loading</title><link rel="stylesheet" href="/app.css"></head>
            <body><h1>Fake encrypted app (local test)</h1><script>
            const b64 = u8 => btoa(String.fromCharCode(...u8));
            const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
            (async () => {
              await fetch('/api/plain');
              try { await fetch('http://localhost:' + location.port + '/api/plain', {mode:'no-cors'}); } catch (e) {}
              const key = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
              const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
              const iv = crypto.getRandomValues(new Uint8Array(12));
              const body = JSON.stringify({search:'abc', userId:'546', password:'%s'});
              const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(body)));
              const packed = new Uint8Array(iv.length + ct.length); packed.set(iv); packed.set(ct, iv.length);
              const r = await fetch('/api/search', {method:'POST', headers:{'Content-Type':'application/json','x-test-key':b64(raw)},
                                                    body: JSON.stringify({payload: b64(packed)})});
              const env = await r.json();
              const p = unb64(env.responseObject);
              const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv:p.slice(0,12)}, key, p.slice(12));
              document.body.setAttribute('data-reply', new TextDecoder().decode(plain));
              document.title = 'done';
            })();
            </script></body></html>
            """.formatted(FAKE_PASSWORD);

    @BeforeClass
    public void setUp() throws IOException {
        boolean edge = new File("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe").isFile()
                || new File("C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe").isFile();
        if (!edge) throw new SkipException("Microsoft Edge not installed - recorder IT skipped");

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", ex -> send(ex, 200, "text/html", PAGE));
        server.createContext("/app.css", ex -> send(ex, 200, "text/css", "body{font-family:Arial}"));
        server.createContext("/api/plain", ex -> send(ex, 200, "application/json",
                "{\"name\":\"test-user\",\"password\":\"" + FAKE_PLAIN_PW + "\"}"));
        server.createContext("/api/search", this::encryptedEcho);
        server.start();
        port = server.getAddress().getPort();
        outDir = Path.of("target", "recorder-it");
        Files.createDirectories(outDir);
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    public void capturesDecryptsAndRedacts() throws Exception {
        RecorderConfig cfg = new RecorderConfig();
        cfg.project = "LOCAL-FAKE";
        cfg.role = "Maker";
        cfg.startUrl = "http://127.0.0.1:" + port + "/";
        cfg.outDir = outDir;
        cfg.headless = true;
        cfg.resolve();
        assertEquals(cfg.approvedHosts, List.of("127.0.0.1:" + port));

        Recorder.Summary s;
        try (Recorder rec = Recorder.start(cfg)) {
            rec.page().navigate(cfg.startUrl);
            rec.page().waitForFunction("document.title === 'done'");
            String reply = rec.page().getAttribute("body", "data-reply");
            assertTrue(reply.contains("\"result\":\"ok\""), "page itself must still work: " + reply);
            rec.waitAndStep(500);
            s = rec.stop();
        }

        List<JsonNode> recs = new ArrayList<>();
        for (String line : Files.readAllLines(s.captureFile)) recs.add(M.readTree(line));
        List<String> paths = recs.stream().map(r -> r.path("method").asText() + " " + r.path("path").asText()).toList();
        System.out.println("CAPTURED: " + paths);

        assertEquals(recs.size(), 2, "only the 2 in-scope API calls: " + paths);
        assertFalse(paths.stream().anyMatch(p -> p.contains("app.css")), "static files are not captured");

        JsonNode search = recs.stream().filter(r -> r.path("path").asText().equals("/api/search")).findFirst().orElseThrow();
        assertTrue(search.path("requestDecrypted").asBoolean(), "request body read as plain text");
        assertTrue(search.path("responseDecrypted").asBoolean(), "response body read as plain text");
        JsonNode req = M.readTree(search.path("requestBody").asText());
        assertEquals(req.path("search").asText(), "abc");
        assertEquals(req.path("password").asText(), JsonRedactor.REDACTED);
        JsonNode resp = M.readTree(search.path("responseBody").asText());
        assertEquals(resp.path("result").asText(), "ok");
        assertEquals(resp.path("token").asText(), JsonRedactor.REDACTED);
        assertFalse(search.path("requestHeaderNames").toString().contains("FAKE"), "header values never stored");

        JsonNode plain = recs.stream().filter(r -> r.path("path").asText().equals("/api/plain")).findFirst().orElseThrow();
        assertFalse(plain.path("requestDecrypted").asBoolean());
        assertEquals(M.readTree(plain.path("responseBody").asText()).path("password").asText(), JsonRedactor.REDACTED);

        assertEquals(s.decryptedRequests, 1);
        assertEquals(s.decryptedResponses, 1);
        assertEquals(s.uniqueEndpoints, 2);
        String csv = Files.readString(s.inventoryCsv);
        assertTrue(csv.contains("search;userId") || csv.contains("password;search;userId"),
                "inventory shows the real (decrypted) body field names: " + csv);

        // Leak check over every file the recorder wrote.
        for (Path f : List.of(s.captureFile, s.inventoryJson, s.inventoryCsv, s.reportHtml)) {
            String content = Files.readString(f);
            for (String secret : List.of(FAKE_PASSWORD, FAKE_TOKEN, FAKE_PLAIN_PW)) {
                assertFalse(content.contains(secret), secret + " leaked into " + f.getFileName());
            }
        }
    }

    // ---------------- fake server ----------------
    private void encryptedEcho(HttpExchange ex) throws IOException {
        try {
            byte[] key = Base64.getDecoder().decode(ex.getRequestHeaders().getFirst("x-test-key"));
            JsonNode n = M.readTree(ex.getRequestBody().readAllBytes());
            byte[] packed = Base64.getDecoder().decode(n.path("payload").asText());
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, packed, 0, 12));
            String plainReq = new String(gcm.doFinal(packed, 12, packed.length - 12), StandardCharsets.UTF_8);
            String search = M.readTree(plainReq).path("search").asText();

            String reply = "{\"result\":\"ok\",\"echo\":\"" + search + "\",\"token\":\"" + FAKE_TOKEN + "\"}";
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            byte[] ct = enc.doFinal(reply.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[12 + ct.length];
            System.arraycopy(iv, 0, out, 0, 12);
            System.arraycopy(ct, 0, out, 12, ct.length);
            send(ex, 200, "application/json",
                    "{\"statusCode\":200,\"responseObject\":\"" + Base64.getEncoder().encodeToString(out) + "\"}");
        } catch (Exception e) {
            send(ex, 400, "application/json", "{\"statusCode\":400}");
        }
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
