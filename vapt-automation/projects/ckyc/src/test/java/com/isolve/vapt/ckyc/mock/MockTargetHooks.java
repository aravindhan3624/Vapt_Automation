package com.isolve.vapt.ckyc.mock;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.cucumber.java.AfterAll;
import io.cucumber.java.BeforeAll;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FAKE target for proving the pipeline end to end without touching any real system.
 * Starts only when -Dvapt.mock.port is set, binds to the loopback address only, and is
 * used together with config/ckyc-mock-config.yaml (apiBaseUrl = http://localhost:port).
 *
 * It is deliberately vulnerable in two places so the run exercises the FAIL path too:
 *   - GET /customer/MOCK-FOREIGN-002 returns another user's record (IDOR, VAPT-049)
 *   - any customer id containing a quote returns a DB error string (SQLi signal, VAPT-046)
 * Everything else behaves securely (headers, token checks, HTML-encoding).
 */
public final class MockTargetHooks {

    private static final String FOREIGN_ID = "MOCK-FOREIGN-002";
    private static final Set<String> ISSUED_TOKENS = ConcurrentHashMap.newKeySet();
    private static HttpServer server;

    @BeforeAll
    public static void startMockTarget() throws IOException {
        String port = System.getProperty("vapt.mock.port");
        if (port == null || port.isBlank()) return;
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), Integer.parseInt(port)), 0);
        server.createContext("/auth/login", MockTargetHooks::login);
        server.createContext("/customer", MockTargetHooks::customer);
        server.start();
    }

    @AfterAll
    public static void stopMockTarget() {
        if (server != null) server.stop(0);
    }

    private static void login(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (!"POST".equals(ex.getRequestMethod()) || !body.contains("\"username\"") || !body.contains("\"password\"")) {
            send(ex, 400, "{\"error\":\"bad request\"}");
            return;
        }
        String token = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64("{\"sub\":\"mock-maker\",\"exp\":4102444800}")
                + "." + b64("mock-signature-" + System.nanoTime());
        ISSUED_TOKENS.add(token);
        send(ex, 200, "{\"data\":{\"accessToken\":\"" + token + "\"}}");
    }

    private static void customer(HttpExchange ex) throws IOException {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth == null || !auth.startsWith("Bearer ") || !ISSUED_TOKENS.contains(auth.substring(7))) {
            send(ex, 401, "{\"error\":\"unauthorized\"}");
            return;
        }
        if ("POST".equals(ex.getRequestMethod())) {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            send(ex, 201, "{\"saved\":\"" + htmlEncode(body) + "\"}");
            return;
        }
        String rawPath = ex.getRequestURI().getRawPath();
        String id = URLDecoder.decode(rawPath.substring(rawPath.lastIndexOf('/') + 1), StandardCharsets.UTF_8);
        if (id.contains("'")) {
            send(ex, 500, "{\"error\":\"java.sql.SQLException: ORA-01756: quoted string not properly terminated\"}");
        } else if (FOREIGN_ID.equals(id)) {
            send(ex, 200, "{\"id\":\"" + FOREIGN_ID + "\",\"owner\":\"other-test-user\",\"name\":\"Mock Customer\"}");
        } else if (id.startsWith("MOCK-OWN-")) {
            send(ex, 200, "{\"id\":\"" + id + "\",\"owner\":\"mock-maker\"}");
        } else {
            send(ex, 404, "{\"error\":\"not found\"}");
        }
    }

    private static void send(HttpExchange ex, int status, String json) throws IOException {
        var h = ex.getResponseHeaders();
        h.add("Content-Type", "application/json");
        h.add("Content-Security-Policy", "default-src 'self'");
        h.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        h.add("X-Content-Type-Options", "nosniff");
        h.add("X-Frame-Options", "DENY");
        h.add("Referrer-Policy", "no-referrer");
        h.add("Pragma", "no-cache");
        h.add("Cache-Control", "no-store");
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String htmlEncode(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
