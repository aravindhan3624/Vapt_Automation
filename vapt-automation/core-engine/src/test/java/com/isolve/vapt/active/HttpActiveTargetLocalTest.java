package com.isolve.vapt.active;

import com.sun.net.httpserver.HttpServer;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.testng.Assert.*;

/**
 * End-to-end on loopback: capture file -> loader -> gate -> real HTTP sender -> checks -> report.
 * The fake server serves a document with no auth (the weakness) and protects an API endpoint. It
 * records every path it receives, proving the engine fetched only the two safe reads - never the
 * approve / update endpoints present in the capture - and sent the session cookie only for baseline.
 */
public class HttpActiveTargetLocalTest {

    private static final String REF = "ISOLVE-VAPT-CKYC-2026-001";
    private static final String SESSION = "ckyc_session=FAKE-SESSION-xyz";

    private HttpServer server;
    private int port;
    private final Set<String> pathsHit = ConcurrentHashMap.newKeySet();
    private final Set<String> cookielessHits = ConcurrentHashMap.newKeySet();

    @BeforeClass
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            pathsHit.add(ex.getRequestMethod() + " " + path);
            boolean hasSession = SESSION.equals(ex.getRequestHeaders().getFirst("Cookie"));
            if (!hasSession) cookielessHits.add(path);
            if (path.startsWith("/CKYC_IMAGE/")) {
                send(ex, 200, "JPEGDATA");                       // document served with NO auth check
            } else if (path.endsWith("/getCustomerDetailsV2")) {
                send(ex, hasSession ? 200 : 401, hasSession ? "{\"ok\":true}" : "");
            } else {
                send(ex, 404, "");
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
    public void documentUnauthConfirmedLiveWithoutTouchingStateChanging() throws Exception {
        String base = "http://127.0.0.1:" + port;
        Path capture = Path.of("target", "active-http-it", "walk.capture.jsonl");
        Files.createDirectories(capture.getParent());
        Files.write(capture, List.of(
                row("GET", base, "/CKYC_IMAGE/123/IN31100011/IN31100011_02_Photo.jpg", null),
                row("POST", base, "/ckyc-api-gateway/ckycBackend/dvs-V2/getCustomerDetailsV2", "{\"ckycNo\":\"1001\"}"),
                row("POST", base, "/ckyc-api-gateway/ckycBackend/dvs-V2/approveRejectCustomerV2", "{\"ckycNo\":\"1001\"}"),
                row("POST", base, "/ckyc-api-gateway/ckycBackend/dvs-V2/updateCustomerDetailsV2", "{\"ckycNo\":\"1001\"}")
        ), StandardCharsets.UTF_8);

        ActiveRunOptions o = new ActiveRunOptions();
        o.confirmedActiveTesting = true;
        o.approvalReference = REF;
        o.approvedHosts = List.of("127.0.0.1:" + port);
        o.enabledChecks = List.of(ActiveCheckType.UNAUTH_DOCUMENT_ACCESS, ActiveCheckType.UNAUTHENTICATED_ACCESS);
        o.delayBetweenRequestsMs = 0;

        com.isolve.vapt.config.ProjectConfig cfg = new com.isolve.vapt.config.ProjectConfig();
        cfg.setProjectName("CKYC-7.0");
        cfg.setEnvironment("DEV");
        cfg.setApiBaseUrl(base);
        com.isolve.vapt.config.AuthorizationScope scope = new com.isolve.vapt.config.AuthorizationScope();
        scope.setAuthorizedBy("Head of IS");
        scope.setApprovalReference(REF);
        cfg.setScope(scope);

        ActiveTestGate.Authorization auth = ActiveTestGate.authorize(cfg, o, REF);
        HttpActiveTarget target = new HttpActiveTarget("Cookie", SESSION, null, null);
        List<RecordedCall> recorded = CaptureCallLoader.load(capture);
        ActiveChecks checks = new ActiveChecks(auth, target, o).run(recorded);
        ActiveCheckReport rep = ActiveCheckReport.build("CKYC-7.0", auth, checks);

        // Only the two safe reads were ever requested - approve/update were never sent.
        assertFalse(pathsHit.stream().anyMatch(p -> p.contains("approveReject") || p.contains("updateCustomer")),
                "state-changing endpoints must never be hit: " + pathsHit);
        assertTrue(pathsHit.stream().anyMatch(p -> p.contains("/CKYC_IMAGE/")), "document was fetched");

        boolean docConfirmed = rep.findings.stream().anyMatch(f ->
                f.type == ActiveCheckType.UNAUTH_DOCUMENT_ACCESS && f.status.equals(ActiveChecks.CONFIRMED));
        boolean apiSecure = rep.findings.stream().anyMatch(f ->
                f.endpoint.endsWith("/getCustomerDetailsV2") && f.status.equals(ActiveChecks.SECURE));
        assertTrue(docConfirmed, "unauth document access confirmed");
        assertTrue(apiSecure, "customer details correctly denied without the session");

        // The no-auth re-send reached the document WITHOUT a cookie (the baseline sent one; this did not).
        assertTrue(cookielessHits.contains("/CKYC_IMAGE/123/IN31100011/IN31100011_02_Photo.jpg"),
                "the no-auth document check must reach the server with no cookie");

        Path dir = Path.of("target", "active-http-it");
        String all = Files.readString(rep.writeHtml(dir, "r")) + Files.readString(rep.writeCsv(dir, "r"));
        assertFalse(all.contains("FAKE-SESSION-xyz"), "session value never written to the report");
    }

    private static String row(String method, String base, String path, String body) {
        String b = body == null ? "null" : "\"" + body.replace("\"", "\\\"") + "\"";
        String host = base.replaceFirst("^https?://", "");
        return "{\"method\":\"" + method + "\",\"scheme\":\"http\",\"host\":\"" + host + "\",\"path\":\"" + path
                + "\",\"requestBody\":" + b + ",\"requestDecrypted\":" + (body != null) + "}";
    }

    private static void send(com.sun.net.httpserver.HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            ex.sendResponseHeaders(code, -1);
        } else {
            ex.sendResponseHeaders(code, bytes.length);
            ex.getResponseBody().write(bytes);
        }
        ex.close();
    }
}
