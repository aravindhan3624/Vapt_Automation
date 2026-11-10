package com.isolve.vapt.recorder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isolve.vapt.discovery.CapturedCall;
import com.isolve.vapt.discovery.DiscoveryReport;
import com.isolve.vapt.discovery.Endpoint;
import com.isolve.vapt.discovery.EndpointInventory;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.options.HttpHeader;
import com.microsoft.playwright.options.Proxy;
import com.microsoft.playwright.options.SecurityDetails;
import com.isolve.vapt.passive.PassiveCheckReport;
import com.isolve.vapt.passive.PassiveChecks;
import com.isolve.vapt.passive.PassiveObservation;
import com.isolve.vapt.zap.ZapDaemon;
import com.isolve.vapt.zap.ZapPassiveAnalysis;
import com.isolve.vapt.zap.ZapPassiveSession;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Passive recorder: opens the installed Microsoft Edge with a fresh, empty profile, lets the
 * tester log in and use the application, and captures API calls (XHR / fetch) to approved hosts.
 *
 * - The recorder sends no requests of its own and never fills in or reads login forms.
 * - Header values are never stored (names only). Bodies are redacted before being written.
 * - For apps that encrypt bodies with WebCrypto AES-GCM (CKYC 7.0), an in-page hook reports the
 *   plain text, matched exactly to the wire value, so the capture holds readable (redacted) JSON.
 *
 * All Playwright calls happen on the thread that created the recorder.
 */
public final class Recorder implements AutoCloseable {

    private static final ObjectMapper M = new ObjectMapper();
    private static final Set<String> API_TYPES = Set.of("xhr", "fetch");
    private static final long CORRELATION_WAIT_MS = 5_000;

    /** Raw data waiting for correlation + redaction. In memory only, never written. */
    private static final class Pending {
        final long createdAt = System.currentTimeMillis();
        CaptureRecord rec;
        String rawRequestBody;
        String rawResponseBody;
        String requestBlob;
        String responseBlob;
        // For Phase 5 passive checks (memory only, dropped after the check runs).
        String url;
        String resourceType;
        String rawQuery;
        List<String[]> responseHeaders;
        String tlsProtocol;
        Long certValidTo;
    }

    public static final class Summary {
        public int captured;
        public int decryptedRequests;
        public int decryptedResponses;
        public int uniqueEndpoints;
        public Path captureFile;
        public Path reportHtml;
        public Path inventoryJson;
        public Path inventoryCsv;
        /** Phase 4 ZAP passive analysis, when the recorder ran with ZAP. */
        public ZapPassiveAnalysis.Result zap;
        /** Phase 5 passive checks (always on; reads the same traffic, sends nothing). */
        public int passiveLeads;
        public Path passiveHtml;
        public Path passiveCsv;
    }

    private final RecorderConfig cfg;
    private final Playwright playwright;
    private final Browser browser;
    private final BrowserContext context;
    private final Page firstPage;
    private final Map<String, String> encrypted = new ConcurrentHashMap<>();  // wire blob -> plain request
    private final Map<String, String> decrypted = new ConcurrentHashMap<>();  // wire blob -> plain response
    private final Deque<Response> responses = new ArrayDeque<>();
    private final List<Pending> pending = new ArrayList<>();
    private final List<CaptureRecord> finalized = new ArrayList<>();
    private final BufferedWriter out;
    private final Path captureFile;
    private final String baseName;
    private volatile String currentModule = "";
    private volatile boolean disconnected;
    private int decReq;
    private int decResp;
    private boolean stopped;
    private ZapDaemon zap;
    private final PassiveChecks passive = new PassiveChecks();
    private ZapPassiveSession zapSession;

    private Recorder(RecorderConfig cfg) throws IOException {
        this.cfg = cfg.resolve();
        Files.createDirectories(cfg.outDir);
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        this.baseName = safe(cfg.project) + "-" + safe(cfg.role) + "-" + stamp;
        this.captureFile = cfg.outDir.resolve(baseName + ".capture.jsonl");
        this.out = Files.newBufferedWriter(captureFile, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);

        if (cfg.zapInstallDir != null) {
            // Phase 4: local ZAP watches the tester's traffic (passive only), scoped to approved hosts.
            try {
                this.zap = ZapDaemon.start(cfg.zapInstallDir, cfg.zapHomeDir, 0, ZapPassiveAnalysis.START_TIMEOUT);
                this.zapSession = new ZapPassiveSession(zap, safe(cfg.project) + "-passive", cfg.approvedHosts);
            } catch (Exception e) {
                if (zap != null) zap.close();
                out.close();
                throw new IOException("Could not start ZAP for passive analysis: " + e.getMessage(), e);
            }
        }

        // Use the installed Edge; do not let Playwright download its own browsers.
        this.playwright = Playwright.create(new Playwright.CreateOptions()
                .setEnv(Map.of("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")));
        this.browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
                .setChannel("msedge")
                .setHeadless(cfg.headless));
        browser.onDisconnected(b -> disconnected = true);

        Browser.NewContextOptions opts = new Browser.NewContextOptions();   // fresh profile, nothing from the user's Edge
        if (!cfg.headless) opts.setViewportSize(null);
        if (zap != null) {
            // ZAP re-signs TLS with its own CA, which this fresh profile does not trust.
            // "<-loopback>" also sends localhost traffic through ZAP (local tests).
            opts.setProxy(new Proxy("http://127.0.0.1:" + zap.port()).setBypass("<-loopback>")).setIgnoreHTTPSErrors(true);
        } else if (!cfg.proxy.isBlank()) {
            // Burp / ZAP re-sign TLS with their own CA, which this fresh profile does not trust.
            opts.setProxy("http://" + cfg.proxy).setIgnoreHTTPSErrors(true);
        }
        this.context = browser.newContext(opts);

        context.exposeBinding("__vaptCrypto", (source, args) -> {
            onCryptoEvent(args.length > 0 ? String.valueOf(args[0]) : "");
            return null;
        });
        context.exposeBinding("__vaptModule", (source, args) -> {
            currentModule = args.length > 0 && args[0] != null ? String.valueOf(args[0]).trim() : "";
            return null;
        });
        context.addInitScript("window.__vaptOverlay = " + cfg.overlay + ";");
        context.addInitScript(resource("/recorder/crypto-hook.js"));
        context.onResponse(responses::add);
        this.firstPage = context.newPage();
    }

    public static Recorder start(RecorderConfig cfg) throws IOException {
        return new Recorder(cfg);
    }

    /** The first tab (navigate here, or let the tester do it). */
    public Page page() {
        return firstPage;
    }

    /** True while the browser is connected and at least one tab is open. */
    public boolean isOpen() {
        if (disconnected) return false;
        try {
            return !context.pages().isEmpty();
        } catch (PlaywrightException e) {
            return false;
        }
    }

    /** Lets Playwright deliver events for a while, then processes what arrived. */
    public void waitAndStep(int millis) {
        try {
            List<Page> pages = context.pages();
            if (!pages.isEmpty()) pages.get(pages.size() - 1).waitForTimeout(millis);
        } catch (PlaywrightException ignore) { /* tab closed by the tester */ }
        processResponses();
        finalizeOlderThan(CORRELATION_WAIT_MS);
    }

    /** Ends the session: processes everything left, writes the capture file and the report. */
    public Summary stop() throws IOException {
        if (stopped) throw new IllegalStateException("Recorder already stopped");
        stopped = true;
        processResponses();
        finalizeOlderThan(0);
        out.close();
        closeBrowser();

        List<CapturedCall> calls = new ArrayList<>();
        for (CaptureRecord r : finalized) calls.add(toCapturedCall(r));
        List<Endpoint> endpoints = EndpointInventory.build(calls);
        DiscoveryReport report = new DiscoveryReport(
                cfg.project + " / " + cfg.role, List.of(captureFile.getFileName().toString()), calls.size(), endpoints);

        Summary s = new Summary();
        s.captured = finalized.size();
        s.decryptedRequests = decReq;
        s.decryptedResponses = decResp;
        s.uniqueEndpoints = endpoints.size();
        s.captureFile = captureFile;
        s.inventoryJson = report.writeJson(cfg.outDir.toFile(), baseName + "-endpoints").toPath();
        s.inventoryCsv = report.writeCsv(cfg.outDir.toFile(), baseName + "-endpoints").toPath();
        s.reportHtml = report.writeHtml(cfg.outDir.toFile(), baseName + "-endpoint-discovery").toPath();

        PassiveCheckReport pr = PassiveCheckReport.build(cfg.project,
                "Recorder session " + cfg.role + " (" + captureFile.getFileName() + ")", cfg.approvedHosts, passive);
        if (decResp > 0) pr.addNote("This application encrypts API bodies; data and error checks ran on the decrypted "
                + "(plain) bodies read inside the browser.");
        s.passiveLeads = pr.leads();
        s.passiveHtml = pr.writeHtml(cfg.outDir, baseName + "-passive-checks");
        s.passiveCsv = pr.writeCsv(cfg.outDir, baseName + "-passive-checks");
        pr.writeJson(cfg.outDir, baseName + "-passive-checks");
        if (zapSession != null) {
            try {
                List<String> notes = new ArrayList<>();
                notes.add("Live: the tester's own browser session (" + cfg.role + ") was routed through a local ZAP proxy; "
                        + "ZAP only watched it.");
                if (decReq + decResp > 0) {
                    notes.add("This application encrypts API bodies, so ZAP saw ciphertext bodies: header, cookie, status "
                            + "and error checks are valid; body-content rules cannot see the plain fields.");
                }
                s.zap = ZapPassiveAnalysis.finish(zapSession, cfg.project,
                        "Recorder session " + cfg.role + " (" + captureFile.getFileName() + ")", cfg.outDir, baseName, notes);
            } catch (Exception e) {
                throw new IOException("ZAP passive analysis failed: " + e.getMessage(), e);
            } finally {
                closeZap();
            }
        }
        return s;
    }

    @Override
    public void close() {
        if (!stopped) {
            try { stop(); } catch (Exception ignore) { /* best effort */ }
        }
        closeBrowser();
        closeZap();
    }

    private void closeZap() {
        if (zap != null) {
            zap.close();   // also deletes the ZAP session that held raw traffic
            zap = null;
            zapSession = null;
        }
    }

    // ---------------- capture ----------------
    private void onCryptoEvent(String json) {
        try {
            JsonNode n = M.readTree(json);
            String blob = n.path("blob").asText("");
            String plain = n.path("plain").asText("");
            if (blob.isEmpty()) return;
            if ("enc".equals(n.path("kind").asText())) encrypted.put(blob, plain);
            else if ("dec".equals(n.path("kind").asText())) decrypted.put(blob, plain);
        } catch (Exception ignore) { /* malformed event: ignore */ }
    }

    private void processResponses() {
        Response resp;
        while ((resp = responses.poll()) != null) {
            try {
                capture(resp);
            } catch (PlaywrightException ignore) { /* page went away mid-read */ }
        }
    }

    private void capture(Response resp) {
        Request req = resp.request();
        URI uri;
        try { uri = URI.create(req.url()); } catch (Exception e) { return; }
        mixedContent(req);
        if (!cfg.inScope(uri)) return;
        if ("document".equals(req.resourceType())) {
            observeDocument(req, resp, uri);
            return;
        }
        if (!API_TYPES.contains(req.resourceType())) return;

        CaptureRecord r = new CaptureRecord();
        r.capturedAt = LocalDateTime.now().toString();
        r.project = cfg.project;
        r.role = cfg.role;
        r.module = currentModule;
        r.method = req.method();
        r.scheme = uri.getScheme();
        r.host = uri.getPort() > 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
        r.path = uri.getRawPath() == null ? "/" : uri.getRawPath();
        r.queryParamNames = queryNames(uri.getRawQuery());
        r.requestHeaderNames = new ArrayList<>(new LinkedHashSet<>(req.headers().keySet()));
        r.requestContentType = header(req.headers(), "content-type");
        r.status = resp.status();
        r.responseContentType = header(resp.headers(), "content-type");

        Pending p = new Pending();
        p.rec = r;
        p.rawRequestBody = req.postData();
        p.requestBlob = envelopeBlob(p.rawRequestBody, "payload");
        if (isTextual(r.responseContentType)) {
            try {
                byte[] body = resp.body();
                p.rawResponseBody = body == null ? null : new String(body, StandardCharsets.UTF_8);
            } catch (PlaywrightException noBody) { /* redirects etc. */ }
        }
        p.url = req.url();
        p.resourceType = req.resourceType();
        p.rawQuery = uri.getRawQuery();
        p.responseHeaders = headers(resp);
        tls(resp, p);
        p.responseBlob = envelopeBlob(p.rawResponseBody, "responseObject");
        if (p.responseBlob == null) p.responseBlob = envelopeBlob(p.rawResponseBody, "payload");
        pending.add(p);
    }

    /** Matches plain text from the hook, redacts, writes. Raw values are dropped afterwards. */
    private void finalizeOlderThan(long ageMs) {
        long now = System.currentTimeMillis();
        Iterator<Pending> it = pending.iterator();
        while (it.hasNext()) {
            Pending p = it.next();
            if (now - p.createdAt < ageMs) continue;
            CaptureRecord r = p.rec;
            String reqBody = p.rawRequestBody;
            if (p.requestBlob != null && encrypted.containsKey(p.requestBlob)) {
                reqBody = encrypted.remove(p.requestBlob);
                r.requestDecrypted = true;
                decReq++;
            }
            String respBody = p.rawResponseBody;
            if (p.responseBlob != null && decrypted.containsKey(p.responseBlob)) {
                respBody = decrypted.remove(p.responseBlob);
                r.responseDecrypted = true;
                decResp++;
            }
            passive.observe(observation(p, respBody, r.responseDecrypted));
            if (cfg.captureBodies) {
                r.requestBody = JsonRedactor.redact(reqBody, cfg.maxBodyChars);
                r.responseBody = JsonRedactor.redact(respBody, cfg.maxBodyChars);
            }
            try {
                out.write(M.writeValueAsString(r));
                out.newLine();
                out.flush();
            } catch (IOException e) {
                throw new IllegalStateException("Cannot write capture file " + captureFile, e);
            }
            finalized.add(r);
            it.remove();
        }
    }

    // ---------------- Phase 5 passive checks (in memory) ----------------
    private boolean viaProxy() {
        return zap != null || !cfg.proxy.isBlank();
    }

    private PassiveObservation observation(Pending p, String plainResponseBody, boolean decryptedBody) {
        PassiveObservation o = new PassiveObservation();
        o.method = p.rec.method;
        o.url = p.url;
        o.resourceType = p.resourceType == null ? "" : p.resourceType;
        o.status = p.rec.status;
        o.responseContentType = p.rec.responseContentType;
        if (p.responseHeaders != null) o.responseHeaders = p.responseHeaders;
        o.queryParamNames = p.rec.queryParamNames;
        o.rawQuery = p.rawQuery == null ? "" : p.rawQuery;
        o.responseBody = plainResponseBody;
        o.responseDecrypted = decryptedBody;
        o.tlsProtocol = p.tlsProtocol;
        o.certValidToEpochSec = p.certValidTo;
        o.viaProxy = viaProxy();
        return o;
    }

    private void observeDocument(Request req, Response resp, URI uri) {
        Pending p = new Pending();
        p.rec = new CaptureRecord();
        p.rec.method = req.method();
        p.rec.status = resp.status();
        p.rec.responseContentType = header(resp.headers(), "content-type");
        p.rec.queryParamNames = queryNames(uri.getRawQuery());
        p.url = req.url();
        p.resourceType = "document";
        p.rawQuery = uri.getRawQuery();
        p.responseHeaders = headers(resp);
        tls(resp, p);
        String body = null;
        if (isTextual(p.rec.responseContentType)) {
            try {
                byte[] b = resp.body();
                if (b != null) body = new String(b, 0, Math.min(b.length, 500_000), StandardCharsets.UTF_8);
            } catch (PlaywrightException noBody) { /* redirects etc. */ }
        }
        passive.observe(observation(p, body, false));
    }

    private void mixedContent(Request req) {
        try {
            String page = req.frame().url();
            URI pu = URI.create(page);
            if (cfg.inScope(pu)) passive.observeSubresource(page, req.url());
        } catch (Exception ignore) { /* service worker / detached frame */ }
    }

    private static List<String[]> headers(Response resp) {
        List<String[]> out = new ArrayList<>();
        try {
            for (HttpHeader h : resp.headersArray()) out.add(new String[]{h.name, h.value});
        } catch (PlaywrightException e) {
            resp.headers().forEach((k, v) -> out.add(new String[]{k, v}));
        }
        return out;
    }

    private static void tls(Response resp, Pending p) {
        try {
            SecurityDetails sd = resp.securityDetails();
            if (sd != null) {
                p.tlsProtocol = sd.protocol;
                p.certValidTo = sd.validTo == null ? null : sd.validTo.longValue();
            }
        } catch (PlaywrightException ignore) { /* not available */ }
    }

    // ---------------- helpers ----------------
    private static CapturedCall toCapturedCall(CaptureRecord r) {
        CapturedCall c = new CapturedCall();
        c.method = r.method;
        c.scheme = r.scheme;
        c.host = r.host;
        c.path = r.path;
        c.queryParamNames = r.queryParamNames;
        c.requestHeaderNames = r.requestHeaderNames;
        c.requestContentType = r.requestContentType;
        c.requestBodyParamNames = topLevelKeys(r.requestBody);
        c.status = r.status;
        c.responseContentType = r.responseContentType;
        return c;
    }

    private static List<String> topLevelKeys(String json) {
        List<String> keys = new ArrayList<>();
        if (json == null || json.isBlank()) return keys;
        try {
            JsonNode n = M.readTree(json);
            if (n != null && n.isObject()) n.fieldNames().forEachRemaining(keys::add);
        } catch (Exception ignore) { /* not JSON */ }
        return keys;
    }

    private static String envelopeBlob(String body, String field) {
        if (body == null || body.isBlank() || body.charAt(0) != '{') return null;
        try {
            JsonNode n = M.readTree(body);
            return n.path(field).isTextual() ? n.path(field).asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<String> queryNames(String rawQuery) {
        Set<String> names = new LinkedHashSet<>();
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&")) {
                int eq = pair.indexOf('=');
                String n = eq >= 0 ? pair.substring(0, eq) : pair;
                if (!n.isEmpty()) names.add(n);
            }
        }
        return new ArrayList<>(names);
    }

    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return "";
    }

    private static boolean isTextual(String contentType) {
        String ct = contentType == null ? "" : contentType.toLowerCase();
        return ct.contains("json") || ct.contains("text") || ct.contains("xml") || ct.isEmpty();
    }

    private static String resource(String path) {
        try (InputStream in = Recorder.class.getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("Missing resource " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String safe(String s) {
        return s == null ? "x" : s.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private void closeBrowser() {
        try { context.close(); } catch (Exception ignore) { }
        try { browser.close(); } catch (Exception ignore) { }
        try { playwright.close(); } catch (Exception ignore) { }
    }
}
