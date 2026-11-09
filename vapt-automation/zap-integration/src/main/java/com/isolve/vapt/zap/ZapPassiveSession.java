package com.isolve.vapt.zap;

import com.isolve.vapt.util.MaskUtil;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Passive-only use of a running ZAP daemon: a context limited to approved hosts, waiting for the
 * passive scanner, reading alerts and exporting ZAP's own report. Traffic reaches ZAP only when
 * the framework (or the tester's browser) routes its own requests through the ZAP proxy;
 * this class never sends requests to the target itself and has no active-scan method.
 */
public final class ZapPassiveSession {

    private final ZapDaemon zap;
    private final String contextName;
    private final List<String> approvedHosts;

    /**
     * @param approvedHosts host names (optionally host:port) that are in scope. Must not be empty;
     *                      everything else stays out of the ZAP context.
     */
    public ZapPassiveSession(ZapDaemon zap, String contextName, List<String> approvedHosts) throws Exception {
        if (approvedHosts == null || approvedHosts.isEmpty() || approvedHosts.stream().anyMatch(h -> h == null || h.isBlank())) {
            throw new IllegalArgumentException("At least one approved host is required for the ZAP context");
        }
        this.zap = zap;
        this.contextName = contextName;
        this.approvedHosts = List.copyOf(approvedHosts);
        zap.call("context", "action", "newContext", Map.of("contextName", contextName));
        for (String host : this.approvedHosts) {
            zap.call("context", "action", "includeInContext",
                    Map.of("contextName", contextName, "regex", scopeRegex(host)));
        }
        zap.call("context", "action", "setContextInScope", Map.of("contextName", contextName, "booleanInScope", "true"));
        // Passive rules look only at approved hosts; other traffic the browser makes is ignored.
        zap.call("pscan", "action", "setScanOnlyInScope", Map.of("onlyInScope", "true"));
    }

    /**
     * Imports a HAR file (browser DevTools / Burp export) into this ZAP session so the passive
     * scanner can read it. Importing sends NO requests: ZAP only reads the request/response pairs
     * already in the file. The file may hold live cookies/tokens; it is read locally and the ZAP
     * session that stores it is deleted when the daemon closes.
     */
    public void importHar(java.nio.file.Path harFile) throws Exception {
        java.nio.file.Path abs = harFile.toAbsolutePath().normalize();
        if (!java.nio.file.Files.isRegularFile(abs)) throw new IllegalArgumentException("HAR file not found: " + abs);
        zap.call("exim", "action", "importHar", Map.of("filePath", abs.toString()));
    }

    /** Total messages in the ZAP session (all hosts). */
    public int messageCount() throws Exception {
        return Integer.parseInt(ZapDaemon.value(zap.call("core", "view", "numberOfMessages", Map.of())));
    }

    /** All alerts for the approved hosts (redacted). */
    public List<ZapAlert> alerts() throws Exception {
        return alerts("");
    }

    /** Regex for one approved host: http(s), optional port, any path. */
    static String scopeRegex(String hostOrHostPort) {
        String h = hostOrHostPort.trim();
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        String port = h.contains(":") ? ":" + h.substring(h.indexOf(':') + 1) : "(:\\d+)?";
        return "https?://" + Pattern.quote(host) + port + "(/.*)?";
    }

    public List<String> approvedHosts() {
        return approvedHosts;
    }

    /** Waits until ZAP's passive scanner has processed everything it has recorded. */
    public void waitForPassiveScan(Duration timeout) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            int left = Integer.parseInt(ZapDaemon.value(zap.call("pscan", "view", "recordsToScan", Map.of())));
            if (left == 0) return;
            TimeUnit.MILLISECONDS.sleep(500);
        }
        throw new IllegalStateException("Passive scan still running after " + timeout.toSeconds() + "s");
    }

    /** Number of requests ZAP has recorded for a base URL (proves traffic went through the proxy). */
    public int messageCount(String baseUrl) throws Exception {
        return Integer.parseInt(ZapDaemon.value(zap.call("core", "view", "numberOfMessages", Map.of("baseurl", baseUrl))));
    }

    /** Alerts for a base URL, redacted. Only URLs inside the approved hosts are returned. */
    public List<ZapAlert> alerts(String baseUrl) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        if (baseUrl != null && !baseUrl.isBlank()) params.put("baseurl", baseUrl);
        params.put("start", "0");
        params.put("count", "100000");
        ApiResponse r = zap.call("alert", "view", "alerts", params);
        List<ZapAlert> out = new ArrayList<>();
        if (!(r instanceof ApiResponseList list)) return out;
        for (ApiResponse item : list.getItems()) {
            if (!(item instanceof ApiResponseSet set)) continue;
            ZapAlert a = new ZapAlert();
            a.pluginId = str(set, "pluginId");
            a.name = str(set, "alert");
            a.risk = str(set, "risk");
            a.confidence = str(set, "confidence");
            a.url = str(set, "url");
            a.param = str(set, "param");
            a.evidence = str(set, "evidence");
            a.cweId = str(set, "cweid");
            a.wascId = str(set, "wascid");
            a.solution = str(set, "solution");
            a.reference = str(set, "reference");
            a.method = str(set, "method");
            a.description = str(set, "description");
            if (inScope(a.url)) out.add(a);
        }
        return out;
    }

    /**
     * ZAP's own HTML report for everything in the session (redacted). It covers ALL hosts ZAP saw,
     * not only approved ones; prefer {@link PassiveAnalysisReport} for anything shared.
     */
    public String htmlReport() throws Exception {
        byte[] raw = zap.callOther("core", "htmlreport", Map.of());
        return MaskUtil.mask(new String(raw, java.nio.charset.StandardCharsets.UTF_8));
    }

    boolean inScope(String url) {
        for (String h : approvedHosts) if (url.matches(scopeRegex(h))) return true;
        return false;
    }

    private static String str(ApiResponseSet set, String key) {
        ApiResponse v = set.getValue(key);
        String s = v instanceof ApiResponseElement e ? e.getValue() : (v == null ? "" : v.toString());
        return MaskUtil.mask(s == null ? "" : s);
    }
}
