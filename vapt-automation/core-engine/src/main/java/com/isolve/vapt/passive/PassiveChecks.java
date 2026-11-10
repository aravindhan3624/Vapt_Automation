package com.isolve.vapt.passive;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isolve.vapt.discovery.EndpointInventory;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase 5 passive checks over traffic the tester's own session already produced. Sends nothing.
 *
 * Each observation is inspected in memory; only check results are kept: counts, header / cookie /
 * field NAMES, reason labels and normalized endpoints. Raw header values, bodies, cookie values and
 * personal data are never stored. Every hit is a lead with status "To verify".
 *
 * Feed with {@link #observe(PassiveObservation)} (in-scope traffic) and
 * {@link #observeSubresource(String, String)} (for mixed content), then call {@link #results()}.
 */
public final class PassiveChecks {

    public static final String LEAD = "Lead - to verify";
    public static final String OK = "No issue observed";
    public static final String NONE = "Not observed (no applicable traffic)";
    public static final String NOT_CHECKED = "Not checked";

    private static final ObjectMapper M = new ObjectMapper();
    private static final int MAX_ENDPOINTS = 15;
    private static final int MAX_NAMES = 40;
    private static final long HSTS_MIN_SECONDS = 15_552_000L;   // 180 days
    private static final long CERT_WARN_DAYS = 30;

    /** One check's accumulated result. */
    public static final class Result {
        public String id;
        public String title;
        public List<String> checklistIds = new ArrayList<>();
        public String status = NONE;
        public int applicable;
        public int hits;
        public Map<String, Integer> reasons = new LinkedHashMap<>();
        public List<String> names = new ArrayList<>();
        public List<String> endpoints = new ArrayList<>();
        public List<String> passEvidence = new ArrayList<>();
        public String howToVerify;
        public String note;

        Result(String id, String title, String howToVerify, String... checklist) {
            this.id = id;
            this.title = title;
            this.howToVerify = howToVerify;
            this.checklistIds.addAll(List.of(checklist));
        }
    }

    private final Map<String, Result> checks = new LinkedHashMap<>();
    private final Set<String> seenCookies = new LinkedHashSet<>();
    private final Set<String> seenCertHosts = new LinkedHashSet<>();
    private boolean anyTlsDetails;
    private boolean anyViaProxy;
    private boolean anyDecrypted;
    private int observations;

    public PassiveChecks() {
        add("P5-H01", "Content-Security-Policy missing or weak on pages",
                "Open the page response; confirm CSP header is absent or allows 'unsafe-inline'/'unsafe-eval'/wildcard sources.", "VAPT-010");
        add("P5-H02", "Clickjacking protection missing (X-Frame-Options / CSP frame-ancestors)",
                "Confirm the page response has neither X-Frame-Options DENY/SAMEORIGIN nor CSP frame-ancestors; try framing it in a local test page.", "VAPT-025");
        add("P5-H03", "Strict-Transport-Security missing or short",
                "Confirm HTTPS responses lack HSTS or max-age < 180 days.", "VAPT-001");
        add("P5-H04", "X-Content-Type-Options: nosniff missing",
                "Confirm the response lacks X-Content-Type-Options: nosniff.", "VAPT-023");
        add("P5-H05", "Server / framework version disclosed in headers",
                "Confirm Server / X-Powered-By / X-AspNet-Version reveal product and version.", "VAPT-008");
        add("P5-H06", "API responses cacheable (no Cache-Control: no-store)",
                "Confirm API responses carrying user data lack Cache-Control: no-store (and Pragma: no-cache).", "VAPT-063", "VAPT-012");
        add("P5-H07", "CORS allows any origin",
                "Confirm Access-Control-Allow-Origin: * (worse with Allow-Credentials: true) on API responses.", "VAPT-023");
        add("P5-C01", "Cookie flags missing (Secure / HttpOnly / SameSite)",
                "Inspect Set-Cookie for the named cookies; confirm the missing attributes.", "VAPT-014");
        add("P5-D01", "Personal data returned unmasked (PAN, Aadhaar, card, mobile, email)",
                "Open the named response fields; confirm full values are returned where the screen needs only masked ones.", "VAPT-043", "VAPT-052");
        add("P5-D02", "Secrets returned in responses (password, PIN, OTP, CVV, secret keys)",
                "Open the named response fields; confirm a real secret value is returned to the browser.", "VAPT-052", "VAPT-017");
        add("P5-D03", "Sensitive data in URL query string",
                "Confirm the named query parameters carry credentials or personal data (they end up in logs and history).", "VAPT-017", "VAPT-002");
        add("P5-E01", "Error details leaked (stack traces, exception classes, SQL errors, internal paths/IPs)",
                "Reproduce the call and capture the response showing the internal detail.", "VAPT-041", "VAPT-042");
        add("P5-E02", "Server errors (HTTP 5xx) during normal use",
                "Re-run the step; check the 5xx response for leaked detail and whether input caused it.", "VAPT-041");
        add("P5-T01", "Plain HTTP (no TLS) to the application",
                "Confirm the request URL is http:// and carries application data.", "VAPT-001", "VAPT-039");
        add("P5-T02", "Old TLS protocol (below TLS 1.2)",
                "Confirm with the browser security panel or a TLS scanner (approved) that TLS 1.0/1.1 is used.", "VAPT-001", "VAPT-023");
        add("P5-T03", "TLS certificate expired or expiring within 30 days",
                "Check the certificate validity dates in the browser.", "VAPT-023");
        add("P5-T04", "Mixed content (HTTPS page loads HTTP resources)",
                "Confirm the HTTPS page requested the http:// resource.", "VAPT-001");
    }

    private void add(String id, String title, String how, String... checklist) {
        checks.put(id, new Result(id, title, how, checklist));
    }

    // ---------------- feeding ----------------

    /** Inspects one in-scope request/response. Values are not retained. */
    public synchronized void observe(PassiveObservation o) {
        URI u;
        try {
            u = URI.create(o.url);
        } catch (Exception e) {
            return;
        }
        if (u.getHost() == null) return;
        observations++;
        if (o.viaProxy) anyViaProxy = true;
        if (o.responseDecrypted) anyDecrypted = true;
        String ep = o.method.toUpperCase(Locale.ROOT) + " " + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "")
                + EndpointInventory.normalizePath(u.getRawPath());
        boolean https = "https".equalsIgnoreCase(u.getScheme());
        boolean doc = isDocument(o);
        boolean api = isApi(o);
        boolean ok2xx = o.status >= 200 && o.status < 300;

        // ---- transport ----
        Result t1 = checks.get("P5-T01");
        t1.applicable++;
        if (!https) hit(t1, ep, "http:// request", null);
        else pass(t1, ep);

        if (https && !o.viaProxy && o.tlsProtocol != null && !o.tlsProtocol.isBlank()) {
            anyTlsDetails = true;
            Result t2 = checks.get("P5-T02");
            t2.applicable++;
            String proto = o.tlsProtocol.toUpperCase(Locale.ROOT).replace("V", "v");
            if (proto.contains("SSL") || proto.matches(".*TLS ?1\\.[01]\\b.*")) hit(t2, ep, o.tlsProtocol, null);
            else pass(t2, ep + " (" + o.tlsProtocol + ")");
        }
        if (https && !o.viaProxy && o.certValidToEpochSec != null && seenCertHosts.add(u.getHost())) {
            Result t3 = checks.get("P5-T03");
            t3.applicable++;
            long daysLeft = (o.certValidToEpochSec - Instant.now().getEpochSecond()) / 86_400L;
            if (daysLeft < 0) hit(t3, u.getHost(), "expired", null);
            else if (daysLeft < CERT_WARN_DAYS) hit(t3, u.getHost(), "expires in " + daysLeft + " days", null);
            else pass(t3, u.getHost() + " (valid for " + daysLeft + " more days)");
        }

        // ---- headers ----
        if (doc && ok2xx) {
            // The browser enforces every CSP it gets: each header AND each <meta http-equiv> tag.
            String csp = o.header("Content-Security-Policy");
            List<String> policies = new ArrayList<>();
            for (String h : o.headers("Content-Security-Policy")) if (h != null && !h.isBlank()) policies.add(h);
            int headerPolicies = policies.size();
            policies.addAll(metaCsp(o.responseBody));
            String where = headerPolicies > 0 && policies.size() > headerPolicies ? "header + meta tag"
                    : headerPolicies > 0 ? "header" : "meta tag";
            Result h1 = checks.get("P5-H01");
            h1.applicable++;
            if (policies.isEmpty()) {
                hit(h1, ep, o.header("Content-Security-Policy-Report-Only") != null ? "only report-only CSP" : "missing", null);
            } else {
                List<String> weak = cspWeaknesses(policies);
                if (weak.isEmpty()) {
                    pass(h1, ep + " (CSP in " + where + ")");
                } else {
                    hit(h1, ep, weak.get(0) + " (CSP in " + where + ")", null);
                    for (int i = 1; i < weak.size(); i++) h1.reasons.merge(weak.get(i) + " (CSP in " + where + ")", 1, Integer::sum);
                }
            }
            Result h2 = checks.get("P5-H02");
            h2.applicable++;
            String xfo = o.header("X-Frame-Options");
            // frame-ancestors only works in a CSP header; browsers ignore it in a <meta> tag.
            boolean frameAncestors = csp != null && csp.toLowerCase(Locale.ROOT).contains("frame-ancestors");
            boolean xfoOk = xfo != null && (xfo.trim().equalsIgnoreCase("DENY") || xfo.trim().equalsIgnoreCase("SAMEORIGIN"));
            if (!xfoOk && !frameAncestors) hit(h2, ep, xfo == null ? "missing" : "invalid X-Frame-Options value", null);
            else pass(h2, ep);
        }
        if (https && (doc || api)) {
            Result h3 = checks.get("P5-H03");
            h3.applicable++;
            String hsts = o.header("Strict-Transport-Security");
            if (hsts == null) hit(h3, ep, "missing", null);
            else if (hstsMaxAge(hsts) < HSTS_MIN_SECONDS) hit(h3, ep, "max-age below 180 days", null);
            else pass(h3, ep);
        }
        if (doc || api) {
            Result h4 = checks.get("P5-H04");
            h4.applicable++;
            String xcto = o.header("X-Content-Type-Options");
            if (xcto == null || !xcto.trim().equalsIgnoreCase("nosniff")) hit(h4, ep, xcto == null ? "missing" : "not nosniff", null);
            else pass(h4, ep);
        }
        Result h5 = checks.get("P5-H05");
        h5.applicable++;
        boolean leaked = false;
        String server = o.header("Server");
        if (server != null && server.matches(".*\\d.*")) {
            hit(h5, ep, "Server header with version", "Server: " + server.trim());
            leaked = true;
        }
        for (String name : List.of("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")) {
            String v = o.header(name);
            if (v != null && !v.isBlank()) {
                hit(h5, ep, name + " header", name + ": " + v.trim());
                leaked = true;
            }
        }
        if (!leaked) pass(h5, ep);

        if (api && ok2xx) {
            Result h6 = checks.get("P5-H06");
            h6.applicable++;
            String cc = o.header("Cache-Control");
            if (cc == null || !cc.toLowerCase(Locale.ROOT).contains("no-store")) {
                hit(h6, ep, cc == null ? "no Cache-Control" : "Cache-Control without no-store", null);
            } else {
                pass(h6, ep);
            }
            Result h7 = checks.get("P5-H07");
            h7.applicable++;
            String acao = o.header("Access-Control-Allow-Origin");
            String acac = o.header("Access-Control-Allow-Credentials");
            if (acao != null && acao.trim().equals("*")) {
                hit(h7, ep, acac != null && acac.trim().equalsIgnoreCase("true") ? "* with credentials" : "Allow-Origin: *", null);
            } else {
                pass(h7, ep);
            }
        }

        // ---- cookies ----
        for (String sc : o.headers("Set-Cookie")) {
            for (String one : sc.split("\n")) checkCookie(one, https, ep);
        }

        // ---- data in URL ----
        if (!o.queryParamNames.isEmpty()) {
            Result d3 = checks.get("P5-D03");
            d3.applicable++;
            boolean any = false;
            Map<String, String> q = parseQuery(o.rawQuery);
            for (Map.Entry<String, String> e : q.entrySet()) {
                String reason = null;
                if (SENSITIVE_PARAM.matcher(e.getKey()).matches()) reason = "sensitive parameter name";
                else {
                    SensitiveData.Hit h = SensitiveData.classify(e.getKey(), e.getValue());
                    if (h != null && !h.masked()) reason = h.type() + " value";
                }
                if (reason != null) {
                    hit(d3, ep, reason, "?" + e.getKey());
                    any = true;
                }
            }
            if (!any) pass(d3, ep);
        }

        // ---- response body ----
        if (o.status > 0) {
            Result e2 = checks.get("P5-E02");
            e2.applicable++;
            if (o.status >= 500) hit(e2, ep, "HTTP " + o.status, null);
            else pass(e2, ep);
        }
        String body = o.responseBody;
        if (body != null && !body.isBlank()) {
            Result e1 = checks.get("P5-E01");
            e1.applicable++;
            boolean leak = false;
            for (Map.Entry<String, Pattern> lp : LEAK_PATTERNS.entrySet()) {
                if (lp.getValue().matcher(body).find()) {
                    hit(e1, ep, lp.getKey(), null);
                    leak = true;
                }
            }
            if (!leak) pass(e1, ep);
            scanData(body, ep, o.responseContentType);
        }
    }

    /** For mixed-content detection: an in-scope page (pageUrl) caused a request to requestUrl. */
    public synchronized void observeSubresource(String pageUrl, String requestUrl) {
        if (pageUrl == null || requestUrl == null) return;
        if (!pageUrl.startsWith("https://")) return;
        Result t4 = checks.get("P5-T04");
        t4.applicable++;
        if (requestUrl.startsWith("http://")) {
            try {
                URI r = URI.create(requestUrl);
                hit(t4, "GET " + r.getHost() + EndpointInventory.normalizePath(r.getRawPath()), "http:// resource on https page", null);
            } catch (Exception e) {
                hit(t4, "(unparsable URL)", "http:// resource on https page", null);
            }
        }
    }

    // ---------------- results ----------------

    public synchronized List<Result> results() {
        for (Result r : checks.values()) {
            if (r.hits > 0) r.status = LEAD;
            else if (r.applicable > 0) r.status = OK;
            else r.status = NONE;
        }
        Result t2 = checks.get("P5-T02");
        Result t3 = checks.get("P5-T03");
        if (!anyTlsDetails) {
            String why = anyViaProxy
                    ? "traffic went through a local proxy (ZAP/Burp), so the browser saw the proxy's TLS, not the server's"
                    : "no TLS details were available for this traffic (e.g. HAR import)";
            for (Result r : List.of(t2, t3)) {
                if (r.applicable == 0) {
                    r.status = NOT_CHECKED;
                    r.note = "Not checked: " + why + ". Run the recorder without -Zap/-Proxy to check it.";
                }
            }
        }
        if (anyDecrypted) {
            checks.get("P5-D01").note = "Checked on the decrypted (plain) response bodies.";
        }
        return new ArrayList<>(checks.values());
    }

    public synchronized int observations() {
        return observations;
    }

    // ---------------- helpers ----------------

    private void checkCookie(String setCookie, boolean https, String ep) {
        String sc = setCookie.trim();
        if (sc.isEmpty()) return;
        int eq = sc.indexOf('=');
        if (eq <= 0) return;
        String name = sc.substring(0, eq).trim();
        String attrs = sc.toLowerCase(Locale.ROOT);
        Result c1 = checks.get("P5-C01");
        boolean firstTime = seenCookies.add(name);
        if (firstTime) c1.applicable++;
        boolean missing = false;
        if (https && !attrs.matches("(?s).*;\\s*secure\\s*(;.*)?$")) {
            hit(c1, ep, "missing Secure", name);
            missing = true;
        }
        if (!attrs.matches("(?s).*;\\s*httponly\\s*(;.*)?$")) {
            hit(c1, ep, "missing HttpOnly", name);
            missing = true;
        }
        if (!attrs.matches("(?s).*;\\s*samesite\\s*=.*")) {
            hit(c1, ep, "missing SameSite", name);
            missing = true;
        } else if (attrs.matches("(?s).*;\\s*samesite\\s*=\\s*none.*") && !attrs.matches("(?s).*;\\s*secure\\s*(;.*)?$")) {
            hit(c1, ep, "SameSite=None without Secure", name);
            missing = true;
        }
        if (!missing && firstTime) c1.passEvidence.add(name + " (Secure/HttpOnly/SameSite set)");
    }

    private void scanData(String body, String ep, String contentType) {
        Result d1 = checks.get("P5-D01");
        Result d2 = checks.get("P5-D02");
        d1.applicable++;
        d2.applicable++;
        int[] counts = new int[2];   // [unmaskedPersonal, secrets]
        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonNode n = M.readTree(trimmed);
                walk(n, "", null, ep, counts, d1, d2, 0);
            } catch (Exception notJson) {
                scanText(body, ep, counts, d1);
            }
        } else if (contentType == null || contentType.toLowerCase(Locale.ROOT).matches(".*(json|text|xml|html).*") || contentType.isBlank()) {
            scanText(body, ep, counts, d1);
        }
        if (counts[0] == 0) pass(d1, ep);
        if (counts[1] == 0) pass(d2, ep);
    }

    private void walk(JsonNode n, String path, String key, String ep, int[] counts, Result d1, Result d2, int depth) {
        if (n == null || depth > 40) return;
        if (n.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = n.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                walk(e.getValue(), path.isEmpty() ? e.getKey() : path + "." + e.getKey(), e.getKey(), ep, counts, d1, d2, depth + 1);
            }
        } else if (n.isArray()) {
            for (JsonNode c : n) walk(c, path + "[]", key, ep, counts, d1, d2, depth + 1);
        } else if (n.isTextual() || n.isNumber()) {
            String v = n.asText();
            // A JSON string that itself holds JSON (common in wrapped responses): look inside too.
            String t = v.trim();
            if (n.isTextual() && t.length() > 1 && (t.startsWith("{") || t.startsWith("["))) {
                try {
                    walk(M.readTree(t), path, key, ep, counts, d1, d2, depth + 1);
                    return;
                } catch (Exception ignore) { /* plain text */ }
            }
            SensitiveData.Hit h = SensitiveData.classify(key, v);
            if (h == null) return;
            if (h.type() == SensitiveData.Type.SECRET) {
                if (!h.masked() && !v.isBlank()) {
                    hit(d2, ep, "secret field", path);
                    counts[1]++;
                }
            } else if (h.masked()) {
                d1.reasons.merge("masked " + h.type() + " (good)", 1, Integer::sum);
                addName(d1.passEvidence, path + " (" + h.type() + " masked)");
            } else {
                hit(d1, ep, "unmasked " + h.type(), path);
                counts[0]++;
            }
        }
    }

    private static final Pattern TEXT_PAN = Pattern.compile("\\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\\b");
    private static final Pattern TEXT_12 = Pattern.compile("(?<![0-9])[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}(?![0-9])");
    private static final Pattern TEXT_EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    private void scanText(String body, String ep, int[] counts, Result d1) {
        if (TEXT_PAN.matcher(body).find()) {
            hit(d1, ep, "unmasked PAN", "(text body)");
            counts[0]++;
        }
        Matcher m = TEXT_12.matcher(body);
        while (m.find()) {
            if (SensitiveData.verhoeffValid(m.group().replaceAll("[ -]", ""))) {
                hit(d1, ep, "unmasked AADHAAR", "(text body)");
                counts[0]++;
                break;
            }
        }
        if (TEXT_EMAIL.matcher(body).find()) {
            hit(d1, ep, "unmasked EMAIL", "(text body)");
            counts[0]++;
        }
    }

    private static final Pattern SENSITIVE_PARAM = Pattern.compile(
            "(?i).*(?:password|passwd|pwd|otp|pin|token|secret|session|jsessionid|api_?key|auth|pan|aadhaar|aadhar|card_?no|cvv).*");

    private static final Map<String, Pattern> LEAK_PATTERNS = new LinkedHashMap<>();

    static {
        LEAK_PATTERNS.put("Java stack trace", Pattern.compile("\\bat [A-Za-z_$][\\w$]*(?:\\.[\\w$<>]+)+\\([\\w$]*\\.(?:java|kt|scala):\\d+\\)"));
        LEAK_PATTERNS.put("exception class name", Pattern.compile(
                "\\b(?:java|javax|jakarta|org|com|net|io)\\.[A-Za-z0-9_.$]+(?:Exception|Error)\\b|\\b[A-Z][A-Za-z]+(?:Connect|Sql|SQL|Hibernate|Persistence|NullPointer|IllegalState|IllegalArgument|ClassCast|NumberFormat)Exception\\b"));
        LEAK_PATTERNS.put(".NET / Python / PHP trace", Pattern.compile(
                "System\\.[A-Za-z.]+Exception|Traceback \\(most recent call last\\)|\\bon line \\d+\\b.*\\.php|Fatal error:.*\\.php"));
        LEAK_PATTERNS.put("SQL error", Pattern.compile(
                "(?i)SQLSTATE|\\bORA-\\d{5}\\b|SQLException|syntax error at or near|You have an error in your SQL syntax|PSQLException|SQLServerException|Incorrect syntax near|unterminated quoted string"));
        LEAK_PATTERNS.put("framework error page", Pattern.compile(
                "Whitelabel Error Page|Apache Tomcat/\\d|<title>Error \\d{3}|JBWEB\\d+|Werkzeug Debugger|DEBUG = True"));
        LEAK_PATTERNS.put("internal file path", Pattern.compile(
                "(?<![A-Za-z])[A-Za-z]:\\\\(?:Users|Program Files|inetpub|apps?|opt|tomcat|jboss|wildfly)[^\"<>\\s]*|(?<![\\w/])/(?:home|opt|var/lib|usr/local|srv|app|tomcat)/[\\w./-]{3,}"));
        LEAK_PATTERNS.put("internal IP address", Pattern.compile(
                "(?<![\\d.])(?:10\\.\\d{1,3}|192\\.168|172\\.(?:1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\.\\d{1,3}(?![\\d.])"));
    }

    private static final Pattern META_TAG = Pattern.compile("(?is)<meta\\b[^>]*>");
    private static final Pattern META_CSP = Pattern.compile("(?is)http-equiv\\s*=\\s*[\"']?\\s*content-security-policy\\s*[\"']?(?=[\\s/>])");
    private static final Pattern META_CONTENT = Pattern.compile("(?is)\\bcontent\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')");

    /** CSP policies set with &lt;meta http-equiv="Content-Security-Policy" content="..."&gt; in an HTML page. */
    static List<String> metaCsp(String html) {
        List<String> out = new ArrayList<>();
        if (html == null || html.isEmpty()) return out;
        String head = html.length() > 300_000 ? html.substring(0, 300_000) : html;
        Matcher tags = META_TAG.matcher(head);
        while (tags.find()) {
            String tag = tags.group();
            if (!META_CSP.matcher(tag).find()) continue;
            Matcher c = META_CONTENT.matcher(tag);
            if (c.find()) {
                String v = c.group(1) != null ? c.group(1) : c.group(2);
                v = v.replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'").replace("&amp;", "&").trim();
                if (!v.isEmpty()) out.add(v);
            }
        }
        return out;
    }

    /** What one policy still allows for scripts/styles. A missing directive with no default-src allows everything. */
    private record CspAllows(boolean scriptInline, boolean scriptEval, boolean scriptAny, boolean styleInline, boolean hasDefault) {
    }

    private static CspAllows allows(String policy) {
        String c = policy.toLowerCase(Locale.ROOT);
        String def = directive(c, "default-src");
        String script = directive(c, "script-src");
        if (script == null) script = def;
        String style = directive(c, "style-src");
        if (style == null) style = def;
        boolean scriptInline = script == null || (script.contains("'unsafe-inline'") && !hasNonceOrHash(script));
        boolean scriptEval = script == null || script.contains("'unsafe-eval'");
        boolean scriptAny = script == null || anySource(script);
        boolean styleInline = style == null || (style.contains("'unsafe-inline'") && !hasNonceOrHash(style));
        return new CspAllows(scriptInline, scriptEval, scriptAny, styleInline, def != null);
    }

    /**
     * Weaknesses of the effective policy. Every policy is enforced, so something is allowed only
     * when ALL policies allow it (e.g. a header without script-src plus a meta tag with
     * script-src 'unsafe-inline' still allows inline script).
     */
    static List<String> cspWeaknesses(List<String> policies) {
        boolean inline = true, eval = true, any = true, styleInline = true, anyDefault = false;
        for (String p : policies) {
            CspAllows a = allows(p);
            inline &= a.scriptInline();
            eval &= a.scriptEval();
            any &= a.scriptAny();
            styleInline &= a.styleInline();
            anyDefault |= a.hasDefault();
        }
        List<String> out = new ArrayList<>();
        if (any) out.add("script-src allows any source (wildcard / scheme / no script-src)");
        if (inline) out.add("script-src allows 'unsafe-inline'");
        if (eval) out.add("script-src allows 'unsafe-eval'");
        if (styleInline) out.add("style-src allows 'unsafe-inline'");
        if (!anyDefault) out.add("no default-src fallback");
        return out;
    }

    private static boolean hasNonceOrHash(String sources) {
        return sources.contains("'nonce-") || sources.contains("'sha256-") || sources.contains("'sha384-") || sources.contains("'sha512-");
    }

    private static boolean anySource(String sources) {
        for (String t : sources.trim().split("\\s+")) {
            if (t.equals("*") || t.equals("https:") || t.equals("http:") || t.equals("data:") || t.equals("blob:")
                    || t.matches("(?:https?://)?\\*(?:[:/].*)?")) {
                return true;
            }
        }
        return false;
    }

    private static String directive(String csp, String name) {
        for (String d : csp.split(";")) {
            String t = d.trim();
            if (t.startsWith(name + " ") || t.equals(name)) return t.substring(name.length()).trim();
        }
        return null;
    }

    private static long hstsMaxAge(String hsts) {
        Matcher m = Pattern.compile("(?i)max-age\\s*=\\s*\"?(\\d+)").matcher(hsts);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }

    private static boolean isDocument(PassiveObservation o) {
        if (!o.resourceType.isBlank()) return o.resourceType.equals("document") || o.resourceType.equals("iframe");
        return o.responseContentType != null && o.responseContentType.toLowerCase(Locale.ROOT).contains("text/html");
    }

    private static boolean isApi(PassiveObservation o) {
        if (!o.resourceType.isBlank() && (o.resourceType.equals("xhr") || o.resourceType.equals("fetch"))) return true;
        String ct = o.responseContentType == null ? "" : o.responseContentType.toLowerCase(Locale.ROOT);
        return o.resourceType.isBlank() && (ct.contains("json") || ct.contains("xml"));
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            try {
                v = java.net.URLDecoder.decode(v, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception ignore) { /* keep raw */ }
            if (!k.isEmpty()) out.put(k, v);
        }
        return out;
    }

    private static void hit(Result r, String endpoint, String reason, String name) {
        r.hits++;
        r.reasons.merge(reason, 1, Integer::sum);
        if (name != null) addName(r.names, name);
        if (endpoint != null && !r.endpoints.contains(endpoint) && r.endpoints.size() < MAX_ENDPOINTS) r.endpoints.add(endpoint);
    }

    private static void pass(Result r, String evidence) {
        if (evidence != null && !r.passEvidence.contains(evidence) && r.passEvidence.size() < 5) r.passEvidence.add(evidence);
    }

    private static void addName(List<String> list, String name) {
        if (!list.contains(name) && list.size() < MAX_NAMES) list.add(name);
    }
}
