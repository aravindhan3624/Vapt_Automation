package com.isolve.vapt.zap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.isolve.vapt.catalog.VaptCatalogLoader;
import com.isolve.vapt.catalog.VaptFinding;
import com.isolve.vapt.util.MaskUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Passive-analysis report built from ZAP passive alerts for the approved hosts only.
 *
 * Every row is a LEAD with status "To verify": ZAP passive rules are heuristics, and nothing here
 * is a confirmed vulnerability until a tester reproduces it with evidence. Each ZAP rule is
 * linked to related banking-checklist items through {@code zap/zap-catalog-map.yaml}.
 *
 * Everything written is scrubbed: MaskUtil (tokens, passwords, OTP, PAN, Aadhaar, card numbers)
 * plus cookie values, JWT-shaped strings, long secret-looking strings and URL query values.
 */
public final class PassiveAnalysisReport {

    public static final String STATUS = "To verify";
    private static final int MAX_URLS = 50;
    private static final int MAX_EVIDENCE = 3;
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** One ZAP rule, aggregated over all URLs it fired on. */
    public static final class Lead {
        public String pluginId;
        public String name;
        public String risk;
        public String confidence;
        public String cweId;
        public List<String> checklistIds = new ArrayList<>();
        public List<String> checklistTitles = new ArrayList<>();
        public int occurrences;
        public List<String> urls = new ArrayList<>();
        public List<String> params = new ArrayList<>();
        public List<String> evidence = new ArrayList<>();
        public String description;
        public String solution;
        public String reference;
        public String status = STATUS;
    }

    public String project;
    public String source;
    public List<String> approvedHosts;
    public String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    public int messagesRecorded;
    public int alertCount;
    public Map<String, Integer> leadsByRisk = new LinkedHashMap<>();
    public List<String> notes = new ArrayList<>();
    public List<Lead> leads = new ArrayList<>();

    public static PassiveAnalysisReport build(String project, String source, List<String> approvedHosts,
                                              int messagesRecorded, List<ZapAlert> alerts) {
        PassiveAnalysisReport r = new PassiveAnalysisReport();
        r.project = project;
        r.source = source;
        r.approvedHosts = List.copyOf(approvedHosts);
        r.messagesRecorded = messagesRecorded;
        r.alertCount = alerts.size();
        Map<String, List<String>> map = loadMapping();

        Map<String, Lead> byRule = new LinkedHashMap<>();
        Map<String, Set<String>> urlSets = new LinkedHashMap<>();
        for (ZapAlert a : alerts) {
            String key = a.pluginId + "|" + a.name;
            Lead l = byRule.computeIfAbsent(key, k -> newLead(a, map));
            l.occurrences++;
            if (rank(a.confidence) > rank(l.confidence)) l.confidence = a.confidence;
            Set<String> urls = urlSets.computeIfAbsent(key, k -> new LinkedHashSet<>());
            String u = (a.method.isBlank() ? "" : a.method + " ") + safeUrl(a.url);
            if (urls.size() < MAX_URLS) urls.add(u);
            String p = scrub(a.param);
            if (!p.isBlank() && !l.params.contains(p) && l.params.size() < 20) l.params.add(p);
            String ev = truncate(scrub(a.evidence), 300);
            if (!ev.isBlank() && !l.evidence.contains(ev) && l.evidence.size() < MAX_EVIDENCE) l.evidence.add(ev);
        }
        for (Map.Entry<String, Lead> e : byRule.entrySet()) e.getValue().urls = new ArrayList<>(urlSets.get(e.getKey()));

        r.leads = new ArrayList<>(byRule.values());
        r.leads.sort(Comparator.comparingInt((Lead l) -> -riskRank(l.risk)).thenComparing(l -> l.name));
        for (String risk : List.of("High", "Medium", "Low", "Informational")) {
            r.leadsByRisk.put(risk, (int) r.leads.stream().filter(l -> risk.equalsIgnoreCase(l.risk)).count());
        }
        r.notes.add("Passive analysis only: ZAP read traffic that the tester's own browsing (or an imported file) "
                + "produced. No requests were added, changed or replayed.");
        r.notes.add("Every row is a lead to verify, not a confirmed finding. Confirm with request/response evidence "
                + "before raising it.");
        r.notes.add("Only alerts for the approved hosts are included. URL query values and secrets are removed.");
        return r;
    }

    public void addNote(String note) {
        notes.add(note);
    }

    // ---------------- writers ----------------
    public Path writeJson(Path dir, String baseName) throws IOException {
        Files.createDirectories(dir);
        Path f = dir.resolve(baseName + ".json");
        Files.writeString(f, scrub(JSON.writeValueAsString(this)), StandardCharsets.UTF_8);
        return f;
    }

    public Path writeCsv(Path dir, String baseName) throws IOException {
        Files.createDirectories(dir);
        StringBuilder sb = new StringBuilder("Risk,Confidence,ZAP rule id,ZAP rule,CWE,Checklist items,Occurrences,Status,Sample URLs\n");
        for (Lead l : leads) {
            sb.append(csv(l.risk)).append(',').append(csv(l.confidence)).append(',').append(csv(l.pluginId)).append(',')
              .append(csv(l.name)).append(',').append(csv(l.cweId)).append(',').append(csv(String.join(" ", l.checklistIds)))
              .append(',').append(l.occurrences).append(',').append(csv(l.status)).append(',')
              .append(csv(String.join(" | ", l.urls.subList(0, Math.min(5, l.urls.size()))))).append('\n');
        }
        Path f = dir.resolve(baseName + ".csv");
        Files.writeString(f, scrub(sb.toString()), StandardCharsets.UTF_8);
        return f;
    }

    public Path writeHtml(Path dir, String baseName) throws IOException {
        Files.createDirectories(dir);
        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html><head><meta charset='utf-8'><title>").append(esc(project))
         .append(" - ZAP passive analysis</title><style>")
         .append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24}h1{font-size:22px}")
         .append("table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #d0d7de;padding:6px 8px;")
         .append("text-align:left;vertical-align:top;font-size:13px}th{background:#f3f5f7}")
         .append(".High{color:#a40e26;font-weight:600}.Medium{color:#b35900;font-weight:600}.Low{color:#7d6608}")
         .append(".Informational{color:#57606a}.note{background:#fff8e1;border:1px solid #f0d58c;padding:8px 12px;margin:6px 0}")
         .append("details{margin:10px 0;border:1px solid #d0d7de;padding:8px 12px}summary{cursor:pointer;font-weight:600}")
         .append("code{background:#f3f5f7;padding:1px 4px;word-break:break-all}</style></head><body>");
        h.append("<h1>").append(esc(project)).append(" &ndash; ZAP passive analysis</h1>");
        h.append("<p>Source: ").append(esc(source)).append("<br>Approved hosts: ").append(esc(String.join(", ", approvedHosts)))
         .append("<br>Generated: ").append(esc(generatedAt)).append("<br>Messages ZAP recorded (all hosts): ").append(messagesRecorded)
         .append(" &middot; In-scope alerts: ").append(alertCount).append(" &middot; Distinct leads: ").append(leads.size()).append("</p>");
        for (String n : notes) h.append("<div class='note'>").append(esc(n)).append("</div>");

        h.append("<h2>Summary</h2><table><tr><th>Risk</th><th>Leads</th></tr>");
        leadsByRisk.forEach((k, v) -> h.append("<tr><td class='").append(k).append("'>").append(k).append("</td><td>").append(v).append("</td></tr>"));
        h.append("</table>");

        h.append("<h2>Leads (status: To verify)</h2><table><tr><th>#</th><th>Risk</th><th>Confidence</th><th>ZAP rule</th>")
         .append("<th>CWE</th><th>Checklist item</th><th>Occurrences</th></tr>");
        int i = 1;
        for (Lead l : leads) {
            h.append("<tr><td>").append(i++).append("</td><td class='").append(esc(l.risk)).append("'>").append(esc(l.risk))
             .append("</td><td>").append(esc(l.confidence)).append("</td><td>").append(esc(l.name)).append(" <small>(")
             .append(esc(l.pluginId)).append(")</small></td><td>").append(esc(l.cweId)).append("</td><td>");
            for (int k = 0; k < l.checklistIds.size(); k++) {
                if (k > 0) h.append("<br>");
                h.append(esc(l.checklistIds.get(k))).append(" ").append(esc(l.checklistTitles.get(k)));
            }
            if (l.checklistIds.isEmpty()) h.append("&ndash;");
            h.append("</td><td>").append(l.occurrences).append("</td></tr>");
        }
        h.append("</table>");

        h.append("<h2>Details</h2>");
        i = 1;
        for (Lead l : leads) {
            h.append("<details><summary>").append(i++).append(". <span class='").append(esc(l.risk)).append("'>")
             .append(esc(l.risk)).append("</span> &ndash; ").append(esc(l.name)).append(" (").append(l.occurrences)
             .append(")</summary>");
            h.append("<p><b>Status:</b> ").append(esc(l.status)).append("</p>");
            if (!blank(l.description)) h.append("<p><b>What ZAP saw:</b> ").append(esc(l.description)).append("</p>");
            if (!l.params.isEmpty()) h.append("<p><b>Parameter / header:</b> ").append(esc(String.join(", ", l.params))).append("</p>");
            if (!l.evidence.isEmpty()) {
                h.append("<p><b>Evidence (redacted):</b></p><ul>");
                for (String ev : l.evidence) h.append("<li><code>").append(esc(ev)).append("</code></li>");
                h.append("</ul>");
            }
            h.append("<p><b>URLs</b> (query values removed):</p><ul>");
            for (String u : l.urls) h.append("<li><code>").append(esc(u)).append("</code></li>");
            h.append("</ul>");
            if (!blank(l.solution)) h.append("<p><b>Suggested fix:</b> ").append(esc(l.solution)).append("</p>");
            if (!blank(l.reference)) h.append("<p><b>Reference:</b> ").append(esc(l.reference)).append("</p>");
            h.append("</details>");
        }
        h.append("</body></html>");
        Path f = dir.resolve(baseName + ".html");
        Files.writeString(f, scrub(h.toString()), StandardCharsets.UTF_8);
        return f;
    }

    // ---------------- helpers ----------------
    private static Lead newLead(ZapAlert a, Map<String, List<String>> map) {
        Lead l = new Lead();
        l.pluginId = a.pluginId;
        l.name = a.name;
        l.risk = a.risk;
        l.confidence = a.confidence;
        l.cweId = a.cweId == null || a.cweId.isBlank() || a.cweId.equals("-1") || a.cweId.equals("0") ? "" : a.cweId;
        l.description = truncate(scrub(a.description), 1500);
        l.solution = truncate(scrub(a.solution), 1500);
        l.reference = truncate(scrub(a.reference), 800);
        for (String id : map.getOrDefault(a.pluginId, List.of())) {
            l.checklistIds.add(id);
            Optional<VaptFinding> f = safeFind(id);
            l.checklistTitles.add(f.map(VaptFinding::getTitle).orElse(""));
        }
        return l;
    }

    private static Optional<VaptFinding> safeFind(String id) {
        try {
            return VaptCatalogLoader.findById(id);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** ZAP rule id -> checklist ids; from -Dvapt.zap.map if set, else the bundled file. */
    @SuppressWarnings("unchecked")
    static Map<String, List<String>> loadMapping() {
        ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
        String override = System.getProperty("vapt.zap.map", "");
        try (InputStream in = override.isBlank()
                ? PassiveAnalysisReport.class.getResourceAsStream("/zap/zap-catalog-map.yaml")
                : Files.newInputStream(Path.of(override))) {
            if (in == null) return Map.of();
            Map<String, Object> root = yaml.readValue(in, Map.class);
            Object m = root.get("mappings");
            Map<String, List<String>> out = new LinkedHashMap<>();
            if (m instanceof Map<?, ?> mm) {
                mm.forEach((k, v) -> {
                    List<String> ids = new ArrayList<>();
                    if (v instanceof List<?> lst) lst.forEach(x -> ids.add(String.valueOf(x)));
                    else if (v != null) ids.add(String.valueOf(v));
                    out.put(String.valueOf(k), ids);
                });
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read ZAP checklist mapping", e);
        }
    }

    /** scheme://host[:port]/path?name1&name2 - query VALUES are dropped. */
    static String safeUrl(String url) {
        try {
            URI u = URI.create(url);
            StringBuilder sb = new StringBuilder();
            sb.append(u.getScheme()).append("://").append(u.getHost());
            if (u.getPort() > 0) sb.append(':').append(u.getPort());
            sb.append(u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath());
            if (u.getRawQuery() != null && !u.getRawQuery().isEmpty()) {
                List<String> names = new ArrayList<>();
                for (String pair : u.getRawQuery().split("&")) {
                    int eq = pair.indexOf('=');
                    String n = eq >= 0 ? pair.substring(0, eq) : pair;
                    if (!n.isEmpty() && !names.contains(n)) names.add(n);
                }
                sb.append('?').append(String.join("&", names));
            }
            return scrub(sb.toString());
        } catch (Exception e) {
            int q = url.indexOf('?');
            return scrub(q >= 0 ? url.substring(0, q) : url);
        }
    }

    private static final Pattern COOKIE_VALUE = Pattern.compile("(?i)((?:set-)?cookie\\s*:\\s*[^=;\\s]+=)[^;\\r\\n\"<]*");
    private static final Pattern NAME_VALUE = Pattern.compile(
            "(?i)\\b([A-Za-z0-9_.-]*(?:token|session|sessid|jsessionid|auth|secret|password|passwd|pwd|otp|csrf|xsrf|apikey|api_key|key)[A-Za-z0-9_.-]*)(\\s*[=:]\\s*\"?)([^\\s\"&;,<]{4,})");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?:\\.[A-Za-z0-9_-]*)?");
    // Long token-like strings with both letters and digits; "/" excluded so URL paths survive.
    private static final Pattern LONG_SECRET = Pattern.compile(
            "\\b(?=[A-Za-z0-9+_-]*\\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{40,}={0,2}");

    /** MaskUtil plus cookie values, name=value secrets, JWTs and long secret-looking strings. */
    static String scrub(String s) {
        if (s == null || s.isEmpty()) return s == null ? "" : s;
        String out = MaskUtil.mask(s);
        out = COOKIE_VALUE.matcher(out).replaceAll("$1***REDACTED***");
        out = NAME_VALUE.matcher(out).replaceAll("$1$2***REDACTED***");
        out = JWT.matcher(out).replaceAll("***REDACTED-JWT***");
        out = LONG_SECRET.matcher(out).replaceAll("***REDACTED***");
        return out;
    }

    private static int riskRank(String risk) {
        if (risk == null) return 0;
        return switch (risk.toLowerCase()) {
            case "high" -> 4;
            case "medium" -> 3;
            case "low" -> 2;
            case "informational" -> 1;
            default -> 0;
        };
    }

    private static int rank(String confidence) {
        if (confidence == null) return 0;
        return switch (confidence.toLowerCase()) {
            case "confirmed", "user confirmed" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0;
        };
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + " ...";
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static String csv(String s) {
        String v = s == null ? "" : s;
        if (v.startsWith("=") || v.startsWith("+") || v.startsWith("-") || v.startsWith("@")) v = "'" + v; // no formula injection
        return "\"" + v.replace("\"", "\"\"") + "\"";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
