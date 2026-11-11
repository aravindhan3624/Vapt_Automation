package com.isolve.vapt.active;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.isolve.vapt.catalog.VaptCatalogLoader;
import com.isolve.vapt.catalog.VaptFinding;
import com.isolve.vapt.util.MaskUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Report for a Phase 6 active run. Confirmed access-control weaknesses first, then securely-denied
 * checks (closure evidence), then inconclusive. Records the authorization under which the run was
 * performed. Only statuses, endpoints and short non-sensitive explanations are written; every
 * string also goes through MaskUtil.
 */
public final class ActiveCheckReport {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public String project;
    public String environment;
    public String approvalReference;
    public String authorizedBy;
    public List<String> approvedHosts;
    public String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    public int requestsSent;
    public Map<String, Integer> byStatus = new LinkedHashMap<>();
    public List<String> notes = new ArrayList<>();
    public List<String> skipped = new ArrayList<>();
    public List<ActiveChecks.ActiveFinding> findings = new ArrayList<>();
    public Map<String, String> checklistTitles = new LinkedHashMap<>();

    public static ActiveCheckReport build(String project, ActiveTestGate.Authorization auth, ActiveChecks checks) {
        ActiveCheckReport r = new ActiveCheckReport();
        r.project = project;
        r.environment = auth.environment;
        r.approvalReference = auth.approvalReference;
        r.authorizedBy = auth.authorizedBy;
        r.approvedHosts = auth.approvedHosts;
        r.requestsSent = checks.requestsSent();
        r.skipped = checks.skippedNotes();
        r.findings = new ArrayList<>(checks.findings());
        r.findings.sort(Comparator.comparingInt((ActiveChecks.ActiveFinding f) -> order(f.status)).thenComparing(f -> f.endpoint));
        for (String s : List.of(ActiveChecks.CONFIRMED, ActiveChecks.SECURE, ActiveChecks.INCONCLUSIVE)) {
            r.byStatus.put(s, (int) r.findings.stream().filter(f -> s.equals(f.status)).count());
        }
        for (ActiveChecks.ActiveFinding f : r.findings) {
            r.checklistTitles.computeIfAbsent(f.checklistId, k -> {
                try {
                    return VaptCatalogLoader.findById(k).map(VaptFinding::getTitle).orElse("");
                } catch (RuntimeException e) {
                    return "";
                }
            });
        }
        r.notes.add("Active checks performed under written approval " + auth.approvalReference + " against the "
                + auth.environment + " environment, hosts: " + String.join(", ", auth.approvedHosts) + ".");
        r.notes.add("Every request was a READ-ONLY re-send of a call the tester already made, with the authorization "
                + "weakened (no token / another user's token / another object id). Nothing was created, changed, "
                + "approved, deleted or submitted.");
        r.notes.add("CONFIRMED rows are reproducible access-control weaknesses. SECURE rows are evidence the control "
                + "works (closure evidence). INCONCLUSIVE rows need a manual check.");
        return r;
    }

    public int confirmed() {
        return byStatus.getOrDefault(ActiveChecks.CONFIRMED, 0);
    }

    private static int order(String status) {
        if (ActiveChecks.CONFIRMED.equals(status)) return 0;
        if (ActiveChecks.INCONCLUSIVE.equals(status)) return 1;
        return 2;
    }

    // ---------------- writers ----------------
    public Path writeJson(Path dir, String base) throws IOException {
        Files.createDirectories(dir);
        Path f = dir.resolve(base + ".json");
        Files.writeString(f, MaskUtil.mask(JSON.writeValueAsString(this)), StandardCharsets.UTF_8);
        return f;
    }

    public Path writeCsv(Path dir, String base) throws IOException {
        Files.createDirectories(dir);
        StringBuilder sb = new StringBuilder("Status,Check,Checklist,Method,Endpoint,Weakened HTTP,Baseline HTTP,Detail\n");
        for (ActiveChecks.ActiveFinding f : findings) {
            sb.append(csv(f.status)).append(',').append(csv(f.type.name())).append(',').append(csv(f.checklistId)).append(',')
              .append(csv(f.method)).append(',').append(csv(f.endpoint)).append(',').append(f.observedStatus).append(',')
              .append(f.baselineStatus).append(',').append(csv(f.detail)).append('\n');
        }
        Path f = dir.resolve(base + ".csv");
        Files.writeString(f, MaskUtil.mask(sb.toString()), StandardCharsets.UTF_8);
        return f;
    }

    public Path writeHtml(Path dir, String base) throws IOException {
        Files.createDirectories(dir);
        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html><head><meta charset='utf-8'><title>").append(esc(project))
         .append(" - active checks</title><style>")
         .append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24}h1{font-size:22px}")
         .append("table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #d0d7de;padding:6px 8px;")
         .append("text-align:left;vertical-align:top;font-size:13px}th{background:#f3f5f7}")
         .append(".CONFIRMED{color:#a40e26;font-weight:600}.SECURE{color:#1a7f37;font-weight:600}.INC{color:#b35900}")
         .append(".note{background:#fff8e1;border:1px solid #f0d58c;padding:8px 12px;margin:6px 0}")
         .append("code{background:#f3f5f7;padding:1px 4px;word-break:break-all}</style></head><body>");
        h.append("<h1>").append(esc(project)).append(" &ndash; active checks (Phase 6)</h1>");
        h.append("<p>Environment: ").append(esc(environment)).append("<br>Approval: ").append(esc(approvalReference))
         .append("<br>Authorized by: ").append(esc(authorizedBy)).append("<br>Hosts: ").append(esc(String.join(", ", approvedHosts)))
         .append("<br>Generated: ").append(esc(generatedAt)).append("<br>Requests sent: ").append(requestsSent).append("</p>");
        for (String n : notes) h.append("<div class='note'>").append(esc(n)).append("</div>");

        h.append("<h2>Summary</h2><table><tr><th>Result</th><th>Count</th></tr>");
        byStatus.forEach((k, v) -> h.append("<tr><td class='").append(css(k)).append("'>").append(esc(k)).append("</td><td>")
                .append(v).append("</td></tr>"));
        h.append("</table>");

        h.append("<h2>Findings</h2><table><tr><th>Result</th><th>Check</th><th>Checklist</th><th>Endpoint</th>")
         .append("<th>Weakened / Baseline HTTP</th><th>Detail</th></tr>");
        for (ActiveChecks.ActiveFinding f : findings) {
            h.append("<tr><td class='").append(css(f.status)).append("'>").append(esc(f.status)).append("</td><td>")
             .append(esc(f.type.title)).append("</td><td>").append(esc(f.checklistId)).append(' ')
             .append(esc(checklistTitles.getOrDefault(f.checklistId, ""))).append("</td><td><code>").append(esc(f.endpoint))
             .append("</code></td><td>").append(f.observedStatus).append(" / ").append(f.baselineStatus).append("</td><td>")
             .append(esc(f.detail)).append("</td></tr>");
        }
        h.append("</table>");
        if (!skipped.isEmpty()) {
            h.append("<h2>Not run</h2><ul>");
            for (String s : skipped) h.append("<li>").append(esc(s)).append("</li>");
            h.append("</ul>");
        }
        h.append("</body></html>");
        Path f = dir.resolve(base + ".html");
        Files.writeString(f, MaskUtil.mask(h.toString()), StandardCharsets.UTF_8);
        return f;
    }

    private static String css(String s) {
        if (ActiveChecks.CONFIRMED.equals(s)) return "CONFIRMED";
        if (ActiveChecks.SECURE.equals(s)) return "SECURE";
        return "INC";
    }

    private static String csv(String s) {
        String v = s == null ? "" : s;
        if (v.startsWith("=") || v.startsWith("+") || v.startsWith("-") || v.startsWith("@")) v = "'" + v;
        return "\"" + v.replace("\"", "\"\"") + "\"";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
