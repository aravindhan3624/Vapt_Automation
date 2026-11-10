package com.isolve.vapt.passive;

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
 * Writes Phase 5 passive-check results as HTML (leads first, then checks with no issue, with the
 * endpoints that were checked as closure evidence), CSV and JSON. Contains only names, counts,
 * reasons and endpoints; every string also goes through MaskUtil.
 */
public final class PassiveCheckReport {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public String project;
    public String source;
    public List<String> approvedHosts;
    public String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    public int observations;
    public Map<String, Integer> byStatus = new LinkedHashMap<>();
    public List<String> notes = new ArrayList<>();
    public List<PassiveChecks.Result> checks = new ArrayList<>();
    public Map<String, String> checklistTitles = new LinkedHashMap<>();

    public static PassiveCheckReport build(String project, String source, List<String> approvedHosts, PassiveChecks pc) {
        PassiveCheckReport r = new PassiveCheckReport();
        r.project = project;
        r.source = source;
        r.approvedHosts = List.copyOf(approvedHosts);
        r.observations = pc.observations();
        r.checks = new ArrayList<>(pc.results());
        r.checks.sort(Comparator.comparingInt((PassiveChecks.Result c) -> order(c.status)).thenComparing(c -> c.id));
        for (String s : List.of(PassiveChecks.LEAD, PassiveChecks.OK, PassiveChecks.NONE, PassiveChecks.NOT_CHECKED)) {
            r.byStatus.put(s, (int) r.checks.stream().filter(c -> c.status.equals(s)).count());
        }
        for (PassiveChecks.Result c : r.checks) {
            for (String id : c.checklistIds) {
                r.checklistTitles.computeIfAbsent(id, k -> {
                    try {
                        return VaptCatalogLoader.findById(k).map(VaptFinding::getTitle).orElse("");
                    } catch (RuntimeException e) {
                        return "";
                    }
                });
            }
        }
        r.notes.add("Passive checks only: the tool inspected traffic that the tester's own session (or an imported file) "
                + "produced. It sent no requests of its own.");
        r.notes.add("\"Lead - to verify\" rows are not confirmed findings: reproduce each with request/response evidence "
                + "before raising it. \"No issue observed\" rows list the endpoints that were checked (closure evidence).");
        r.notes.add("Values are never written: only header / cookie / field names, counts and endpoints.");
        return r;
    }

    public void addNote(String n) {
        notes.add(n);
    }

    public int leads() {
        return byStatus.getOrDefault(PassiveChecks.LEAD, 0);
    }

    private static int order(String status) {
        if (PassiveChecks.LEAD.equals(status)) return 0;
        if (PassiveChecks.OK.equals(status)) return 1;
        if (PassiveChecks.NOT_CHECKED.equals(status)) return 2;
        return 3;
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
        StringBuilder sb = new StringBuilder("Check,Title,Checklist items,Status,Applicable,Hits,Reasons,Names,Endpoints\n");
        for (PassiveChecks.Result c : checks) {
            sb.append(csv(c.id)).append(',').append(csv(c.title)).append(',').append(csv(String.join(" ", c.checklistIds)))
              .append(',').append(csv(c.status)).append(',').append(c.applicable).append(',').append(c.hits).append(',')
              .append(csv(reasons(c))).append(',').append(csv(String.join(" | ", c.names))).append(',')
              .append(csv(String.join(" | ", c.hits > 0 ? c.endpoints : c.passEvidence))).append('\n');
        }
        Path f = dir.resolve(base + ".csv");
        Files.writeString(f, MaskUtil.mask(sb.toString()), StandardCharsets.UTF_8);
        return f;
    }

    public Path writeHtml(Path dir, String base) throws IOException {
        Files.createDirectories(dir);
        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html><head><meta charset='utf-8'><title>").append(esc(project))
         .append(" - passive checks</title><style>")
         .append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24}h1{font-size:22px}")
         .append("table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #d0d7de;padding:6px 8px;")
         .append("text-align:left;vertical-align:top;font-size:13px}th{background:#f3f5f7}")
         .append(".lead{color:#a40e26;font-weight:600}.ok{color:#1a7f37;font-weight:600}.none{color:#57606a}")
         .append(".note{background:#fff8e1;border:1px solid #f0d58c;padding:8px 12px;margin:6px 0}")
         .append("details{margin:10px 0;border:1px solid #d0d7de;padding:8px 12px}summary{cursor:pointer;font-weight:600}")
         .append("code{background:#f3f5f7;padding:1px 4px;word-break:break-all}</style></head><body>");
        h.append("<h1>").append(esc(project)).append(" &ndash; passive checks (Phase 5)</h1>");
        h.append("<p>Source: ").append(esc(source)).append("<br>Approved hosts: ").append(esc(String.join(", ", approvedHosts)))
         .append("<br>Generated: ").append(esc(generatedAt)).append("<br>Responses inspected: ").append(observations).append("</p>");
        for (String n : notes) h.append("<div class='note'>").append(esc(n)).append("</div>");

        h.append("<h2>Summary</h2><table><tr><th>Status</th><th>Checks</th></tr>");
        byStatus.forEach((k, v) -> h.append("<tr><td class='").append(css(k)).append("'>").append(esc(k)).append("</td><td>")
                .append(v).append("</td></tr>"));
        h.append("</table>");

        h.append("<h2>Checks</h2><table><tr><th>Check</th><th>Title</th><th>Checklist item</th><th>Status</th>")
         .append("<th>Applicable</th><th>Hits</th></tr>");
        for (PassiveChecks.Result c : checks) {
            h.append("<tr><td>").append(esc(c.id)).append("</td><td>").append(esc(c.title)).append("</td><td>");
            for (int i = 0; i < c.checklistIds.size(); i++) {
                if (i > 0) h.append("<br>");
                String id = c.checklistIds.get(i);
                h.append(esc(id)).append(' ').append(esc(checklistTitles.getOrDefault(id, "")));
            }
            h.append("</td><td class='").append(css(c.status)).append("'>").append(esc(c.status)).append("</td><td>")
             .append(c.applicable).append("</td><td>").append(c.hits).append("</td></tr>");
        }
        h.append("</table><h2>Details</h2>");
        for (PassiveChecks.Result c : checks) {
            h.append("<details").append(c.hits > 0 ? " open" : "").append("><summary>").append(esc(c.id)).append(" &ndash; ")
             .append(esc(c.title)).append(" &ndash; <span class='").append(css(c.status)).append("'>").append(esc(c.status))
             .append("</span></summary>");
            h.append("<p>Applicable responses: ").append(c.applicable).append(" &middot; Hits: ").append(c.hits).append("</p>");
            if (c.note != null) h.append("<p><b>Note:</b> ").append(esc(c.note)).append("</p>");
            if (!c.reasons.isEmpty()) h.append("<p><b>Reasons:</b> ").append(esc(reasons(c))).append("</p>");
            if (!c.names.isEmpty()) list(h, "Names (headers / cookies / fields / parameters)", c.names);
            if (c.hits > 0) {
                list(h, "Endpoints (first " + c.endpoints.size() + ")", c.endpoints);
                h.append("<p><b>How to verify:</b> ").append(esc(c.howToVerify)).append("</p>");
            }
            if (!c.passEvidence.isEmpty()) list(h, c.hits > 0 ? "Also seen without the issue" : "Checked, no issue (closure evidence)", c.passEvidence);
            h.append("</details>");
        }
        h.append("</body></html>");
        Path f = dir.resolve(base + ".html");
        Files.writeString(f, MaskUtil.mask(h.toString()), StandardCharsets.UTF_8);
        return f;
    }

    private static void list(StringBuilder h, String title, List<String> items) {
        h.append("<p><b>").append(esc(title)).append(":</b></p><ul>");
        for (String s : items) h.append("<li><code>").append(esc(s)).append("</code></li>");
        h.append("</ul>");
    }

    private static String reasons(PassiveChecks.Result c) {
        List<String> parts = new ArrayList<>();
        c.reasons.forEach((k, v) -> parts.add(k + " x" + v));
        return String.join("; ", parts);
    }

    private static String css(String status) {
        if (PassiveChecks.LEAD.equals(status)) return "lead";
        if (PassiveChecks.OK.equals(status)) return "ok";
        return "none";
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
