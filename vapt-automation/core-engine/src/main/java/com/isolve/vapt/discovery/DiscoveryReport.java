package com.isolve.vapt.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.isolve.vapt.util.MaskUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Writes the endpoint inventory as redacted JSON, CSV and an HTML discovery report.
 * Every string goes through MaskUtil before it is written (CLAUDE.md section 8).
 */
public final class DiscoveryReport {

    private final String project;
    private final List<String> sources;
    private final int callsParsed;
    private final List<Endpoint> endpoints;
    private final String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

    public DiscoveryReport(String project, List<String> sources, int callsParsed, List<Endpoint> endpoints) {
        this.project = project;
        this.sources = sources;
        this.callsParsed = callsParsed;
        this.endpoints = endpoints;
    }

    public File writeJson(File dir, String baseName) throws IOException {
        ObjectMapper m = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        ObjectNode root = m.createObjectNode();
        ObjectNode meta = root.putObject("meta");
        meta.put("project", project);
        meta.put("generatedAt", generatedAt);
        meta.put("mode", "PASSIVE DISCOVERY - no requests were sent by this tool");
        ArrayNode src = meta.putArray("sourceFiles");
        sources.forEach(src::add);
        meta.put("callsParsed", callsParsed);
        meta.put("uniqueEndpoints", endpoints.size());
        meta.put("redaction", "Only names, status codes and counts are stored; header/cookie/token/body VALUES are never kept.");
        ArrayNode arr = root.putArray("endpoints");
        for (Endpoint e : endpoints) {
            ObjectNode n = arr.addObject();
            n.put("module", mask(e.module));
            n.put("method", e.method);
            n.put("path", mask(e.normalizedPath));
            n.put("samplePath", mask(e.samplePath));
            n.put("host", mask(e.host));
            putAll(n.putArray("queryParams"), e.queryParams);
            putAll(n.putArray("bodyParams"), e.bodyParams);
            ArrayNode st = n.putArray("statusCodes");
            e.statusCodes.forEach(st::add);
            putAll(n.putArray("requestContentTypes"), e.requestContentTypes);
            putAll(n.putArray("responseContentTypes"), e.responseContentTypes);
            n.put("encryptedBody", e.encryptedBody);
            n.put("occurrences", e.occurrences);
        }
        File out = new File(dir, baseName + ".redacted.json");
        m.writeValue(out, root);
        return out;
    }

    public File writeCsv(File dir, String baseName) throws IOException {
        StringBuilder sb = new StringBuilder("module,method,path,query_params,body_params,status_codes,encrypted_body,occurrences\n");
        for (Endpoint e : endpoints) {
            sb.append(csv(mask(e.module))).append(',')
              .append(csv(e.method)).append(',')
              .append(csv(mask(e.normalizedPath))).append(',')
              .append(csv(String.join(";", e.queryParams))).append(',')
              .append(csv(String.join(";", e.bodyParams))).append(',')
              .append(csv(joinInts(e.statusCodes))).append(',')
              .append(e.encryptedBody).append(',')
              .append(e.occurrences).append('\n');
        }
        File out = new File(dir, baseName + ".redacted.csv");
        Files.writeString(out.toPath(), sb.toString(), StandardCharsets.UTF_8);
        return out;
    }

    public File writeHtml(File dir, String baseName) throws IOException {
        Map<String, List<Endpoint>> byModule = new TreeMap<>();
        for (Endpoint e : endpoints) byModule.computeIfAbsent(e.module, k -> new java.util.ArrayList<>()).add(e);

        Map<String, Integer> methodCount = new LinkedHashMap<>();
        int encrypted = 0;
        for (Endpoint e : endpoints) {
            methodCount.merge(e.method, 1, Integer::sum);
            if (e.encryptedBody) encrypted++;
        }

        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Endpoint Discovery - ")
         .append(esc(project)).append("</title><style>")
         .append("body{font:13px/1.45 'Segoe UI',Arial,sans-serif;color:#1b2430;margin:24px}")
         .append("h1{color:#0f2a4a;margin:0 0 4px}h2{color:#0f2a4a;border-bottom:2px solid #0f2a4a;padding-bottom:3px;margin-top:22px}")
         .append(".meta{color:#5d6b7a;font-size:12px;margin-bottom:12px}.note{background:#eef6ee;border-left:4px solid #1e7a46;padding:6px 10px;margin:10px 0}")
         .append(".kpis{display:flex;gap:8px;margin:10px 0}.kpi{flex:1;border:1px solid #d9e0e8;border-radius:6px;padding:7px 9px;background:#f4f7fa}")
         .append(".kpi b{display:block;font-size:18px;color:#0f2a4a}table{width:100%;border-collapse:collapse;font-size:12px;margin:6px 0 12px}")
         .append("th,td{border:1px solid #d9e0e8;padding:4px 6px;text-align:left;vertical-align:top}th{background:#0f2a4a;color:#fff}")
         .append("code{font-family:Consolas,monospace;font-size:11.5px}.m{font-weight:700}.enc{color:#9a6200;font-weight:600}")
         .append("</style></head><body>");
        h.append("<h1>Endpoint Discovery Report</h1><div class='meta'>Project: <b>").append(esc(project))
         .append("</b> &nbsp;|&nbsp; Generated: ").append(esc(generatedAt))
         .append(" &nbsp;|&nbsp; Source capture(s): ").append(esc(String.join(", ", sources))).append("</div>");
        h.append("<div class='note'><b>Passive discovery only.</b> This report was built from traffic the tester captured while using the application normally. "
               + "This tool sent no requests. Only names, status codes and counts are stored; header, cookie, token and body values are never kept.</div>");
        h.append("<div class='kpis'>")
         .append(kpi(String.valueOf(callsParsed), "HTTP calls parsed"))
         .append(kpi(String.valueOf(endpoints.size()), "unique endpoints"))
         .append(kpi(String.valueOf(byModule.size()), "modules"))
         .append(kpi(String.valueOf(encrypted), "endpoints with encrypted body"))
         .append("</div>");
        h.append("<p>Methods: ");
        methodCount.forEach((k, v) -> h.append("<span class='m'>").append(esc(k)).append("</span> ").append(v).append(" &nbsp; "));
        h.append("</p>");

        h.append("<h2>Endpoints by module</h2>");
        for (Map.Entry<String, List<Endpoint>> me : byModule.entrySet()) {
            h.append("<h3>").append(esc(mask(me.getKey()))).append(" <span style='color:#5d6b7a;font-weight:400'>(")
             .append(me.getValue().size()).append(")</span></h3>");
            h.append("<table><tr><th style='width:6%'>Method</th><th style='width:34%'>Path</th><th>Query params</th>")
             .append("<th>Body params</th><th style='width:9%'>Status</th><th style='width:6%'>Calls</th></tr>");
            for (Endpoint e : me.getValue()) {
                h.append("<tr><td class='m'>").append(esc(e.method)).append("</td><td><code>")
                 .append(esc(mask(e.normalizedPath))).append("</code></td><td>")
                 .append(esc(String.join(", ", e.queryParams))).append("</td><td>")
                 .append(e.encryptedBody ? "<span class='enc'>encrypted body</span>" : esc(String.join(", ", e.bodyParams)))
                 .append("</td><td>").append(esc(joinInts(e.statusCodes))).append("</td><td>")
                 .append(e.occurrences).append("</td></tr>");
            }
            h.append("</table>");
        }
        h.append("<p class='meta'>Next phase (not run): endpoints will be classified by type and reviewed before any active test. "
               + "Active testing requires separate written confirmation.</p></body></html>");
        File out = new File(dir, baseName + ".html");
        Files.writeString(out.toPath(), h.toString(), StandardCharsets.UTF_8);
        return out;
    }

    // ---------------- helpers ----------------
    private static String kpi(String v, String label) {
        return "<div class='kpi'><b>" + esc(v) + "</b>" + esc(label) + "</div>";
    }

    private static void putAll(ArrayNode arr, Collection<String> values) {
        for (String v : values) arr.add(mask(v));
    }

    private static String joinInts(Collection<Integer> ints) {
        StringBuilder sb = new StringBuilder();
        for (Integer i : ints) { if (sb.length() > 0) sb.append(';'); sb.append(i); }
        return sb.toString();
    }

    private static String mask(String s) {
        return s == null ? "" : MaskUtil.mask(s);
    }

    private static String csv(String s) {
        if (s == null) return "";
        boolean quote = s.contains(",") || s.contains("\"") || s.contains("\n");
        String v = s.replace("\"", "\"\"");
        return quote ? "\"" + v + "\"" : v;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
