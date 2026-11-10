package com.isolve.vapt.passive;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Phase 5 offline: runs the passive checks over an exported HAR file (browser DevTools / Burp).
 * Reads the file only; sends nothing. Only entries for approved hosts are checked.
 * HAR files have no TLS details, so the TLS protocol/certificate checks show "Not checked".
 *
 *   HarPassiveChecks --project CKYC-7.0 --hosts dev-host[,host2:port] --har C:\captures\walk.har[,b.har]
 *                    [--out C:\captures\CKYC-7.0]
 */
public final class HarPassiveChecks {

    private static final ObjectMapper M = new ObjectMapper();

    private HarPassiveChecks() {
    }

    /** Feeds every in-scope HAR entry to the checks. Returns the number of entries used. */
    public static int feed(Path har, List<String> approvedHosts, PassiveChecks pc) throws Exception {
        JsonNode entries = M.readTree(har.toFile()).path("log").path("entries");
        int used = 0;
        for (JsonNode e : entries) {
            JsonNode req = e.path("request");
            JsonNode resp = e.path("response");
            String url = req.path("url").asText("");
            URI u;
            try {
                u = URI.create(url);
            } catch (Exception ex) {
                continue;
            }
            if (!inScope(u, approvedHosts)) continue;
            PassiveObservation o = new PassiveObservation();
            o.method = req.path("method").asText("GET");
            o.url = url;
            o.resourceType = e.path("_resourceType").asText("");      // Chrome/Edge HAR extension
            o.status = resp.path("status").asInt();
            for (JsonNode h : resp.path("headers")) {
                o.responseHeaders.add(new String[]{h.path("name").asText(), h.path("value").asText()});
            }
            o.responseContentType = header(o, "content-type");
            o.rawQuery = u.getRawQuery() == null ? "" : u.getRawQuery();
            if (!o.rawQuery.isEmpty()) {
                for (String pair : o.rawQuery.split("&")) {
                    int eq = pair.indexOf('=');
                    String n = eq >= 0 ? pair.substring(0, eq) : pair;
                    if (!n.isEmpty() && !o.queryParamNames.contains(n)) o.queryParamNames.add(n);
                }
            }
            JsonNode content = resp.path("content");
            if (content.has("text")) {
                String text = content.path("text").asText();
                if ("base64".equalsIgnoreCase(content.path("encoding").asText(""))) {
                    try {
                        text = new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException ignore) { /* keep as is */ }
                }
                o.responseBody = text;
            }
            pc.observe(o);
            used++;
        }
        return used;
    }

    public static PassiveCheckReport run(String project, List<String> hosts, List<Path> hars, Path outDir, String[] outPaths)
            throws Exception {
        PassiveChecks pc = new PassiveChecks();
        int used = 0;
        List<String> names = new ArrayList<>();
        for (Path h : hars) {
            used += feed(h, hosts, pc);
            names.add(h.getFileName().toString());
        }
        PassiveCheckReport r = PassiveCheckReport.build(project, "Imported HAR: " + String.join(", ", names), hosts, pc);
        r.addNote("Offline: read from an exported file (" + used + " in-scope entries); the application was not contacted.");
        r.addNote("If the application encrypts API bodies, HAR bodies are ciphertext: data checks only see unencrypted "
                + "responses. Use the recorder for decrypted bodies.");
        String base = project.replaceAll("[^A-Za-z0-9._-]", "_") + "-har-"
                + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-passive-checks";
        Path html = r.writeHtml(outDir, base);
        Path csv = r.writeCsv(outDir, base);
        r.writeJson(outDir, base);
        if (outPaths != null && outPaths.length >= 2) {
            outPaths[0] = html.toString();
            outPaths[1] = csv.toString();
        }
        return r;
    }

    public static void main(String[] args) throws Exception {
        String project = "PROJECT";
        List<String> hosts = new ArrayList<>();
        List<Path> hars = new ArrayList<>();
        String out = "";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project" -> project = args[++i];
                case "--hosts" -> hosts.addAll(split(args[++i]));
                case "--har" -> split(args[++i]).forEach(h -> hars.add(Path.of(h)));
                case "--out" -> out = args[++i];
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        if (hosts.isEmpty()) throw new IllegalArgumentException("--hosts is required (approved host names only)");
        if (hars.isEmpty()) throw new IllegalArgumentException("--har is required");
        Path outDir = out.isBlank() ? Path.of("C:\\captures", project) : Path.of(out);
        System.out.println("Passive checks (Phase 5) - offline HAR, no requests are sent");
        String[] paths = new String[2];
        PassiveCheckReport r = run(project, hosts, hars, outDir, paths);
        System.out.println("Responses inspected: " + r.observations + "   Leads: " + r.leads() + "   Status: " + r.byStatus);
        System.out.println("Report (names/counts only): " + paths[0]);
        System.out.println("CSV                      : " + paths[1]);
    }

    static boolean inScope(URI u, List<String> approved) {
        if (u.getHost() == null) return false;
        String host = u.getHost().toLowerCase(Locale.ROOT);
        for (String a : approved) {
            String ah = a.trim().toLowerCase(Locale.ROOT);
            if (ah.contains(":")) {
                String h = ah.substring(0, ah.indexOf(':'));
                int p = Integer.parseInt(ah.substring(ah.indexOf(':') + 1));
                int up = u.getPort() > 0 ? u.getPort() : ("https".equalsIgnoreCase(u.getScheme()) ? 443 : 80);
                if (host.equals(h) && up == p) return true;
            } else if (host.equals(ah)) {
                return true;
            }
        }
        return false;
    }

    private static String header(PassiveObservation o, String name) {
        String v = o.header(name);
        return v == null ? "" : v;
    }

    private static List<String> split(String s) {
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).toList();
    }
}
