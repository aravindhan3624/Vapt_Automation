package com.isolve.vapt.discovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parsers for passive capture files. No network access; these only read a file the
 * user exported from their own proxy/browser. Values are discarded, names kept.
 */
public final class CaptureParsers {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CaptureParsers() {}

    /** Detect the format from the file content and parse accordingly. */
    public static List<CapturedCall> parse(File file) throws Exception {
        String head = readHead(file, 4096).trim();
        if (head.startsWith("{")) return parseHar(file);
        if (head.startsWith("<")) return parseBurpXml(file);
        throw new IllegalArgumentException(
                "Unrecognized capture format in " + file.getName() + " (expected HAR JSON '{' or Burp XML '<').");
    }

    // ---------------- HAR (browser / Burp "Save as HAR") ----------------
    public static List<CapturedCall> parseHar(File file) throws Exception {
        JsonNode root = MAPPER.readTree(file);
        JsonNode entries = root.path("log").path("entries");
        List<CapturedCall> calls = new ArrayList<>();
        for (JsonNode e : entries) {
            JsonNode req = e.path("request");
            JsonNode resp = e.path("response");
            CapturedCall c = new CapturedCall();
            c.method = req.path("method").asText("GET");
            fillFromUrl(c, req.path("url").asText(""));
            c.queryParamNames = names(req.path("queryString"), "name");
            c.requestHeaderNames = headerNames(req.path("headers"));
            c.requestContentType = contentTypeOf(req.path("headers"), req.path("postData").path("mimeType").asText(""));
            c.requestBodyParamNames = bodyParamNames(req.path("postData"));
            c.status = resp.path("status").asInt(0);
            c.responseContentType = resp.path("content").path("mimeType").asText(
                    contentTypeOf(resp.path("headers"), ""));
            calls.add(c);
        }
        return calls;
    }

    private static List<String> bodyParamNames(JsonNode postData) {
        if (postData == null || postData.isMissingNode()) return List.of();
        JsonNode params = postData.path("params");
        if (params.isArray() && params.size() > 0) return names(params, "name");
        String text = postData.path("text").asText("");
        return topLevelJsonKeys(text);
    }

    // ---------------- Burp Suite "Save items" XML ----------------
    public static List<CapturedCall> parseBurpXml(File file) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        // Harden the XML parser (no external entities / DTDs) - we only read structure.
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        Document doc = f.newDocumentBuilder().parse(file);
        NodeList items = doc.getElementsByTagName("item");
        List<CapturedCall> calls = new ArrayList<>();
        for (int i = 0; i < items.getLength(); i++) {
            Element item = (Element) items.item(i);
            CapturedCall c = new CapturedCall();
            c.method = text(item, "method", "GET");
            String url = text(item, "url", "");
            if (!url.isEmpty()) fillFromUrl(c, url);
            String path = text(item, "path", "");
            if (!path.isEmpty()) splitPathQuery(c, path);
            c.host = firstNonEmpty(text(item, "host", ""), c.host);
            c.scheme = firstNonEmpty(text(item, "protocol", ""), c.scheme);
            c.status = parseIntSafe(text(item, "status", "0"));
            c.responseContentType = text(item, "mimetype", "");
            // Decode the raw request only to read header NAMES and body param NAMES.
            Element reqEl = firstChild(item, "request");
            if (reqEl != null) {
                String raw = decodeMaybeBase64(reqEl);
                applyRawRequest(c, raw);
            }
            calls.add(c);
        }
        return calls;
    }

    private static void applyRawRequest(CapturedCall c, String raw) {
        if (raw == null || raw.isBlank()) return;
        String[] parts = raw.split("\r?\n\r?\n", 2);
        String[] lines = parts[0].split("\r?\n");
        Set<String> headerNames = new LinkedHashSet<>();
        String contentType = "";
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name = lines[i].substring(0, colon).trim();
                headerNames.add(name);
                if (name.equalsIgnoreCase("Content-Type")) contentType = lines[i].substring(colon + 1).trim();
            }
        }
        if (!headerNames.isEmpty()) c.requestHeaderNames = new ArrayList<>(headerNames);
        if (!contentType.isEmpty()) c.requestContentType = contentType;
        if (parts.length == 2 && contentType.toLowerCase().contains("json")) {
            c.requestBodyParamNames = topLevelJsonKeys(parts[1].trim());
        }
    }

    // ---------------- shared helpers ----------------
    private static void fillFromUrl(CapturedCall c, String url) {
        if (url == null || url.isEmpty()) return;
        try {
            URI u = URI.create(url);
            if (u.getScheme() != null) c.scheme = u.getScheme();
            if (u.getHost() != null) c.host = u.getHost();
            c.path = u.getRawPath() == null ? "" : u.getRawPath();
            c.queryParamNames = queryNames(u.getRawQuery());
        } catch (Exception ignore) {
            splitPathQuery(c, url);
        }
    }

    private static void splitPathQuery(CapturedCall c, String pathAndQuery) {
        int q = pathAndQuery.indexOf('?');
        if (q >= 0) {
            c.path = pathAndQuery.substring(0, q);
            c.queryParamNames = queryNames(pathAndQuery.substring(q + 1));
        } else {
            c.path = pathAndQuery;
        }
    }

    private static List<String> queryNames(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) return List.of();
        Set<String> out = new LinkedHashSet<>();
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (!name.isEmpty()) out.add(name);
        }
        return new ArrayList<>(out);
    }

    private static List<String> topLevelJsonKeys(String text) {
        if (text == null || text.isBlank()) return List.of();
        try {
            JsonNode n = MAPPER.readTree(text);
            if (n.isObject()) {
                Set<String> keys = new LinkedHashSet<>();
                n.fieldNames().forEachRemaining(keys::add);
                return new ArrayList<>(keys);
            }
        } catch (Exception ignore) { /* not JSON / encrypted */ }
        return List.of();
    }

    private static List<String> names(JsonNode arr, String field) {
        Set<String> out = new LinkedHashSet<>();
        if (arr != null && arr.isArray()) {
            for (JsonNode n : arr) {
                String v = n.path(field).asText("");
                if (!v.isEmpty()) out.add(v);
            }
        }
        return new ArrayList<>(out);
    }

    private static List<String> headerNames(JsonNode headers) {
        return names(headers, "name");
    }

    private static String contentTypeOf(JsonNode headers, String fallback) {
        if (headers != null && headers.isArray()) {
            for (JsonNode h : headers) {
                if (h.path("name").asText("").equalsIgnoreCase("Content-Type")) {
                    return h.path("value").asText(fallback);
                }
            }
        }
        return fallback;
    }

    private static String decodeMaybeBase64(Element el) {
        String content = el.getTextContent();
        if (content == null) return "";
        if ("true".equalsIgnoreCase(el.getAttribute("base64"))) {
            try {
                return new String(Base64.getMimeDecoder().decode(content.trim()), StandardCharsets.UTF_8);
            } catch (Exception e) {
                return "";
            }
        }
        return content;
    }

    private static Element firstChild(Element parent, String tag) {
        NodeList nl = parent.getElementsByTagName(tag);
        for (int i = 0; i < nl.getLength(); i++) {
            if (nl.item(i).getParentNode() == parent) return (Element) nl.item(i);
        }
        return nl.getLength() > 0 ? (Element) nl.item(0) : null;
    }

    private static String text(Element parent, String tag, String def) {
        Element e = firstChild(parent, tag);
        if (e == null) return def;
        String t = e.getTextContent();
        return t == null ? def : t.trim();
    }

    private static String readHead(File file, int n) throws Exception {
        byte[] buf = new byte[n];
        try (var in = new java.io.FileInputStream(file)) {
            int read = in.read(buf);
            return read <= 0 ? "" : new String(buf, 0, read, StandardCharsets.UTF_8);
        }
    }

    private static int parseIntSafe(String s) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return 0; }
    }

    private static String firstNonEmpty(String a, String b) {
        return (a != null && !a.isEmpty()) ? a : b;
    }
}
