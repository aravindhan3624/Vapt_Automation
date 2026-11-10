package com.isolve.vapt.discovery;

import com.isolve.vapt.util.MaskUtil;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Turns a flat list of captured calls into a de-duplicated endpoint inventory:
 * normalizes path ids, groups by module, and merges repeated calls into one entry.
 * Pure data transformation - no network, no test traffic.
 */
public final class EndpointInventory {

    private static final Pattern UUID =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern DIGITS = Pattern.compile("^\\d+$");
    private static final Pattern LONG_HEX = Pattern.compile("^[0-9a-fA-F]{16,}$");

    /** Path segments that are infrastructure, not the business module. */
    private static final Set<String> INFRA_SEGMENTS = new LinkedHashSet<>(List.of(
            "ckyc-api-gateway", "ckycbackend", "api", "apis", "rest", "gateway", "backend",
            "service", "services", "v1", "v2", "v3", "web", "public"));

    /** Segment shapes that are infrastructure too, e.g. "app-api", "ckyc-api-gateway", "ckycBackend". */
    private static final Pattern INFRA_SHAPE =
            Pattern.compile("(?i)((.*[-_])?(api|apis|rest|gateway)([-_].*)?|.*backend|.*gateway)");

    /** Extra project-specific prefixes to skip when guessing the module (from --skip). */
    private static final Set<String> EXTRA_SKIP = new LinkedHashSet<>();

    private EndpointInventory() {}

    public static void addSkipSegments(List<String> segments) {
        for (String s : segments) if (!s.isBlank()) EXTRA_SKIP.add(s.trim().toLowerCase());
    }

    public static List<Endpoint> build(List<CapturedCall> calls) {
        Map<String, Endpoint> byKey = new TreeMap<>();
        for (CapturedCall c : calls) {
            String norm = normalizePath(c.path);
            String key = c.method + " " + norm;
            Endpoint ep = byKey.computeIfAbsent(key, k -> {
                Endpoint e = new Endpoint();
                e.method = c.method;
                e.normalizedPath = norm;
                e.host = c.host;
                e.module = guessModule(c.path);
                e.samplePath = MaskUtil.mask(c.path);   // redact any PII/token that slipped into the path
                return e;
            });
            ep.occurrences++;
            ep.queryParams.addAll(c.queryParamNames);
            ep.bodyParams.addAll(c.requestBodyParamNames);
            if (c.status > 0) ep.statusCodes.add(c.status);
            if (notBlank(c.requestContentType)) ep.requestContentTypes.add(shortType(c.requestContentType));
            if (notBlank(c.responseContentType)) ep.responseContentTypes.add(shortType(c.responseContentType));
            // A single top-level "payload"/"data" field over an encrypted app = opaque body.
            if (ep.bodyParams.size() == 1 &&
                    (ep.bodyParams.contains("payload") || ep.bodyParams.contains("data"))) {
                ep.encryptedBody = true;
            }
        }
        List<Endpoint> out = new ArrayList<>(byKey.values());
        out.sort(Comparator.comparing((Endpoint e) -> e.module).thenComparing(e -> e.normalizedPath).thenComparing(e -> e.method));
        return out;
    }

    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) return "/";
        String[] segs = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (String s : segs) {
            if (s.isEmpty()) continue;
            sb.append('/');
            if (UUID.matcher(s).matches()) sb.append("{uuid}");
            else if (DIGITS.matcher(s).matches()) sb.append("{id}");
            else if (LONG_HEX.matcher(s).matches()) sb.append("{hash}");
            else sb.append(s);
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    static String guessModule(String path) {
        if (path == null) return "(unknown)";
        for (String s : path.split("/")) {
            if (s.isEmpty()) continue;
            String low = s.toLowerCase();
            if (INFRA_SEGMENTS.contains(low) || EXTRA_SKIP.contains(low) || INFRA_SHAPE.matcher(s).matches()) continue;
            if (DIGITS.matcher(s).matches() || UUID.matcher(s).matches()) continue;
            return s;   // first business-looking segment
        }
        return "(root)";
    }

    private static String shortType(String ct) {
        int semi = ct.indexOf(';');
        return (semi > 0 ? ct.substring(0, semi) : ct).trim();
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
