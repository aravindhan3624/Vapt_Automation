package com.isolve.vapt.engine;

import io.restassured.response.Response;

import java.util.LinkedHashMap;
import java.util.Map;

/** Maps directly to catalog findings VAPT-010 (CSP), VAPT-012 (Pragma), VAPT-025
 *  (Clickjacking / X-Frame-Options), VAPT-061 (header consistency), VAPT-009
 *  (server/version disclosure). Fully automatable — no payloads, just header review. */
public final class SecurityHeaderValidator {

    public static final class HeaderCheck {
        public final String header;
        public final boolean present;
        public final String value;
        public final String verdict; // SECURE | WEAK | MISSING

        HeaderCheck(String header, boolean present, String value, String verdict) {
            this.header = header; this.present = present; this.value = value; this.verdict = verdict;
        }

        /** Readable evidence for reports, e.g. "MISSING" or "SECURE (nosniff)". */
        @Override
        public String toString() {
            return present ? verdict + " (" + value + ")" : verdict;
        }
    }

    public Map<String, HeaderCheck> evaluate(Response response) {
        Map<String, HeaderCheck> results = new LinkedHashMap<>();

        results.put("Content-Security-Policy", check(response, "Content-Security-Policy",
                v -> v != null && !v.isBlank() && !v.contains("unsafe-inline") && !v.contains("unsafe-eval")));
        results.put("Strict-Transport-Security", check(response, "Strict-Transport-Security",
                v -> v != null && v.contains("max-age")));
        results.put("X-Content-Type-Options", check(response, "X-Content-Type-Options",
                v -> "nosniff".equalsIgnoreCase(v)));
        results.put("X-Frame-Options", check(response, "X-Frame-Options",
                v -> v != null && (v.equalsIgnoreCase("DENY") || v.equalsIgnoreCase("SAMEORIGIN"))));
        results.put("Referrer-Policy", check(response, "Referrer-Policy", v -> v != null && !v.isBlank()));
        results.put("Pragma", check(response, "Pragma", v -> v != null && v.toLowerCase().contains("no-cache")));
        results.put("Cache-Control", check(response, "Cache-Control",
                v -> v != null && (v.toLowerCase().contains("no-store") || v.toLowerCase().contains("no-cache"))));

        // Disclosure checks: SHOULD be absent entirely.
        results.put("Server", disclosureCheck(response, "Server"));
        results.put("X-Powered-By", disclosureCheck(response, "X-Powered-By"));
        results.put("X-AspNet-Version", disclosureCheck(response, "X-AspNet-Version"));

        return results;
    }

    private HeaderCheck check(Response response, String header, java.util.function.Predicate<String> isSecure) {
        String value = response.getHeader(header);
        boolean present = value != null;
        String verdict = !present ? "MISSING" : (isSecure.test(value) ? "SECURE" : "WEAK");
        return new HeaderCheck(header, present, value, verdict);
    }

    private HeaderCheck disclosureCheck(Response response, String header) {
        String value = response.getHeader(header);
        boolean present = value != null && !value.isBlank();
        return new HeaderCheck(header, present, value, present ? "WEAK" : "SECURE");
    }
}
