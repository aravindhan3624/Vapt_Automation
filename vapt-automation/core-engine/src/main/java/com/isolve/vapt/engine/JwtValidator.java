package com.isolve.vapt.engine;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Maps to catalog VAPT-051 (JWT/Token security). Decodes header+payload (no signature
 *  verification needed for this reconnaissance — we are checking the ISSUER's own
 *  token structure and claims, not forging anything). */
public final class JwtValidator {

    public static final class DecodedJwt {
        public final String headerJson;
        public final String payloadJson;
        public DecodedJwt(String headerJson, String payloadJson) {
            this.headerJson = headerJson; this.payloadJson = payloadJson;
        }
    }

    public DecodedJwt decode(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Not a JWT (expected 3 dot-separated segments): " + jwt.length() + " chars");
        }
        return new DecodedJwt(base64UrlDecode(parts[0]), base64UrlDecode(parts[1]));
    }

    private String base64UrlDecode(String segment) {
        return new String(Base64.getUrlDecoder().decode(pad(segment)), StandardCharsets.UTF_8);
    }

    private String pad(String s) {
        int mod = s.length() % 4;
        return mod == 0 ? s : s + "=".repeat(4 - mod);
    }

    /** Produces the standard tamper variants used in negative tests: alg:none, stripped
     *  signature, and a structurally truncated token — never a forged, re-signed token. */
    public String algNoneVariant(String headerJson, String payloadJson) {
        String tamperedHeader = headerJson.replaceAll("\"alg\"\\s*:\\s*\"[^\"]+\"", "\"alg\":\"none\"");
        String h = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedHeader.getBytes(StandardCharsets.UTF_8));
        String p = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return h + "." + p + ".";
    }

    public String signatureStrippedVariant(String originalJwt) {
        String[] parts = originalJwt.split("\\.");
        return parts[0] + "." + parts[1] + ".";
    }
}
