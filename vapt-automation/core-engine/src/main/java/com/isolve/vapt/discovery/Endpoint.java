package com.isolve.vapt.discovery;

import java.util.TreeSet;

/**
 * A unique endpoint after de-duplication: one row per (method + normalized path).
 * Path IDs are normalized (e.g. /customer/12345 -> /customer/{id}) so the same
 * endpoint called with different ids collapses to a single entry.
 *
 * Holds only non-sensitive metadata (names, status codes, counts) for the
 * endpoint-discovery report. No request/response values are stored.
 */
public final class Endpoint {
    public String module = "";
    public String method = "";
    public String normalizedPath = "";
    public String host = "";
    public String samplePath = "";                       // one real (redacted) path example
    public final TreeSet<String> queryParams = new TreeSet<>();
    public final TreeSet<String> bodyParams = new TreeSet<>();
    public final TreeSet<Integer> statusCodes = new TreeSet<>();
    public final TreeSet<String> requestContentTypes = new TreeSet<>();
    public final TreeSet<String> responseContentTypes = new TreeSet<>();
    public int occurrences = 0;
    public boolean encryptedBody = false;                // true when the body is an opaque/encrypted wrapper

    public String key() {
        return method + " " + normalizedPath;
    }
}
