package com.isolve.vapt.passive;

import java.util.ArrayList;
import java.util.List;

/**
 * One request/response the tester's own session already produced, handed to {@link PassiveChecks}
 * IN MEMORY. It holds raw values (headers, plain bodies) only for the duration of the check;
 * it is never serialized, and nothing from it is written except names, counts and endpoints.
 */
public final class PassiveObservation {
    public String method = "GET";
    public String url = "";
    /** document, xhr, fetch, script, stylesheet, image, other ... ("" if unknown, e.g. HAR). */
    public String resourceType = "";
    public int status;
    public String responseContentType = "";
    /** All response headers, in order, duplicates kept (several Set-Cookie). Element = {name, value}. */
    public List<String[]> responseHeaders = new ArrayList<>();
    public List<String> queryParamNames = new ArrayList<>();
    /** Raw query string (values used only to detect sensitive data in URLs, never stored). */
    public String rawQuery = "";
    /** Plain response body (already decrypted when the app encrypts). Null when unknown. */
    public String responseBody;
    public boolean responseDecrypted;
    /** TLS details of the connection, when the browser reports them and no proxy re-signed TLS. */
    public String tlsProtocol;
    public Long certValidToEpochSec;
    public String certSubject;
    /** True when traffic went through a local proxy (ZAP/Burp): TLS details are the proxy's. */
    public boolean viaProxy;

    public String header(String name) {
        for (String[] h : responseHeaders) if (h[0].equalsIgnoreCase(name)) return h[1];
        return null;
    }

    public List<String> headers(String name) {
        List<String> out = new ArrayList<>();
        for (String[] h : responseHeaders) if (h[0].equalsIgnoreCase(name)) out.add(h[1]);
        return out;
    }
}
