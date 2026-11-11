package com.isolve.vapt.active;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One request an active check wants to send, built from a request the tester already made.
 * {@link #auth} controls how the target should authenticate it, so the check can weaken auth
 * without the core engine needing to know the project's token mechanics.
 */
public final class ActiveRequest {

    public enum Auth {
        /** Use the tester's current valid session (baseline, to compare against). */
        CURRENT,
        /** Send no credentials at all. */
        NONE,
        /** Use the provided tampered token verbatim (alg:none / signature stripped). */
        TAMPERED_TOKEN
    }

    public String method = "GET";
    public String url = "";
    /** Plain request body as the tester sent it (the target re-encrypts if the app needs it). Null for GET. */
    public String plainBody;
    public Auth auth = Auth.CURRENT;
    public String tamperedToken;
    /** Free-form extra headers the check wants set (never credentials). */
    public Map<String, String> extraHeaders = new LinkedHashMap<>();

    public ActiveRequest(String method, String url) {
        this.method = method;
        this.url = url;
    }
}
