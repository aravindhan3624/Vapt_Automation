package com.isolve.vapt.active;

import java.net.URI;

/**
 * A request the tester already made in their authorized session, read back so an active check can
 * re-send a safe, authorization-weakened variant of it. Only read-only calls (per
 * {@link NonDestructiveGuard}) are ever acted on.
 */
public final class RecordedCall {
    public String method = "GET";
    public String url = "";
    public String module = "";
    /** Plain (decrypted) request body as recorded, or null. May be redacted in places. */
    public String plainBody;
    /** True when the recorder read this body as plain text (the app encrypts on the wire). */
    public boolean wasEncrypted;

    public RecordedCall() {
    }

    public RecordedCall(String method, String url) {
        this.method = method;
        this.url = url;
    }

    public String path() {
        try {
            String p = URI.create(url).getRawPath();
            return p == null ? "/" : p;
        } catch (Exception e) {
            return url;
        }
    }

    public String host() {
        try {
            URI u = URI.create(url);
            return u.getPort() > 0 ? u.getHost() + ":" + u.getPort() : u.getHost();
        } catch (Exception e) {
            return "";
        }
    }
}
