package com.isolve.vapt.active;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Phase 6 active checks. Each check re-sends a READ-ONLY request the tester already made, with the
 * authorization weakened, and records whether the server denied it (secure) or served it (a
 * confirmed access-control finding). Construction requires an {@link ActiveTestGate.Authorization}
 * token, so the checks cannot run unless the gate was passed.
 *
 * Guarantees enforced here, in code:
 *  - only hosts in the authorization are ever contacted;
 *  - only endpoints {@link NonDestructiveGuard} rates SAFE_READ are ever re-sent;
 *  - a global request budget and a delay between requests (no flooding / brute force);
 *  - each variant is sent exactly once.
 */
public final class ActiveChecks {

    public static final String CONFIRMED = "CONFIRMED - access control weakness";
    public static final String SECURE = "Secure - correctly denied";
    public static final String INCONCLUSIVE = "Inconclusive - verify manually";
    public static final String SKIPPED = "Skipped";

    private final ActiveTestGate.Authorization auth;
    private final ActiveTarget target;
    private final ActiveRunOptions options;
    private final List<ActiveFinding> findings = new ArrayList<>();
    private final List<String> skipped = new ArrayList<>();
    private int requestsSent;

    public ActiveChecks(ActiveTestGate.Authorization auth, ActiveTarget target, ActiveRunOptions options) {
        this.auth = auth;                 // non-null only obtainable from the gate
        this.target = target;
        this.options = options;
        if (auth == null) throw new SecurityException("ActiveChecks requires a passed-gate Authorization.");
    }

    /** One result row. */
    public static final class ActiveFinding {
        public ActiveCheckType type;
        public String method;
        public String endpoint;      // host + normalized-ish path, no query values
        public String status;        // CONFIRMED / SECURE / INCONCLUSIVE
        public int observedStatus;   // HTTP status of the weakened request
        public int baselineStatus;   // HTTP status of the tester's valid request (for reference)
        public String detail;        // short, non-sensitive explanation
        public String checklistId;

        ActiveFinding(ActiveCheckType type, String method, String endpoint) {
            this.type = type;
            this.method = method;
            this.endpoint = endpoint;
            this.checklistId = type.checklistId;
        }
    }

    public List<ActiveFinding> findings() {
        return findings;
    }

    public List<String> skippedNotes() {
        return skipped;
    }

    public int requestsSent() {
        return requestsSent;
    }

    /** Runs every enabled check over the recorded calls. Returns this for chaining to the report. */
    public ActiveChecks run(List<RecordedCall> recorded) throws Exception {
        List<RecordedCall> safe = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (RecordedCall c : recorded) {
            if (!inScope(c.url)) continue;
            if (!NonDestructiveGuard.isSafeRead(c.method, c.path())) continue;
            String key = c.method.toUpperCase(Locale.ROOT) + " " + c.path();
            if (seen.add(key)) safe.add(c);          // one representative per method+path
        }

        for (ActiveCheckType type : ActiveCheckType.values()) {
            if (!options.isEnabled(type)) {
                skipped.add(type.name() + " not enabled");
                continue;
            }
            for (RecordedCall c : safe) {
                if (requestsSent >= options.maxRequests) {
                    skipped.add("request budget (" + options.maxRequests + ") reached; some checks not completed");
                    return this;
                }
                switch (type) {
                    case UNAUTHENTICATED_ACCESS -> unauthenticated(c, false);
                    case UNAUTH_DOCUMENT_ACCESS -> { if (isDocument(c.path())) unauthenticated(c, true); }
                    case IDOR_BOLA -> idor(c);
                    case JWT_TAMPER -> jwtTamper(c);
                }
            }
        }
        return this;
    }

    // ---------------- checks (all read-only) ----------------

    /** Re-send with no credentials. Secure: 401/403. 2xx with a real body: confirmed. */
    private void unauthenticated(RecordedCall c, boolean document) {
        ActiveCheckType type = document ? ActiveCheckType.UNAUTH_DOCUMENT_ACCESS : ActiveCheckType.UNAUTHENTICATED_ACCESS;
        try {
            ActiveResponse base = send(baseline(c));
            ActiveRequest r = new ActiveRequest(c.method, c.url);
            r.plainBody = c.plainBody;
            r.auth = ActiveRequest.Auth.NONE;
            ActiveResponse resp = send(r);
            ActiveFinding f = new ActiveFinding(type, c.method, endpoint(c));
            f.baselineStatus = base.status;
            f.observedStatus = resp.status;
            if (resp.status == 401 || resp.status == 403) {
                f.status = SECURE;
                f.detail = "No-auth request correctly rejected (" + resp.status + ").";
            } else if (resp.is2xx() && resp.length() > 0) {
                f.status = CONFIRMED;
                f.detail = document
                        ? "Document served with NO authentication (HTTP " + resp.status + "). Anyone with the URL can read it."
                        : "Endpoint returned data with NO authentication (HTTP " + resp.status + ").";
            } else {
                f.status = INCONCLUSIVE;
                f.detail = "No-auth request returned HTTP " + resp.status + "; confirm manually.";
            }
            findings.add(f);
        } catch (UnsupportedOperationException un) {
            skipped.add(type.name() + " on " + endpoint(c) + ": " + un.getMessage());
        } catch (Exception e) {
            inconclusive(type, c, "request error: " + e.getClass().getSimpleName());
        }
    }

    /** Re-send for another object id. Secure: 403/404. 2xx returning a different object: confirmed. */
    private void idor(RecordedCall c) {
        if (options.otherObjectIds.isEmpty()) {
            skipped.add("IDOR_BOLA on " + endpoint(c) + ": no otherObjectIds configured");
            return;
        }
        try {
            ActiveResponse base = send(baseline(c));
            String otherId = options.otherObjectIds.get(0);
            ActiveRequest r = swapId(c, otherId);
            if (r == null) {
                skipped.add("IDOR_BOLA on " + endpoint(c) + ": no object id found to swap");
                return;
            }
            r.auth = ActiveRequest.Auth.CURRENT;     // same user, different object = BOLA
            ActiveResponse resp = send(r);
            ActiveFinding f = new ActiveFinding(ActiveCheckType.IDOR_BOLA, c.method, endpoint(c));
            f.baselineStatus = base.status;
            f.observedStatus = resp.status;
            if (resp.status == 401 || resp.status == 403 || resp.status == 404) {
                f.status = SECURE;
                f.detail = "Cross-object request correctly denied (" + resp.status + ").";
            } else if (resp.is2xx() && resp.length() > 0) {
                f.status = CONFIRMED;
                f.detail = "Returned another object's data for id not owned by this user (HTTP " + resp.status + ").";
            } else {
                f.status = INCONCLUSIVE;
                f.detail = "Cross-object request returned HTTP " + resp.status + "; confirm manually.";
            }
            findings.add(f);
        } catch (UnsupportedOperationException un) {
            skipped.add("IDOR_BOLA on " + endpoint(c) + ": " + un.getMessage());
        } catch (Exception e) {
            inconclusive(ActiveCheckType.IDOR_BOLA, c, "request error: " + e.getClass().getSimpleName());
        }
    }

    /** Re-send with an alg:none / signature-stripped token. Secure: rejected. Detection only. */
    private void jwtTamper(RecordedCall c) {
        try {
            ActiveResponse base = send(baseline(c));
            ActiveRequest r = new ActiveRequest(c.method, c.url);
            r.plainBody = c.plainBody;
            r.auth = ActiveRequest.Auth.TAMPERED_TOKEN;      // target supplies the tampered variant
            ActiveResponse resp = send(r);
            ActiveFinding f = new ActiveFinding(ActiveCheckType.JWT_TAMPER, c.method, endpoint(c));
            f.baselineStatus = base.status;
            f.observedStatus = resp.status;
            if (resp.status == 401 || resp.status == 403) {
                f.status = SECURE;
                f.detail = "Tampered (alg:none / unsigned) token correctly rejected (" + resp.status + ").";
            } else if (resp.is2xx()) {
                f.status = CONFIRMED;
                f.detail = "Tampered/unsigned token ACCEPTED (HTTP " + resp.status + ") - signature not verified.";
            } else {
                f.status = INCONCLUSIVE;
                f.detail = "Tampered token returned HTTP " + resp.status + "; confirm manually.";
            }
            findings.add(f);
        } catch (UnsupportedOperationException un) {
            skipped.add("JWT_TAMPER on " + endpoint(c) + ": " + un.getMessage());
        } catch (Exception e) {
            inconclusive(ActiveCheckType.JWT_TAMPER, c, "request error: " + e.getClass().getSimpleName());
        }
    }

    // ---------------- helpers ----------------

    private ActiveRequest baseline(RecordedCall c) {
        ActiveRequest r = new ActiveRequest(c.method, c.url);
        r.plainBody = c.plainBody;
        r.auth = ActiveRequest.Auth.CURRENT;
        return r;
    }

    private ActiveResponse send(ActiveRequest r) throws Exception {
        if (!inScope(r.url)) throw new SecurityException("Out-of-scope host blocked: " + r.url);
        if (requestsSent >= options.maxRequests) throw new IllegalStateException("request budget reached");
        if (requestsSent > 0 && options.delayBetweenRequestsMs > 0) {
            Thread.sleep(options.delayBetweenRequestsMs);
        }
        requestsSent++;
        return target.send(r);
    }

    private void inconclusive(ActiveCheckType type, RecordedCall c, String why) {
        ActiveFinding f = new ActiveFinding(type, c.method, endpoint(c));
        f.status = INCONCLUSIVE;
        f.detail = why;
        findings.add(f);
    }

    /** Swaps the last numeric path segment, or a plain-body id field, to another id. */
    private ActiveRequest swapId(RecordedCall c, String otherId) {
        // path id (e.g. /CKYC_IMAGE/123/...): replace a long numeric segment.
        String url = c.url;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("/(\\d{3,})(?=/|$|\\?)").matcher(url);
        if (m.find()) {
            ActiveRequest r = new ActiveRequest(c.method, new StringBuilder(url).replace(m.start(1), m.end(1), otherId).toString());
            r.plainBody = c.plainBody;
            return r;
        }
        // body id field: replace the value of a *id/*no field in the plain JSON body (textual only).
        if (c.plainBody != null) {
            java.util.regex.Matcher bm = java.util.regex.Pattern.compile(
                    "(?i)(\"[A-Za-z0-9_]*(?:id|no|number|ckyc)\"\\s*:\\s*\")([^\"]{1,40})(\")").matcher(c.plainBody);
            if (bm.find()) {
                ActiveRequest r = new ActiveRequest(c.method, url);
                r.plainBody = new StringBuilder(c.plainBody).replace(bm.start(2), bm.end(2), otherId).toString();
                return r;
            }
        }
        return null;
    }

    private boolean isDocument(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        return p.contains("/ckyc_image/") || p.matches(".*\\.(jpg|jpeg|png|gif|pdf|bmp|tiff|webp)$");
    }

    private boolean inScope(String url) {
        try {
            URI u = URI.create(url);
            if (u.getHost() == null) return false;
            String host = u.getHost().toLowerCase(Locale.ROOT);
            int port = u.getPort();
            for (String a : auth.approvedHosts) {
                String ah = a.trim().toLowerCase(Locale.ROOT);
                if (ah.contains(":")) {
                    String h = ah.substring(0, ah.indexOf(':'));
                    int p = Integer.parseInt(ah.substring(ah.indexOf(':') + 1));
                    if (host.equals(h) && port == p) return true;
                } else if (host.equals(ah)) {
                    return true;
                }
            }
        } catch (Exception ignore) {
            return false;
        }
        return false;
    }

    private String endpoint(RecordedCall c) {
        return c.method.toUpperCase(Locale.ROOT) + " " + c.host() + c.path().replaceAll("/\\d{3,}", "/{id}");
    }
}
