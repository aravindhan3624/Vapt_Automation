package com.isolve.vapt.engine;

import io.restassured.http.Cookie;
import io.restassured.response.Response;

import java.util.ArrayList;
import java.util.List;

/** Maps to catalog finding VAPT-014 (Cookie attributes). Checks Secure/HttpOnly/SameSite
 *  on every session-looking cookie in a response. */
public final class CookieValidator {

    public static final class CookieVerdict {
        public final String name;
        public final boolean secure, httpOnly;
        public final String sameSite;
        public final List<String> issues = new ArrayList<>();

        CookieVerdict(String name, boolean secure, boolean httpOnly, String sameSite) {
            this.name = name; this.secure = secure; this.httpOnly = httpOnly; this.sameSite = sameSite;
        }

        /** Readable evidence for reports; cookie values are never included. */
        @Override
        public String toString() {
            return name + (issues.isEmpty() ? ": OK" : ": " + String.join(", ", issues));
        }
    }

    public List<CookieVerdict> evaluate(Response response) {
        List<CookieVerdict> results = new ArrayList<>();
        for (Cookie cookie : response.getDetailedCookies()) {
            CookieVerdict v = new CookieVerdict(cookie.getName(), cookie.isSecured(), cookie.isHttpOnly(),
                    cookie.getSameSite());
            boolean looksLikeSession = cookie.getName().toLowerCase().matches(".*(session|token|auth|jwt).*");
            if (looksLikeSession) {
                if (!cookie.isSecured()) v.issues.add("Missing Secure flag");
                if (!cookie.isHttpOnly()) v.issues.add("Missing HttpOnly flag");
                if (cookie.getSameSite() == null || cookie.getSameSite().isBlank()) {
                    v.issues.add("Missing SameSite attribute");
                }
            }
            results.add(v);
        }
        return results;
    }
}
