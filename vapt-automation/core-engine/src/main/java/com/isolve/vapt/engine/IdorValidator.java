package com.isolve.vapt.engine;

import io.restassured.response.Response;

/**
 * Maps to catalog VAPT-049 (BOLA/IDOR) and the authorization-matrix work in Section 9.
 * Given two authenticated contexts (User A's token/role and a known object id belonging
 * to User B), calls the same endpoint and asserts the expected deny response.
 */
public final class IdorValidator {

    public static final class Verdict {
        public final int statusCode;
        public final boolean properlyDenied;
        public final String evidence;

        Verdict(int statusCode, boolean properlyDenied, String evidence) {
            this.statusCode = statusCode; this.properlyDenied = properlyDenied; this.evidence = evidence;
        }
    }

    /** @param response the response obtained when User A's token requested an object
     *                  belonging to User B/another role. */
    public Verdict evaluate(Response response) {
        int status = response.getStatusCode();
        boolean denied = status == 401 || status == 403 || status == 404;
        String evidence = "HTTP " + status + " — " + (denied
                ? "object access correctly denied"
                : "UNAUTHORIZED OBJECT DATA RETURNED (body length=" + response.getBody().asString().length() + ")");
        return new Verdict(status, denied, evidence);
    }
}
