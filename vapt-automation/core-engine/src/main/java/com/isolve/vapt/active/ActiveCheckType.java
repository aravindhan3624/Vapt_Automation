package com.isolve.vapt.active;

/**
 * The Phase 6 active checks. All are READ-ONLY: they re-send requests the tester already made in
 * their own authorized session, with the authorization weakened (no token / another user's token /
 * a tampered token) or the object id swapped, and observe whether the server correctly denies them.
 * None creates, changes, approves, deletes or submits anything. There is no brute force, no
 * injection of destructive payloads and no data extraction beyond confirming a single leaked field.
 */
public enum ActiveCheckType {

    /** Re-send a safe read request with NO authentication. Secure result: 401/403. (VAPT-050) */
    UNAUTHENTICATED_ACCESS("VAPT-050", "API Authentication Bypass"),

    /** Re-send a safe read request for ANOTHER object id. Secure result: 403/404. (VAPT-049) */
    IDOR_BOLA("VAPT-049", "Broken Object Level Authorization (IDOR/BOLA)"),

    /** Re-send with an alg:none / signature-stripped token. Secure result: rejected. (VAPT-051) */
    JWT_TAMPER("VAPT-051", "JWT / Token Security Validation"),

    /** Fetch a document/image URL with NO authentication. Secure result: 401/403. (VAPT-049/017) */
    UNAUTH_DOCUMENT_ACCESS("VAPT-049", "Unauthenticated access to customer documents");

    public final String checklistId;
    public final String title;

    ActiveCheckType(String checklistId, String title) {
        this.checklistId = checklistId;
        this.title = title;
    }
}
