package com.isolve.vapt.active;

/**
 * The target's answer to an {@link ActiveRequest}. {@link #plainBody} is already decrypted by the
 * target when the application encrypts responses; the active checks read only its length and a few
 * structural signals, never its sensitive contents, and nothing from it is written to a report.
 */
public final class ActiveResponse {
    public final int status;
    public final String plainBody;
    public final boolean decrypted;

    public ActiveResponse(int status, String plainBody, boolean decrypted) {
        this.status = status;
        this.plainBody = plainBody == null ? "" : plainBody;
        this.decrypted = decrypted;
    }

    public boolean is2xx() {
        return status >= 200 && status < 300;
    }

    public int length() {
        return plainBody.length();
    }
}
