package com.isolve.vapt.active;

import java.util.function.Function;

/**
 * Turns a raw HTTP response into an {@link ActiveResponse}. Projects whose API encrypts responses
 * (e.g. CKYC) supply one that decrypts the body and, when the transport status is 200 but the
 * decrypted envelope carries an inner {@code statusCode} (401/403/…), reports that inner status so
 * the access-control checks read the real result. Keeps the envelope specifics out of core-engine.
 */
@FunctionalInterface
public interface ResponseAdapter {
    /**
     * @param httpStatus transport status code
     * @param rawBody    the raw response body
     * @param header     response-header lookup by name (case-insensitive), may return null
     */
    ActiveResponse adapt(int httpStatus, String rawBody, Function<String, String> header) throws Exception;
}
