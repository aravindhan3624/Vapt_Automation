package com.isolve.vapt.active;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * A generic {@link ActiveTarget} that sends one real HTTP request per call using java.net.http.
 * It is deliberately minimal and non-amplifying: no redirect-following that could multiply
 * requests, no retries, a short timeout, one request per {@link #send}.
 *
 * Project specifics are injected:
 *  - {@code sessionHeader}: the header name + value for the tester's CURRENT session (e.g. a Cookie).
 *    Supplied at run time (never stored in the project), and omitted for {@link ActiveRequest.Auth#NONE}.
 *  - {@code tamperedSession}: the header value to use for {@link ActiveRequest.Auth#TAMPERED_TOKEN}.
 *  - {@code cipher}: re-encrypts a plain body for apps that encrypt on the wire; when null, the
 *    plain body is sent as-is (fine for GET/document calls, which carry no body).
 */
public final class HttpActiveTarget implements ActiveTarget {

    /** Turns a plain request body into the wire body plus any crypto headers the app needs. */
    @FunctionalInterface
    public interface BodyCipher {
        /** @return {wireBody, headers} ; headers are added to the request. */
        EncryptedBody encrypt(String plainBody) throws Exception;
    }

    public record EncryptedBody(String wireBody, Map<String, String> headers) {
    }

    private final HttpClient client;
    private final String sessionHeaderName;
    private final String sessionHeaderValue;
    private final String tamperedSessionValue;
    private final BodyCipher cipher;
    private final ResponseAdapter responseAdapter;

    public HttpActiveTarget(String sessionHeaderName, String sessionHeaderValue, String tamperedSessionValue, BodyCipher cipher) {
        this(sessionHeaderName, sessionHeaderValue, tamperedSessionValue, cipher, null);
    }

    /** @param responseAdapter decrypts / reinterprets the response (e.g. CKYC envelope); null = raw. */
    public HttpActiveTarget(String sessionHeaderName, String sessionHeaderValue, String tamperedSessionValue,
                            BodyCipher cipher, ResponseAdapter responseAdapter) {
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(15))
                .build();
        this.sessionHeaderName = sessionHeaderName;
        this.sessionHeaderValue = sessionHeaderValue;
        this.tamperedSessionValue = tamperedSessionValue;
        this.cipher = cipher;
        this.responseAdapter = responseAdapter;
    }

    @Override
    public ActiveResponse send(ActiveRequest r) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(r.url)).timeout(Duration.ofSeconds(20));

        String wireBody = r.plainBody;
        if (r.plainBody != null && cipher != null) {
            EncryptedBody enc = cipher.encrypt(r.plainBody);
            wireBody = enc.wireBody();
            if (enc.headers() != null) enc.headers().forEach(b::header);
            b.header("Content-Type", "application/json");
        } else if (r.plainBody != null) {
            b.header("Content-Type", "application/json");
        }

        // Authorization: attach the session only when the check wants it.
        switch (r.auth) {
            case CURRENT -> addSession(b, sessionHeaderName, sessionHeaderValue);
            case TAMPERED_TOKEN -> addSession(b, sessionHeaderName, r.tamperedToken != null ? r.tamperedToken : tamperedSessionValue);
            case NONE -> { /* send nothing */ }
        }
        if (r.extraHeaders != null) r.extraHeaders.forEach(b::header);

        if ("GET".equalsIgnoreCase(r.method) || wireBody == null) {
            b.method(r.method, HttpRequest.BodyPublishers.noBody());
        } else {
            b.method(r.method, HttpRequest.BodyPublishers.ofString(wireBody));
        }

        HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (responseAdapter != null) {
            return responseAdapter.adapt(resp.statusCode(), resp.body(),
                    name -> resp.headers().firstValue(name).orElse(null));
        }
        return new ActiveResponse(resp.statusCode(), resp.body(), false);
    }

    private static void addSession(HttpRequest.Builder b, String name, String value) {
        if (name != null && !name.isBlank() && value != null && !value.isBlank()) {
            b.header(name, value);
        }
    }
}
