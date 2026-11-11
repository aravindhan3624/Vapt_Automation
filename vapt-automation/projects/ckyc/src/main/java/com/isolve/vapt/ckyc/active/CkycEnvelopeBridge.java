package com.isolve.vapt.ckyc.active;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isolve.vapt.active.ActiveResponse;
import com.isolve.vapt.active.HttpActiveTarget;
import com.isolve.vapt.active.ResponseAdapter;
import com.isolve.vapt.crypto.EnvelopeCrypto;

import java.util.Map;

/**
 * Bridges the project-independent Phase 6 active checks to CKYC's request/response encryption.
 * The engine produces a plain (possibly id-swapped) JSON body; this re-encrypts it into CKYC's
 * envelope for sending, and decrypts the reply so the checks read the real status.
 *
 * One {@link EnvelopeCrypto} instance per run: the response is wrapped with this run's client
 * public key, so the same instance must encrypt the request and decrypt the response.
 */
public final class CkycEnvelopeBridge {

    private static final ObjectMapper M = new ObjectMapper();

    private CkycEnvelopeBridge() {
    }

    /** Encrypts each outgoing plain body once into {@code {"payload":...}} + the two crypto headers. */
    public static HttpActiveTarget.BodyCipher bodyCipher(EnvelopeCrypto envelope) {
        return plainBody -> {
            EnvelopeCrypto.Envelope e = envelope.encrypt(plainBody);
            return new HttpActiveTarget.EncryptedBody(e.body, Map.of(
                    EnvelopeCrypto.HEADER_CLIENT_SECRET, e.clientSecret,
                    EnvelopeCrypto.HEADER_CLIENT_PUBLIC_KEY, e.clientPublicKey));
        };
    }

    /** Decrypts the envelope reply and surfaces the inner statusCode when the wrapper is 200. */
    public static ResponseAdapter responseAdapter(EnvelopeCrypto envelope) {
        return (httpStatus, rawBody, header) -> {
            String plain = envelope.decrypt(rawBody, header);
            int eff = effectiveStatus(httpStatus, plain);
            boolean decrypted = plain != null && !plain.equals(rawBody);
            return new ActiveResponse(eff, plain, decrypted);
        };
    }

    /** CKYC sometimes returns HTTP 200 wrapping an inner statusCode (401/403/400); use the inner one. */
    public static int effectiveStatus(int httpStatus, String plainBody) {
        if (httpStatus != 200 || plainBody == null) return httpStatus;
        try {
            JsonNode n = M.readTree(plainBody);
            if (n.has("statusCode") && n.get("statusCode").isInt()) {
                int inner = n.get("statusCode").asInt();
                if (inner >= 400) return inner;
            }
        } catch (Exception ignore) { /* not JSON */ }
        return httpStatus;
    }
}
