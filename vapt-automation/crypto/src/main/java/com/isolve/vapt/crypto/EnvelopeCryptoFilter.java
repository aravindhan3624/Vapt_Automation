package com.isolve.vapt.crypto;

import io.restassured.builder.ResponseBuilder;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;

/**
 * REST Assured filter that applies {@link EnvelopeCrypto}: tests build plain JSON, the filter
 * encrypts it on the way out and decrypts the reply, so assertions see plain JSON.
 *
 * Integrity negative tests (e.g. "corrupted key must be rejected") can switch the filter for
 * a single call with {@link #withMode(Mode)}. Those modes only change how OUR request is
 * wrapped; they are used by approval-gated test modules, never by discovery.
 */
public final class EnvelopeCryptoFilter implements Filter {

    /** How the next request is wrapped. */
    public enum Mode {
        /** Normal: encrypt body, send both headers. */
        ENCRYPT,
        /** Send the body unencrypted (checks that the server refuses plain bodies). */
        PLAIN_BODY,
        /** Encrypt, but corrupt the wrapped key header (checks the server fails closed). */
        CORRUPT_KEY
    }

    private final EnvelopeCrypto crypto;
    private final ThreadLocal<Mode> mode = ThreadLocal.withInitial(() -> Mode.ENCRYPT);

    public EnvelopeCryptoFilter(EnvelopeCrypto crypto) {
        this.crypto = crypto;
    }

    /** Mode for the next request on this thread only; resets to ENCRYPT afterwards. */
    public EnvelopeCryptoFilter withMode(Mode m) {
        mode.set(m == null ? Mode.ENCRYPT : m);
        return this;
    }

    @Override
    public Response filter(FilterableRequestSpecification req, FilterableResponseSpecification res, FilterContext ctx) {
        Mode m = mode.get();
        mode.set(Mode.ENCRYPT);   // one-shot

        if (m != Mode.PLAIN_BODY) {
            Object b = req.getBody();
            String plain = b == null ? null : b.toString();
            EnvelopeCrypto.Envelope env = crypto.encrypt(plain);
            if (env.body != null) {
                req.body(env.body);
                if (req.getContentType() == null || req.getContentType().isBlank()) req.contentType("application/json");
            }
            String secret = m == Mode.CORRUPT_KEY ? corrupt(env.clientSecret) : env.clientSecret;
            req.removeHeader(EnvelopeCrypto.HEADER_CLIENT_SECRET);
            req.removeHeader(EnvelopeCrypto.HEADER_CLIENT_PUBLIC_KEY);
            req.header(EnvelopeCrypto.HEADER_CLIENT_SECRET, secret);
            req.header(EnvelopeCrypto.HEADER_CLIENT_PUBLIC_KEY, env.clientPublicKey);
        }

        Response r = ctx.next(req, res);
        String body = r.getBody() == null ? null : r.getBody().asString();
        if (body == null || !EnvelopeCrypto.isEnvelope(body)) return r;
        try {
            String plain = crypto.decrypt(body, r::getHeader);
            return new ResponseBuilder().clone(r).setBody(plain).build();
        } catch (IllegalStateException e) {
            return r;   // not decryptable (e.g. server rejected a tampered call): keep the raw reply as evidence
        }
    }

    /** Keeps the value well-formed base64 but changes its content, so unwrapping must fail. */
    static String corrupt(String b64) {
        byte[] raw = EnvelopeCrypto.unb64(b64);
        for (int i = 0; i < Math.min(8, raw.length); i++) raw[i] ^= (byte) 0x5A;
        return EnvelopeCrypto.b64(raw);
    }
}
