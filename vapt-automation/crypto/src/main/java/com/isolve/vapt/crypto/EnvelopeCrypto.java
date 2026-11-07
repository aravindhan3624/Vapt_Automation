package com.isolve.vapt.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.function.Function;

/**
 * Hybrid RSA-OAEP(SHA-256) + AES-256-GCM request/response envelope, as used by the CKYC 7.0
 * web app. Ported from API_Automation's {@code EnvelopeCrypto} with the same wire format, but:
 * the server public key is passed in (no project config lookup), and each instance holds its
 * own ephemeral client key pair (one per session / role) instead of a process-wide static.
 *
 * <pre>
 * Request :  body   {"payload": B64(iv || ciphertext || tag)}
 *            header clientsecret    = B64(RSA-OAEP-SHA256(serverPublicKey, aesKey))
 *            header clientpublickey = B64(SPKI of this session's ephemeral RSA-2048 public key)
 * Response:  {"responseObject"|"payload": B64(iv||ct||tag), "responseSecret"|"clientSecret"...: B64(wrapped key)}
 *            (the wrapped key may also come as a response header)
 * </pre>
 *
 * The server public key is public material, so it may live in project config. Nothing secret
 * is stored by this class beyond the in-memory ephemeral private key.
 */
public final class EnvelopeCrypto {

    public static final String HEADER_CLIENT_SECRET = "clientsecret";
    public static final String HEADER_CLIENT_PUBLIC_KEY = "clientpublickey";

    private static final ObjectMapper M = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    /** Result of encrypting one request. */
    public static final class Envelope {
        public final String body;            // JSON {"payload": ...}, or null when there was no body
        public final String clientSecret;    // header value
        public final String clientPublicKey; // header value

        Envelope(String body, String clientSecret, String clientPublicKey) {
            this.body = body;
            this.clientSecret = clientSecret;
            this.clientPublicKey = clientPublicKey;
        }
    }

    private final PublicKey serverPublicKey;
    private final KeyPair sessionKeys;

    /** @param serverPublicKeyPem the application's RSA public key (PEM or bare base64 SPKI). */
    public EnvelopeCrypto(String serverPublicKeyPem) {
        try {
            this.serverPublicKey = parsePublicKey(serverPublicKeyPem);
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048, RANDOM);
            this.sessionKeys = g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot initialise envelope crypto: " + e.getMessage(), e);
        }
    }

    /** This session's public key as sent in the {@code clientpublickey} header. */
    public String clientPublicKey() {
        return b64(sessionKeys.getPublic().getEncoded());
    }

    /**
     * Encrypts a plain JSON body. With a null/blank body only the headers are produced
     * (the server still needs them to encrypt its reply).
     */
    public Envelope encrypt(String plainJson) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, RANDOM);
            SecretKey aes = kg.generateKey();

            String body = null;
            if (plainJson != null && !plainJson.isBlank()) {
                byte[] iv = new byte[IV_LEN];
                RANDOM.nextBytes(iv);
                Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
                gcm.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(TAG_BITS, iv));
                byte[] ct = gcm.doFinal(plainJson.getBytes(StandardCharsets.UTF_8));
                byte[] packed = new byte[iv.length + ct.length];
                System.arraycopy(iv, 0, packed, 0, iv.length);
                System.arraycopy(ct, 0, packed, iv.length, ct.length);
                body = M.createObjectNode().put("payload", b64(packed)).toString();
            }

            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.ENCRYPT_MODE, serverPublicKey, OAEP_SHA256);
            byte[] wrapped = rsa.doFinal(aes.getEncoded());
            return new Envelope(body, b64(wrapped), clientPublicKey());
        } catch (Exception e) {
            throw new IllegalStateException("Envelope encryption failed: " + e.getMessage(), e);
        }
    }

    /** True when a response body looks like an encrypted envelope. */
    public static boolean isEnvelope(String body) {
        JsonNode n = parse(body);
        return n != null && n.isObject() && (n.path("responseObject").isTextual() || n.path("payload").isTextual());
    }

    /**
     * Decrypts an envelope response; returns the body unchanged when it is not encrypted.
     * @param header response-header lookup (the wrapped key may come as a header), may be null
     */
    public String decrypt(String body, Function<String, String> header) {
        JsonNode n = parse(body);
        if (n == null || !n.isObject()) return body;
        String data = n.path("responseObject").isTextual() ? n.path("responseObject").asText()
                : n.path("payload").isTextual() ? n.path("payload").asText() : null;
        if (data == null) return body;

        String wrapped = firstText(n, "responseSecret", "clientSecret", "encryptedKey", "secret");
        if (wrapped == null && header != null) {
            for (String h : new String[]{"responseSecret", "clientSecret", "encryptedKey", "responsesecret", "clientsecret"}) {
                wrapped = header.apply(h);
                if (wrapped != null && !wrapped.isBlank()) break;
            }
        }
        if (wrapped == null || wrapped.isBlank()) {
            throw new IllegalStateException("Encrypted response has no wrapped key (responseSecret / clientSecret)");
        }
        try {
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, sessionKeys.getPrivate(), OAEP_SHA256);
            byte[] aesKey = rsa.doFinal(unb64(wrapped));
            byte[] packed = unb64(data);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, packed, 0, IV_LEN));
            byte[] plain = gcm.doFinal(packed, IV_LEN, packed.length - IV_LEN);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Envelope decryption failed: " + e.getMessage(), e);
        }
    }

    // ---------------- helpers ----------------
    static PublicKey parsePublicKey(String pem) throws Exception {
        if (pem == null || pem.isBlank()) throw new IllegalArgumentException("Server public key is empty");
        String b64 = pem.replace("\\n", "\n").replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(b64)));
    }

    private static JsonNode parse(String s) {
        try {
            return s == null || s.isBlank() ? null : M.readTree(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static String firstText(JsonNode n, String... keys) {
        for (String k : keys) {
            JsonNode v = n.get(k);
            if (v != null && v.isTextual() && !v.asText().isBlank()) return v.asText();
        }
        return null;
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static byte[] unb64(String s) {
        return Base64.getDecoder().decode(s.trim());
    }
}
