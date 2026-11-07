package com.isolve.vapt.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.testng.Assert.*;

/**
 * Proves the envelope round trip against a local stand-in for the application server
 * (its own RSA key pair, loopback HTTP only). No external system is contacted.
 */
public class EnvelopeCryptoTest {

    private static final ObjectMapper M = new ObjectMapper();
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private KeyPair server;
    private String serverPubB64;
    private HttpServer http;
    private int port;

    @BeforeClass
    public void setUp() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        server = g.generateKeyPair();
        serverPubB64 = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(server.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";

        // Fake encrypted server: decrypts the request, echoes it inside an encrypted reply.
        http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        http.createContext("/echo", ex -> {
            String status;
            String reply;
            int code;
            try {
                String secret = ex.getRequestHeaders().getFirst("clientsecret");
                String clientPub = ex.getRequestHeaders().getFirst("clientpublickey");
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                JsonNode n = M.readTree(body);
                if (secret == null || !n.path("payload").isTextual()) {
                    code = 400; status = "plain body rejected";
                    reply = M.createObjectNode().put("statusCode", 400).put("message", status).toString();
                } else {
                    byte[] aesKey = rsaDecrypt(server, secret);              // fails if the key header was corrupted
                    String plain = aesDecrypt(aesKey, n.path("payload").asText());
                    reply = encryptedReply(clientPub, M.createObjectNode().put("statusCode", 200).put("echo", plain).toString());
                    code = 200;
                }
            } catch (Exception e) {
                code = 400;
                reply = M.createObjectNode().put("statusCode", 400).put("message", "cannot decrypt").toString();
            }
            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(code, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        http.start();
        port = http.getAddress().getPort();
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (http != null) http.stop(0);
    }

    @Test
    public void encryptThenServerDecryptsAndClientDecryptsReply() throws Exception {
        EnvelopeCrypto client = new EnvelopeCrypto(serverPubB64);
        String plain = "{\"requestID\":\"REQ-1\",\"userId\":\"546\"}";
        EnvelopeCrypto.Envelope env = client.encrypt(plain);

        assertNotNull(env.body);
        assertFalse(env.body.contains("REQ-1"), "plain text must not appear in the encrypted body");
        byte[] aes = rsaDecrypt(server, env.clientSecret);
        assertEquals(aesDecrypt(aes, M.readTree(env.body).path("payload").asText()), plain);

        String reply = encryptedReply(env.clientPublicKey, "{\"statusCode\":200,\"message\":\"OK\"}");
        assertTrue(EnvelopeCrypto.isEnvelope(reply));
        assertEquals(client.decrypt(reply, null), "{\"statusCode\":200,\"message\":\"OK\"}");
    }

    @Test
    public void filterRoundTripGivesPlainJsonToTheTest() {
        EnvelopeCryptoFilter filter = new EnvelopeCryptoFilter(new EnvelopeCrypto(serverPubB64));
        Response r = RestAssured.given().filter(filter).contentType("application/json")
                .body("{\"search\":\"abc\"}").post("http://127.0.0.1:" + port + "/echo");
        assertEquals(r.statusCode(), 200);
        assertEquals(r.jsonPath().getString("echo"), "{\"search\":\"abc\"}");
    }

    @Test
    public void corruptKeyModeIsRejectedByAServerThatFailsClosed() {
        EnvelopeCryptoFilter filter = new EnvelopeCryptoFilter(new EnvelopeCrypto(serverPubB64));
        Response r = RestAssured.given().filter(filter.withMode(EnvelopeCryptoFilter.Mode.CORRUPT_KEY))
                .contentType("application/json").body("{\"search\":\"abc\"}")
                .post("http://127.0.0.1:" + port + "/echo");
        assertEquals(r.statusCode(), 400);
        // mode is one-shot: the next call is normal again
        Response ok = RestAssured.given().filter(filter).contentType("application/json")
                .body("{\"x\":1}").post("http://127.0.0.1:" + port + "/echo");
        assertEquals(ok.statusCode(), 200);
    }

    @Test
    public void plainBodyModeSendsNoEnvelope() {
        EnvelopeCryptoFilter filter = new EnvelopeCryptoFilter(new EnvelopeCrypto(serverPubB64));
        Response r = RestAssured.given().filter(filter.withMode(EnvelopeCryptoFilter.Mode.PLAIN_BODY))
                .contentType("application/json").body("{\"search\":\"abc\"}")
                .post("http://127.0.0.1:" + port + "/echo");
        assertEquals(r.statusCode(), 400);
        assertEquals(r.jsonPath().getString("message"), "plain body rejected");
    }

    @Test
    public void separateInstancesUseSeparateSessionKeys() {
        assertNotEquals(new EnvelopeCrypto(serverPubB64).clientPublicKey(),
                new EnvelopeCrypto(serverPubB64).clientPublicKey());
    }

    // ---------------- server-side helpers (test only) ----------------
    private static byte[] rsaDecrypt(KeyPair kp, String b64) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, kp.getPrivate(), OAEP);
        return rsa.doFinal(Base64.getDecoder().decode(b64));
    }

    private static String aesDecrypt(byte[] key, String b64) throws Exception {
        byte[] packed = Base64.getDecoder().decode(b64);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, packed, 0, 12));
        return new String(gcm.doFinal(packed, 12, packed.length - 12), StandardCharsets.UTF_8);
    }

    private static String encryptedReply(String clientPubB64, String plainJson) throws Exception {
        PublicKey clientPub = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(clientPubB64)));
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aes = kg.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(128, iv));
        byte[] ct = gcm.doFinal(plainJson.getBytes(StandardCharsets.UTF_8));
        byte[] packed = new byte[12 + ct.length];
        System.arraycopy(iv, 0, packed, 0, 12);
        System.arraycopy(ct, 0, packed, 12, ct.length);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, clientPub, OAEP);
        return M.createObjectNode()
                .put("statusCode", 200)
                .put("responseObject", Base64.getEncoder().encodeToString(packed))
                .put("responseSecret", Base64.getEncoder().encodeToString(rsa.doFinal(aes.getEncoded())))
                .toString();
    }
}
