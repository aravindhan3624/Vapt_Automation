package com.isolve.vapt.ckyc.active;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isolve.vapt.active.ActiveCheckReport;
import com.isolve.vapt.active.ActiveCheckType;
import com.isolve.vapt.active.ActiveChecks;
import com.isolve.vapt.active.ActiveRunOptions;
import com.isolve.vapt.active.ActiveTestGate;
import com.isolve.vapt.active.HttpActiveTarget;
import com.isolve.vapt.active.RecordedCall;
import com.isolve.vapt.config.AuthorizationScope;
import com.isolve.vapt.config.ProjectConfig;
import com.isolve.vapt.crypto.EnvelopeCrypto;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
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
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.testng.Assert.*;

/**
 * End-to-end on loopback: the encryption bridge lets the Phase 6 checks work on CKYC-style
 * encrypted endpoints. A fake server speaks CKYC's envelope (RSA-OAEP-SHA256 + AES-256-GCM), with
 * an inner statusCode. It proves: an unauthenticated re-send is denied (inner 401 -> Secure), an
 * IDOR re-send for another id is denied (inner 403 -> Secure), a public endpoint with no auth is
 * CONFIRMED, the id in the ENCRYPTED body was really swapped, and no state-changing call was sent.
 */
public class CkycEnvelopeActiveIT {

    private static final ObjectMapper M = new ObjectMapper();
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private static final String REF = "ISOLVE-VAPT-CKYC-2026-001";
    private static final String COOKIE = "__Host-ckyc_session=FAKE-SESSION";
    private static final String OWNED_ID = "1001";
    private static final String OTHER_ID = "999";

    private HttpServer server;
    private int port;
    private KeyPair serverKeys;
    private String serverPublicKeyB64;
    private final Set<String> pathsHit = ConcurrentHashMap.newKeySet();
    private final Set<String> idsSeenEncrypted = ConcurrentHashMap.newKeySet();

    @BeforeClass
    public void setUp() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        serverKeys = g.generateKeyPair();
        serverPublicKeyB64 = Base64.getEncoder().encodeToString(serverKeys.getPublic().getEncoded());

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    public void bridgeEnablesEncryptedUnauthAndIdorChecks() throws Exception {
        String base = "http://127.0.0.1:" + port;
        ProjectConfig cfg = new ProjectConfig();
        cfg.setProjectName("CKYC-7.0");
        cfg.setEnvironment("DEV");
        cfg.setApiBaseUrl(base);
        AuthorizationScope scope = new AuthorizationScope();
        scope.setAuthorizedBy("Head of IS");
        scope.setApprovalReference(REF);
        cfg.setScope(scope);

        ActiveRunOptions o = new ActiveRunOptions();
        o.confirmedActiveTesting = true;
        o.approvalReference = REF;
        o.approvedHosts = List.of("127.0.0.1:" + port);
        o.enabledChecks = List.of(ActiveCheckType.UNAUTHENTICATED_ACCESS, ActiveCheckType.IDOR_BOLA);
        o.otherObjectIds = List.of(OTHER_ID);
        o.delayBetweenRequestsMs = 0;

        // VAPT_ACTIVE_APPROVAL is set to REF for this test JVM by the surefire config.
        ActiveTestGate.Authorization auth = ActiveTestGate.authorize(cfg, o);
        EnvelopeCrypto envelope = new EnvelopeCrypto(serverPublicKeyB64);
        HttpActiveTarget target = new HttpActiveTarget("Cookie", COOKIE, null,
                CkycEnvelopeBridge.bodyCipher(envelope), CkycEnvelopeBridge.responseAdapter(envelope));

        List<RecordedCall> recorded = List.of(
                read(base + "/ckyc-api-gateway/ckycBackend/dvs-V2/getCustomerDetailsV2", "{\"ckycNo\":\"" + OWNED_ID + "\"}"),
                read(base + "/ckyc-api-gateway/ckycBackend/master/getAllMaster", "{\"all\":true}"),
                read(base + "/ckyc-api-gateway/ckycBackend/dvs-V2/approveRejectCustomerV2", "{\"ckycNo\":\"" + OWNED_ID + "\"}"));

        ActiveChecks checks = new ActiveChecks(auth, target, o).run(recorded);
        ActiveCheckReport rep = ActiveCheckReport.build("CKYC-7.0", auth, checks);

        // guard: approve/reject never sent
        assertFalse(pathsHit.stream().anyMatch(p -> p.contains("approveReject")), "state-changing never sent: " + pathsHit);

        // getCustomerDetailsV2: unauth -> inner 401 Secure; IDOR id 999 -> inner 403 Secure
        assertTrue(rep.findings.stream().anyMatch(f -> f.endpoint.endsWith("/getCustomerDetailsV2")
                && f.type == ActiveCheckType.UNAUTHENTICATED_ACCESS && f.status.equals(ActiveChecks.SECURE)
                && f.observedStatus == 401), "unauth read denied (inner 401): " + rep.findings);
        assertTrue(rep.findings.stream().anyMatch(f -> f.endpoint.endsWith("/getCustomerDetailsV2")
                && f.type == ActiveCheckType.IDOR_BOLA && f.status.equals(ActiveChecks.SECURE)
                && f.observedStatus == 403), "idor denied (inner 403): " + rep.findings);

        // getAllMaster: public, unauth -> 200 CONFIRMED
        assertTrue(rep.findings.stream().anyMatch(f -> f.endpoint.endsWith("/getAllMaster")
                && f.type == ActiveCheckType.UNAUTHENTICATED_ACCESS && f.status.equals(ActiveChecks.CONFIRMED)),
                "public getAllMaster confirmed: " + rep.findings);

        // proof the id was swapped INSIDE the encrypted body (server decrypted 999)
        assertTrue(idsSeenEncrypted.contains(OTHER_ID), "the IDOR id must have been sent, encrypted: " + idsSeenEncrypted);
        assertTrue(idsSeenEncrypted.contains(OWNED_ID), "baseline id present");
    }

    // ---------------- fake CKYC-envelope server ----------------
    private void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        pathsHit.add(path);
        try {
            boolean hasCookie = COOKIE.equals(ex.getRequestHeaders().getFirst("Cookie"));
            byte[] wrappedKey = Base64.getDecoder().decode(ex.getRequestHeaders().getFirst("clientsecret"));
            String clientPubB64 = ex.getRequestHeaders().getFirst("clientpublickey");
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, serverKeys.getPrivate(), OAEP);
            byte[] aesKey = rsa.doFinal(wrappedKey);

            JsonNode body = M.readTree(ex.getRequestBody().readAllBytes());
            byte[] packed = Base64.getDecoder().decode(body.path("payload").asText());
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, packed, 0, 12));
            String plainReq = new String(gcm.doFinal(packed, 12, packed.length - 12), StandardCharsets.UTF_8);
            String ckycNo = M.readTree(plainReq).path("ckycNo").asText("");
            if (!ckycNo.isEmpty()) idsSeenEncrypted.add(ckycNo);

            int inner;
            if (path.endsWith("/getAllMaster")) {
                inner = 200;                                   // public: served to anyone
            } else if (!hasCookie) {
                inner = 401;                                   // unauth denied
            } else if (ckycNo.equals(OTHER_ID)) {
                inner = 403;                                   // IDOR denied
            } else {
                inner = 200;                                   // owner, authenticated
            }
            String replyPlain = "{\"statusCode\":" + inner + ",\"message\":\"ok\"}";
            respondEncrypted(ex, inner, replyPlain, clientPubB64);
        } catch (Exception e) {
            byte[] b = "{\"statusCode\":500}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        }
    }

    /** Encrypt the reply with a fresh AES key wrapped (RSA-OAEP-SHA256) with the client public key. */
    private void respondEncrypted(HttpExchange ex, int inner, String plain, String clientPubB64) throws Exception {
        SecretKey aes = KeyGenerator.getInstance("AES").generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(128, iv));
        byte[] ct = gcm.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] packed = new byte[12 + ct.length];
        System.arraycopy(iv, 0, packed, 0, 12);
        System.arraycopy(ct, 0, packed, 12, ct.length);

        PublicKey clientPub = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(clientPubB64)));
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, clientPub, OAEP);
        byte[] wrapped = rsa.doFinal(aes.getEncoded());

        String out = M.createObjectNode()
                .put("responseObject", Base64.getEncoder().encodeToString(packed))
                .put("responseSecret", Base64.getEncoder().encodeToString(wrapped))
                .toString();
        byte[] b = out.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(200, b.length);       // transport 200 wraps the inner status
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static RecordedCall read(String url, String plainBody) {
        RecordedCall c = new RecordedCall("POST", url);
        c.plainBody = plainBody;
        c.wasEncrypted = true;
        return c;
    }
}
