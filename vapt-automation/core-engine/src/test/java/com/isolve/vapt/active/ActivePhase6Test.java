package com.isolve.vapt.active;

import com.isolve.vapt.config.AuthorizationScope;
import com.isolve.vapt.config.ProjectConfig;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.*;

/**
 * Phase 6 safety and behaviour, entirely against an in-memory fake target (no network).
 * Proves the gate fails closed, the guard refuses state-changing endpoints, and the checks confirm
 * an unauthenticated-access weakness while recording a protected endpoint as secure - and that the
 * fake target was never asked to perform a state-changing call.
 */
public class ActivePhase6Test {

    private static final String REF = "ISOLVE-VAPT-CKYC-2026-001";

    private static ProjectConfig config(String env) {
        ProjectConfig c = new ProjectConfig();
        c.setProjectName("CKYC-7.0");
        c.setEnvironment(env);
        c.setApiBaseUrl("https://dev.example");
        AuthorizationScope s = new AuthorizationScope();
        s.setAuthorizedBy("Head of IS");
        s.setApprovalReference(REF);
        s.setApprovalDate("2026-11-10");
        c.setScope(s);
        return c;
    }

    private static ActiveRunOptions options() {
        ActiveRunOptions o = new ActiveRunOptions();
        o.confirmedActiveTesting = true;
        o.approvalReference = REF;
        o.approvedHosts = List.of("dev.example");
        o.enabledChecks = new ArrayList<>(List.of(ActiveCheckType.UNAUTHENTICATED_ACCESS,
                ActiveCheckType.UNAUTH_DOCUMENT_ACCESS, ActiveCheckType.IDOR_BOLA));
        o.otherObjectIds = List.of("999");
        o.delayBetweenRequestsMs = 0;
        return o;
    }

    // ---------------- gate fails closed ----------------

    @Test
    public void gateRefusesWithoutConfirmation() {
        ActiveRunOptions o = options();
        o.confirmedActiveTesting = false;
        assertThrows(SecurityException.class, () -> ActiveTestGate.authorize(config("DEV"), o, REF));
    }

    @Test
    public void gateRefusesProd() {
        assertThrows(SecurityException.class, () -> ActiveTestGate.authorize(config("PROD"), options(), REF));
    }

    @Test
    public void gateRefusesWhenEnvVarMissingOrMismatched() {
        assertThrows(SecurityException.class, () -> ActiveTestGate.authorize(config("DEV"), options(), null));
        assertThrows(SecurityException.class, () -> ActiveTestGate.authorize(config("DEV"), options(), "WRONG-REF"));
    }

    @Test
    public void gateRefusesWhenRefDoesNotMatchConfig() {
        ActiveRunOptions o = options();
        o.approvalReference = "SOME-OTHER-REF";
        assertThrows(SecurityException.class, () -> ActiveTestGate.authorize(config("DEV"), o, "SOME-OTHER-REF"));
    }

    @Test
    public void gatePassesWithEverythingInPlace() {
        ActiveTestGate.Authorization a = ActiveTestGate.authorize(config("DEV"), options(), REF);
        assertEquals(a.approvalReference, REF);
        assertEquals(a.approvedHosts, List.of("dev.example"));
    }

    // ---------------- guard refuses state-changing endpoints ----------------

    @Test
    public void guardRefusesStateChangingEndpoints() {
        for (String p : List.of(
                "/ckyc-api-gateway/ckycBackend/dvs-V2/approveRejectCustomerV2",
                "/ckyc-api-gateway/ckycBackend/dvs-V2/updateCustomerDetailsV2",
                "/ckyc-api-gateway/ckycBackend/dvs-V2/lockDvsCustomerV2",
                "/ckyc-api-gateway/ckycBackend/auth/login",
                "/ckyc-api-gateway/ckycBackend/auth/revokeToken",
                "/ckyc-api-gateway/ckycBackend/master/crudDashboard",
                "/api/customer/delete/1001")) {
            assertNotEquals(NonDestructiveGuard.classify("POST", p), NonDestructiveGuard.Decision.SAFE_READ,
                    "must NOT be re-sent: " + p);
        }
        assertEquals(NonDestructiveGuard.classify("DELETE", "/api/customer/getDetails"),
                NonDestructiveGuard.Decision.REFUSED_STATE_CHANGING, "DELETE is never safe");
    }

    @Test
    public void guardAllowsReadEndpoints() {
        for (String p : List.of(
                "/ckyc-api-gateway/ckycBackend/dvs-V2/getCustomerDetailsV2",
                "/ckyc-api-gateway/ckycBackend/dvs-V2/getPendingDvsViewV2",
                "/ckyc-api-gateway/ckycBackend/master/getAllMaster",
                "/ckyc-api-gateway/ckycBackend/user/getRolePermissions")) {
            assertEquals(NonDestructiveGuard.classify("POST", p), NonDestructiveGuard.Decision.SAFE_READ, p);
        }
        assertEquals(NonDestructiveGuard.classify("GET", "/CKYC_IMAGE/123/IN31100011/IN31100011_02_Photo.jpg"),
                NonDestructiveGuard.Decision.SAFE_READ);
    }

    // ---------------- checks against a fake target ----------------

    @Test
    public void confirmsUnauthAccessAndNeverSendsStateChanging() throws Exception {
        List<String> sentStateChanging = new ArrayList<>();
        AtomicInteger total = new AtomicInteger();

        ActiveTarget fake = req -> {
            total.incrementAndGet();
            String path = java.net.URI.create(req.url).getPath();
            if (NonDestructiveGuard.classify(req.method, path) != NonDestructiveGuard.Decision.SAFE_READ) {
                sentStateChanging.add(req.method + " " + path);
            }
            // /master/getAllMaster is public-ish: serves data even with no auth (the weakness).
            if (path.endsWith("/getAllMaster")) {
                return new ActiveResponse(200, "{\"masters\":[1,2,3]}", true);
            }
            // The customer-details endpoint properly requires auth.
            if (req.auth == ActiveRequest.Auth.NONE) return new ActiveResponse(401, "", false);
            if (req.auth == ActiveRequest.Auth.CURRENT) return new ActiveResponse(200, "{\"ok\":true}", true);
            return new ActiveResponse(403, "", false);
        };

        List<RecordedCall> recorded = new ArrayList<>();
        recorded.add(post("https://dev.example/ckyc-api-gateway/ckycBackend/dvs-V2/getCustomerDetailsV2", "{\"ckycNo\":\"1001\"}"));
        recorded.add(post("https://dev.example/ckyc-api-gateway/ckycBackend/master/getAllMaster", "{}"));
        // These MUST be ignored by the guard - if the engine ever re-sent them the fake records it.
        recorded.add(post("https://dev.example/ckyc-api-gateway/ckycBackend/dvs-V2/approveRejectCustomerV2", "{\"ckycNo\":\"1001\"}"));
        recorded.add(post("https://dev.example/ckyc-api-gateway/ckycBackend/dvs-V2/updateCustomerDetailsV2", "{\"ckycNo\":\"1001\"}"));
        // Out-of-scope host must never be contacted.
        recorded.add(post("https://evil.example/ckyc-api-gateway/ckycBackend/master/getAllMaster", "{}"));

        ActiveTestGate.Authorization auth = ActiveTestGate.authorize(config("DEV"), options(), REF);
        ActiveChecks checks = new ActiveChecks(auth, fake, options()).run(recorded);

        assertTrue(sentStateChanging.isEmpty(), "engine re-sent a state-changing call: " + sentStateChanging);

        ActiveCheckReport rep = ActiveCheckReport.build("CKYC-7.0", auth, checks);
        assertTrue(rep.confirmed() >= 1, "getAllMaster with no auth should be CONFIRMED");
        boolean masterConfirmed = rep.findings.stream().anyMatch(f ->
                f.endpoint.endsWith("/getAllMaster") && f.status.equals(ActiveChecks.CONFIRMED));
        boolean customerSecure = rep.findings.stream().anyMatch(f ->
                f.endpoint.endsWith("/getCustomerDetailsV2") && f.status.equals(ActiveChecks.SECURE));
        assertTrue(masterConfirmed, "unauth getAllMaster confirmed");
        assertTrue(customerSecure, "customer details correctly denied without auth");
        assertFalse(rep.findings.stream().anyMatch(f -> f.endpoint.contains("evil.example")), "out-of-scope never tested");

        Path dir = Path.of("target", "active-unit");
        String all = Files.readString(rep.writeHtml(dir, "t")) + Files.readString(rep.writeCsv(dir, "t"))
                + Files.readString(rep.writeJson(dir, "t"));
        assertTrue(all.contains(REF), "report records the approval reference");
        assertTrue(all.contains("READ-ONLY"), "report states the read-only guarantee");
    }

    @Test
    public void engineRefusesWithoutGate() {
        assertThrows(SecurityException.class, () -> new ActiveChecks(null, req -> new ActiveResponse(200, "", false), options()));
    }

    private static RecordedCall post(String url, String body) {
        RecordedCall c = new RecordedCall("POST", url);
        c.plainBody = body;
        c.wasEncrypted = true;
        return c;
    }
}
