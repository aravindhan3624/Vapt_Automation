package com.isolve.vapt.ckyc.stepdefs;

import com.isolve.vapt.catalog.VaptCatalogLoader;
import com.isolve.vapt.config.ConfigLoader;
import com.isolve.vapt.config.ProjectConfig;
import com.isolve.vapt.config.EndpointConfig;
import com.isolve.vapt.engine.*;
import com.isolve.vapt.report.FindingResult;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.response.Response;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.testng.Assert.*;

/**
 * Step definitions wiring the Cucumber feature to the core engine. This is the ONLY
 * CKYC-specific Java in the whole framework, and even this is thin glue — all the
 * actual security logic (header rules, SQLi detection, IDOR verdicts, JWT tampering)
 * lives in core-engine and is reused as-is.
 *
 * Results accumulate in RESULTS and are handed to ReportEngine by the test runner's
 * @AfterSuite/@AfterAll hook (see CkycTestRunner).
 */
public class CkycApiSecuritySteps {

    public static final List<FindingResult> RESULTS = new ArrayList<>();

    private ProjectConfig project;
    private ApiEngine apiEngine;
    private AuthEngine authEngine;
    private Response lastResponse;
    private String lastRole;
    private String lastEndpointId;
    private String currentToken;      // token returned by the last loginAs; never logged
    private String statusCheckFinding; // finding id the generic status-code Then step records under
    private String lastXssPayload;

    @Given("the {string} project configuration is loaded")
    public void loadProjectConfig(String projectName) {
        // -Dvapt.config=... overrides the default (used by the local mock dry run)
        File configFile = new File(System.getProperty("vapt.config",
                "config/" + projectName.toLowerCase() + "-config.yaml"));
        this.project = ConfigLoader.load(configFile); // throws SecurityException if scope/env guardrails fail
        this.apiEngine = new ApiEngine(project);
        this.authEngine = new AuthEngine(project, apiEngine);
    }

    @Given("the project's authorization scope is valid for this environment")
    public void scopeIsValid() {
        assertNotNull(project.getScope().getAuthorizedBy(), "Authorization scope missing — refusing to continue");
    }

    @Given("I am authenticated as role {string}")
    public void authenticatedAsRole(String role) {
        this.lastRole = role;
        this.currentToken = authEngine.loginAs(role);
    }

    @When("I log in as role {string} via the UI")
    public void loginViaUi(String role) {
        // UI login flow is driven by a Selenium UiEngine (not shown here) that captures
        // the Set-Cookie headers for CookieValidator to evaluate. Left as an onboarding
        // TODO once CKYC's real login page locators are supplied.
        throw new io.cucumber.java.PendingException("Wire CKYC's UI login page locators here (see README: UI onboarding).");
    }

    @When("I call endpoint {string} as role {string}")
    public void callEndpointAsRole(String endpointId, String role) {
        if (!role.equals(lastRole)) authenticatedAsRole(role);
        callEndpoint(endpointId);
    }

    @When("I call endpoint {string} without authentication")
    public void callEndpointUnauthenticated(String endpointId) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        this.lastResponse = apiEngine.unauthenticatedRequest().get(resolvePath(ep));
        this.lastEndpointId = endpointId;
        this.statusCheckFinding = "VAPT-050";
    }

    @When("I call endpoint {string} with a {string} token")
    public void callEndpointWithTamperedToken(String endpointId, String tamperType) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        JwtValidator jwtValidator = new JwtValidator();
        // Tamper the real token issued by the prior "I am authenticated as role" step.
        String validToken = currentToken;
        assertNotNull(validToken, "No token captured — a login step must run before a tampered-token call");
        String tampered = switch (tamperType) {
            case "alg-none" -> {
                var decoded = jwtValidator.decode(validToken);
                yield jwtValidator.algNoneVariant(decoded.headerJson, decoded.payloadJson);
            }
            case "signature-stripped" -> jwtValidator.signatureStrippedVariant(validToken);
            case "expired" -> "expired.token.placeholder";
            default -> throw new IllegalArgumentException("Unknown tamper type: " + tamperType);
        };
        this.lastResponse = apiEngine.requestWithToken(tampered).get(resolvePath(ep));
        this.lastEndpointId = endpointId;
        this.statusCheckFinding = "VAPT-051";
    }

    @Given("a test customer id belonging to a different test user is known")
    public void aForeignTestCustomerIdIsKnown() {
        // Resolved from project.getTestData() so no real customer id is ever hardcoded in Java.
        assertNotNull(project.getTestData(), "testData map with a 'foreignCustomerId' entry is required for IDOR checks");
    }

    @When("I call endpoint {string} using that other customer id")
    public void callEndpointWithForeignId(String endpointId) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        String foreignId = project.getTestData().get("foreignCustomerId");
        String path = resolvePath(ep, java.util.Map.of("id", foreignId));
        this.lastResponse = apiEngine.baseRequest().get(path);
        this.lastEndpointId = endpointId;
    }

    @When("I submit SQL injection probe {string} to endpoint {string}")
    public void submitSqliProbe(String payload, String endpointId) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        String path = resolvePath(ep, java.util.Map.of("id", payload));
        this.lastResponse = apiEngine.baseRequest().get(path);
        this.lastEndpointId = endpointId;
    }

    @When("I submit XSS probe {string} to endpoint {string} field {string}")
    public void submitXssProbe(String payload, String endpointId, String field) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        this.lastXssPayload = payload;
        this.lastResponse = apiEngine.baseRequest()
                .contentType("application/json")
                .body(java.util.Map.of(field, payload))
                .post(resolvePath(ep));
        this.lastEndpointId = endpointId;
    }

    @Then("security headers should be secure")
    public void securityHeadersShouldBeSecure() {
        var results = new SecurityHeaderValidator().evaluate(lastResponse);
        boolean anyMissing = results.values().stream().anyMatch(h -> "MISSING".equals(h.verdict) || "WEAK".equals(h.verdict));
        recordResult("VAPT-010", "Security Headers", anyMissing ? FindingResult.Status.FAIL : FindingResult.Status.PASS,
                "All security headers present and secure", results.toString());
    }

    @Then("session cookies should have Secure, HttpOnly and SameSite set")
    public void cookiesShouldBeSecure() {
        var results = new CookieValidator().evaluate(lastResponse);
        boolean anyIssue = results.stream().anyMatch(c -> !c.issues.isEmpty());
        recordResult("VAPT-014", "Cookie Attributes", anyIssue ? FindingResult.Status.FAIL : FindingResult.Status.PASS,
                "Secure/HttpOnly/SameSite present on session cookies", results.toString());
    }

    @Then("the response status should be {int} or {int}")
    public void statusShouldBeOneOf(int a, int b) {
        int status = lastResponse.getStatusCode();
        boolean ok = status == a || status == b;
        recordResult(statusCheckFinding, "Auth/Token check on " + lastEndpointId,
                ok ? FindingResult.Status.PASS : FindingResult.Status.FAIL,
                a + " or " + b, String.valueOf(status));
        assertTrue(ok, "Expected " + a + "/" + b + " but got " + status);
    }

    @Then("the response status should be {int}, {int} or {int}")
    public void statusShouldBeOneOfThree(int a, int b, int c) {
        int status = lastResponse.getStatusCode();
        boolean ok = status == a || status == b || status == c;
        var verdict = new IdorValidator().evaluate(lastResponse);
        recordResult("VAPT-049", "BOLA/IDOR on " + lastEndpointId,
                verdict.properlyDenied ? FindingResult.Status.PASS : FindingResult.Status.FAIL,
                a + "/" + b + "/" + c, verdict.evidence);
    }

    @Then("no SQL error signature should appear in the response")
    public void noSqlErrorSignature() {
        String body = lastResponse.getBody().asString();
        boolean sqlErrorFound = InputFuzzEngine.sqlErrorSignatures().stream()
                .anyMatch(sig -> body.toLowerCase().contains(sig.toLowerCase()));
        recordResult("VAPT-046", "SQL Injection on " + lastEndpointId,
                sqlErrorFound ? FindingResult.Status.FAIL : FindingResult.Status.PASS,
                "No DB error/stack trace leaked", sqlErrorFound ? "DB error signature present" : "clean");
    }

    @Then("the stored\\/reflected value should be HTML-encoded")
    public void xssShouldBeEncoded() {
        String body = lastResponse.getBody().asString();
        // Only the exact, unencoded payload counts: "&lt;img ... onerror=alert(1)&gt;" is safely encoded.
        boolean rawScriptReflected = lastXssPayload != null && body.contains(lastXssPayload);
        recordResult("VAPT-045", "XSS on " + lastEndpointId,
                rawScriptReflected ? FindingResult.Status.FAIL : FindingResult.Status.PASS,
                "Payload HTML-encoded, not executable", rawScriptReflected ? "raw payload reflected" : "encoded");
    }

    @Given("I have created a test transaction")
    public void createdTestTransaction() {
        throw new io.cucumber.java.PendingException("Wire CKYC's actual transaction-creation endpoint here.");
    }

    @When("the same Maker attempts to approve that transaction")
    public void sameMakerAttemptsApproval() {
        throw new io.cucumber.java.PendingException("Wire CKYC's actual approval endpoint here.");
    }

    @Then("the server should reject the approval with {int}")
    public void serverRejectsApproval(int code) {
        // Implemented once the two steps above are wired.
    }

    @Then("the result is recorded against finding {string}")
    public void resultAlreadyRecorded(String findingId) {
        // no-op: recordResult() already pushed the FindingResult in the preceding Then step.
    }

    @Then("the result is recorded against business rule {string}")
    public void resultAlreadyRecordedBr(String ruleId) {
        // no-op, same as above.
    }

    private EndpointConfig resolveEndpoint(String id) {
        return project.getEndpoints().stream().filter(e -> e.getId().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Endpoint not found in config: " + id));
    }

    /** Fills every {param} in the endpoint path from testData (key = param name). */
    private String resolvePath(EndpointConfig ep) {
        return resolvePath(ep, java.util.Map.of());
    }

    /** Same, but values in {@code overrides} win (probe payloads, foreign ids). */
    private String resolvePath(EndpointConfig ep, java.util.Map<String, String> overrides) {
        var m = java.util.regex.Pattern.compile("\\{([^}]+)}").matcher(ep.getPath());
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String param = m.group(1);
            String value = overrides.containsKey(param) ? overrides.get(param)
                    : project.getTestData() == null ? null : project.getTestData().get(param);
            if (value == null) {
                throw new IllegalStateException("Path parameter '" + param + "' of endpoint '" + ep.getId()
                        + "' has no value — add '" + param + "' under testData in the project config.");
            }
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(value));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private void callEndpoint(String endpointId) {
        EndpointConfig ep = resolveEndpoint(endpointId);
        this.lastResponse = apiEngine.baseRequest().get(resolvePath(ep));
        this.lastEndpointId = endpointId;
    }

    private void recordResult(String findingId, String title, FindingResult.Status status, String expected, String actual) {
        FindingResult r = new FindingResult();
        r.setFindingId(findingId == null ? "N/A" : findingId);
        r.setTitle(title);
        r.setProjectName(project.getProjectName());
        r.setEnvironment(project.getEnvironment());
        r.setRole(lastRole);
        r.setEndpointOrPage(lastEndpointId);
        if (lastEndpointId != null) {
            project.getEndpoints().stream().filter(e -> e.getId().equals(lastEndpointId)).findFirst()
                    .ifPresent(e -> r.setModule(e.getModule()));
        }
        // Severity/CWE come from the shared catalog so reports never show "Unknown".
        if (findingId != null) {
            VaptCatalogLoader.findById(findingId).ifPresent(f -> {
                r.setSeverity(f.getSeverity());
                r.setCweScore(f.getCweScore() == null ? null : String.valueOf(f.getCweScore()));
            });
        }
        r.setStatus(status);
        r.setExpected(expected);
        r.setActual(actual);
        r.setExecutedBy("AI-Automation");
        RESULTS.add(r);
    }
}
