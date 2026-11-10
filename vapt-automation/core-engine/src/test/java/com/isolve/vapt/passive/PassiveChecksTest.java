package com.isolve.vapt.passive;

import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

/** Phase 5 passive checks on synthetic observations (fake values only). No network. */
public class PassiveChecksTest {

    private static final List<String> FAKE_VALUES = List.of(
            "ABCPE1234F", "234567890123", "9876543210", "test.user@example.com", "FAKE-COOKIE-1",
            "FAKE-PW-77", "10.20.30.40", "otpvalue-42");

    private static PassiveObservation obs(String method, String url, String type, int status, String ct, String body,
                                          String... headers) {
        PassiveObservation o = new PassiveObservation();
        o.method = method;
        o.url = url;
        o.resourceType = type;
        o.status = status;
        o.responseContentType = ct;
        o.responseBody = body;
        for (int i = 0; i + 1 < headers.length; i += 2) o.responseHeaders.add(new String[]{headers[i], headers[i + 1]});
        int q = url.indexOf('?');
        if (q >= 0) {
            o.rawQuery = url.substring(q + 1);
            for (String p : o.rawQuery.split("&")) o.queryParamNames.add(p.split("=")[0]);
        }
        return o;
    }

    private static Map<String, PassiveChecks.Result> run(PassiveChecks pc) {
        return pc.results().stream().collect(Collectors.toMap(r -> r.id, r -> r));
    }

    @Test
    public void detectsLeadsAndKeepsNoValues() throws Exception {
        PassiveChecks pc = new PassiveChecks();

        PassiveObservation page = obs("GET", "https://dev.example/app/home", "document", 200, "text/html", "<html>ok</html>",
                "Server", "Apache/2.4.1 (Unix)", "Set-Cookie", "JSESSIONID=FAKE-COOKIE-1; Path=/");
        page.tlsProtocol = "TLS 1.1";
        page.certValidToEpochSec = Instant.now().getEpochSecond() + 10 * 86_400L;
        pc.observe(page);

        String json = "{\"statusCode\":500,\"responseObject\":{\"customer\":{\"panNo\":\"ABCPE1234F\",\"aadhaarNo\":\"234567890123\","
                + "\"mobileNo\":\"9876543210\",\"email\":\"test.user@example.com\",\"maskedPan\":\"XXXXX1234X\","
                + "\"userPassword\":\"FAKE-PW-77\",\"id\":1234567890},"
                + "\"error\":\"com.sun.mail.util.MailConnectException: Couldn't connect to host 10.20.30.40\"}}";
        pc.observe(obs("POST", "https://dev.example/api/customer/1001/details", "fetch", 500, "application/json", json,
                "Content-Type", "application/json", "Access-Control-Allow-Origin", "*"));

        pc.observe(obs("GET", "https://dev.example/api/verify?otp=otpvalue-42&page=1", "xhr", 200, "application/json",
                "{\"ok\":true}", "Cache-Control", "no-store", "X-Content-Type-Options", "nosniff"));

        pc.observe(obs("GET", "https://dev.example/app/secure", "document", 200, "text/html", "<html>ok</html>",
                "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'", "X-Frame-Options", "DENY",
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains", "X-Content-Type-Options", "nosniff",
                "Set-Cookie", "XSRF=abc; Secure; HttpOnly; SameSite=Strict"));
        pc.observeSubresource("https://dev.example/app/home", "http://cdn.example/lib.js");

        Map<String, PassiveChecks.Result> r = run(pc);
        assertEquals(r.get("P5-H01").status, PassiveChecks.LEAD, "CSP missing on /app/home");
        assertEquals(r.get("P5-H01").hits, 1, "only the page without CSP");
        assertEquals(r.get("P5-H02").hits, 1);
        assertEquals(r.get("P5-H05").status, PassiveChecks.LEAD);
        assertEquals(r.get("P5-H06").status, PassiveChecks.OK, "only 2xx API responses are checked; /api/verify has no-store");
        assertEquals(r.get("P5-H07").hits, 0, "ACAO * was on a 500 response, which is not checked");
        assertTrue(r.get("P5-C01").names.contains("JSESSIONID"));
        assertFalse(r.get("P5-C01").names.contains("XSRF"), "fully flagged cookie is fine");
        assertTrue(r.get("P5-D01").names.contains("responseObject.customer.panNo"));
        assertTrue(r.get("P5-D01").names.contains("responseObject.customer.aadhaarNo"));
        assertTrue(r.get("P5-D01").names.contains("responseObject.customer.mobileNo"));
        assertTrue(r.get("P5-D01").names.contains("responseObject.customer.email"));
        assertFalse(r.get("P5-D01").names.contains("responseObject.customer.id"), "plain numeric id is not personal data");
        assertTrue(r.get("P5-D01").reasons.containsKey("masked PAN (good)"));
        assertTrue(r.get("P5-D02").names.contains("responseObject.customer.userPassword"));
        assertTrue(r.get("P5-D03").names.contains("?otp"));
        assertTrue(r.get("P5-E01").reasons.containsKey("exception class name"), r.get("P5-E01").reasons.toString());
        assertTrue(r.get("P5-E01").reasons.containsKey("internal IP address"));
        assertEquals(r.get("P5-E02").hits, 1);
        assertEquals(r.get("P5-T02").status, PassiveChecks.LEAD, "TLS 1.1");
        assertEquals(r.get("P5-T03").status, PassiveChecks.LEAD, "cert expires in 10 days");
        assertEquals(r.get("P5-T04").status, PassiveChecks.LEAD, "mixed content");
        assertEquals(r.get("P5-T01").status, PassiveChecks.OK, "all https");

        PassiveCheckReport rep = PassiveCheckReport.build("UNIT", "synthetic", List.of("dev.example"), pc);
        Path dir = Path.of("target", "passive-unit");
        String all = Files.readString(rep.writeHtml(dir, "t")) + Files.readString(rep.writeCsv(dir, "t"))
                + Files.readString(rep.writeJson(dir, "t"));
        for (String v : FAKE_VALUES) assertFalse(all.contains(v), v + " leaked into the report");
        assertTrue(all.indexOf("P5-H01") < all.indexOf("P5-T01"), "leads listed before checks with no issue");
    }

    @Test
    public void proxiedTrafficMarksTlsNotChecked() {
        PassiveChecks pc = new PassiveChecks();
        PassiveObservation o = obs("GET", "https://dev.example/", "document", 200, "text/html", "<html></html>");
        o.viaProxy = true;
        o.tlsProtocol = "TLS 1.3";
        pc.observe(o);
        Map<String, PassiveChecks.Result> r = run(pc);
        assertEquals(r.get("P5-T02").status, PassiveChecks.NOT_CHECKED);
        assertTrue(r.get("P5-T02").note.contains("proxy"));
    }

    @Test
    public void classifierAvoidsCommonFalsePositives() {
        assertNull(SensitiveData.classify("companyName", "ABCDE1234F".toLowerCase()));
        assertNull(SensitiveData.classify("requestId", "9876543210"), "10 digits without a phone field name");
        assertNull(SensitiveData.classify("count", "123456789012"), "12 digits failing Verhoeff, no aadhaar name");
        assertEquals(SensitiveData.classify("pan", "ABCPE1234F").type(), SensitiveData.Type.PAN);
        assertEquals(SensitiveData.classify("cardNo", "4111111111111111").type(), SensitiveData.Type.CARD);
        assertTrue(SensitiveData.classify("aadhaarNumber", "XXXX XXXX 1234").masked());
        assertEquals(SensitiveData.classify("otp", "4321").type(), SensitiveData.Type.SECRET);
        assertNull(SensitiveData.classify("pinCode", "560001"), "postal PIN code is not a secret");
    }
}
