package com.isolve.vapt.passive;

import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.*;

/** P5-H01: CSP from the header AND &lt;meta http-equiv&gt; tags, combined the way browsers enforce them. */
public class CspCheckTest {

    private static PassiveChecks.Result h01(String header, String html) {
        PassiveChecks pc = new PassiveChecks();
        PassiveObservation o = new PassiveObservation();
        o.url = "https://dev.example/";
        o.resourceType = "document";
        o.status = 200;
        o.responseContentType = "text/html";
        o.responseBody = html;
        if (header != null) o.responseHeaders.add(new String[]{"Content-Security-Policy", header});
        pc.observe(o);
        return pc.results().stream().filter(r -> r.id.equals("P5-H01")).findFirst().orElseThrow();
    }

    @Test
    public void metaTagIsRead() {
        String html = "<html><head><meta charset='utf-8'>"
                + "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline'\">"
                + "</head><body></body></html>";
        PassiveChecks.Result r = h01("frame-ancestors 'none'", html);
        assertEquals(r.status, PassiveChecks.LEAD);
        String reasons = r.reasons.keySet().toString();
        assertTrue(reasons.contains("any source"), reasons);
        assertTrue(reasons.contains("script-src allows 'unsafe-inline'"), reasons);
        assertTrue(reasons.contains("style-src allows 'unsafe-inline'"), reasons);
        assertTrue(reasons.contains("no default-src fallback"), reasons);
        assertTrue(reasons.contains("header + meta tag"), reasons);
        assertEquals(r.hits, 1, "one page = one hit, several reasons");
    }

    @Test
    public void strictMetaOnlyPasses() {
        String html = "<head><meta content='default-src &#39;self&#39;' http-equiv='content-security-policy'/></head>";
        PassiveChecks.Result r = h01(null, html);
        assertEquals(r.status, PassiveChecks.OK, r.reasons.toString());
        assertTrue(r.passEvidence.get(0).contains("meta tag"));
    }

    @Test
    public void strictHeaderWinsOverWeakMeta() {
        String html = "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src * 'unsafe-inline' 'unsafe-eval'\">";
        PassiveChecks.Result r = h01("default-src 'self'", html);
        assertEquals(r.status, PassiveChecks.OK, "both policies apply, the strict header still blocks: " + r.reasons);
    }

    @Test
    public void nonceMakesUnsafeInlineIgnored() {
        assertTrue(PassiveChecks.cspWeaknesses(List.of("default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'")).isEmpty());
    }

    @Test
    public void noCspAtAll() {
        PassiveChecks.Result r = h01(null, "<html><head><meta name='viewport' content='width=device-width'></head></html>");
        assertEquals(r.status, PassiveChecks.LEAD);
        assertTrue(r.reasons.containsKey("missing"));
    }
}
