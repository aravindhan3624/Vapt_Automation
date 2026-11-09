package com.isolve.vapt.zap;

import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.testng.Assert.*;

/** Report building and redaction, no ZAP needed. */
public class PassiveAnalysisReportTest {

    private static ZapAlert alert(String id, String name, String risk, String url, String evidence) {
        ZapAlert a = new ZapAlert();
        a.pluginId = id;
        a.name = name;
        a.risk = risk;
        a.confidence = "Medium";
        a.url = url;
        a.method = "GET";
        a.evidence = evidence;
        a.cweId = "693";
        return a;
    }

    @Test
    public void groupsSortsMapsAndRedacts() throws Exception {
        List<ZapAlert> alerts = List.of(
                alert("10010", "Cookie No HttpOnly Flag", "Low", "https://dev.example/app?sid=SECRETQ1", "Set-Cookie: JSESSIONID=ABCDEF123456"),
                alert("10038", "Content Security Policy (CSP) Header Not Set", "Medium", "https://dev.example/app", ""),
                alert("10038", "Content Security Policy (CSP) Header Not Set", "Medium", "https://dev.example/home", ""),
                alert("99999", "Unmapped rule", "Informational", "https://dev.example/x",
                        "token=abcd1234efgh eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"));
        PassiveAnalysisReport r = PassiveAnalysisReport.build("T", "unit", List.of("dev.example"), 4, alerts);

        assertEquals(r.leads.size(), 3);
        assertEquals(r.leads.get(0).pluginId, "10038", "Medium first");
        assertEquals(r.leads.get(0).occurrences, 2);
        assertEquals(r.leads.get(0).checklistIds, List.of("VAPT-010"));
        assertFalse(r.leads.get(0).checklistTitles.get(0).isBlank(), "checklist title from catalog");
        assertTrue(r.leads.get(2).checklistIds.isEmpty(), "unmapped rule still listed");
        assertTrue(r.leads.stream().allMatch(l -> l.status.equals("To verify")));

        Path dir = Path.of("target", "report-unit");
        String all = Files.readString(r.writeHtml(dir, "t")) + Files.readString(r.writeCsv(dir, "t")) + Files.readString(r.writeJson(dir, "t"));
        for (String secret : List.of("SECRETQ1", "ABCDEF123456", "abcd1234efgh", "eyJhbGciOiJIUzI1NiJ9")) {
            assertFalse(all.contains(secret), secret + " leaked");
        }
        assertTrue(all.contains("https://dev.example/app?sid"), "query NAME kept, value dropped");
    }

    @Test
    public void longUrlPathsSurviveScrub() {
        String u = "https://dev.example/api/v1/customer/details/getCustomerAddressDetailsByCustomerId";
        assertEquals(PassiveAnalysisReport.safeUrl(u), u);
    }
}
