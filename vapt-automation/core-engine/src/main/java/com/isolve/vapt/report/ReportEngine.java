package com.isolve.vapt.report;

import com.isolve.vapt.util.MaskUtil;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates the three industry-standard deliverables from a List<FindingResult>:
 *   1. VAPT Report          (HTML — executive summary, findings detail, evidence)
 *   2. Retest Report        (HTML — only findings previously FAIL, re-executed)
 *   3. Closure Tracker      (XLSX — one row per finding, lifecycle status, sign-off columns)
 *
 * All text is run through MaskUtil before being written, so request/response evidence
 * in a report can never leak a live secret even if the report is shared.
 */
public final class ReportEngine {

    public File generateVaptReportHtml(String projectName, String environment,
                                        List<FindingResult> results, File outDir) throws IOException {
        Files.createDirectories(outDir.toPath());
        File out = new File(outDir, projectName + "_VAPT_Report_" + LocalDate.now() + ".html");

        Map<FindingResult.Status, Long> counts = results.stream()
                .collect(Collectors.groupingBy(FindingResult::getStatus, Collectors.counting()));
        Map<String, Long> bySeverity = results.stream()
                .filter(r -> r.getStatus() == FindingResult.Status.FAIL)
                .collect(Collectors.groupingBy(r -> r.getSeverity() == null ? "Unknown" : r.getSeverity(), Collectors.counting()));

        StringBuilder html = new StringBuilder();
        html.append("<html><head><meta charset='utf-8'><title>VAPT Report - ").append(esc(projectName)).append("</title>")
            .append(style()).append("</head><body>");
        html.append("<h1>Authorized VAPT / Security Regression Report</h1>");
        html.append("<table class='meta'>")
            .append(row("Project", projectName)).append(row("Environment", environment))
            .append(row("Report Date", LocalDate.now().toString()))
            .append(row("Total Checks Executed", String.valueOf(results.size())))
            .append("</table>");

        html.append("<h2>Executive Summary</h2><table class='summary'><tr><th>Status</th><th>Count</th></tr>");
        for (FindingResult.Status s : FindingResult.Status.values()) {
            html.append("<tr><td>").append(s).append("</td><td>").append(counts.getOrDefault(s, 0L)).append("</td></tr>");
        }
        html.append("</table>");

        html.append("<h2>Findings by Severity (FAIL only)</h2><table class='summary'><tr><th>Severity</th><th>Count</th></tr>");
        for (Map.Entry<String, Long> e : bySeverity.entrySet()) {
            html.append("<tr><td>").append(esc(e.getKey())).append("</td><td>").append(e.getValue()).append("</td></tr>");
        }
        html.append("</table>");

        html.append("<h2>Detailed Findings</h2><table class='findings'>");
        html.append("<tr><th>ID</th><th>Title</th><th>Module</th><th>Severity</th><th>CWE</th>")
            .append("<th>Status</th><th>Endpoint/Page</th><th>Role</th><th>Expected</th><th>Actual</th>")
            .append("<th>Evidence</th></tr>");
        for (FindingResult r : results) {
            html.append("<tr class='").append(r.getStatus() == FindingResult.Status.FAIL ? "fail" : "ok").append("'>")
                .append("<td>").append(esc(r.getFindingId())).append("</td>")
                .append("<td>").append(esc(r.getTitle())).append("</td>")
                .append("<td>").append(esc(r.getModule())).append("</td>")
                .append("<td>").append(esc(r.getSeverity())).append("</td>")
                .append("<td>").append(esc(r.getCweScore())).append("</td>")
                .append("<td>").append(r.getStatus()).append("</td>")
                .append("<td>").append(esc(r.getEndpointOrPage())).append("</td>")
                .append("<td>").append(esc(r.getRole())).append("</td>")
                .append("<td>").append(esc(r.getExpected())).append("</td>")
                .append("<td>").append(esc(r.getActual())).append("</td>")
                .append("<td>").append(evidenceLinks(r)).append("</td>")
                .append("</tr>");
        }
        html.append("</table></body></html>");

        Files.writeString(out.toPath(), html.toString());
        return out;
    }

    public File generateRetestReportHtml(String projectName, String environment,
                                          List<FindingResult> originalFailures,
                                          List<FindingResult> retestResults, File outDir) throws IOException {
        Files.createDirectories(outDir.toPath());
        File out = new File(outDir, projectName + "_Retest_Report_" + LocalDate.now() + ".html");

        StringBuilder html = new StringBuilder();
        html.append("<html><head><meta charset='utf-8'><title>Retest Report</title>").append(style()).append("</head><body>");
        html.append("<h1>Retest / Closure Verification Report</h1>");
        html.append("<table class='meta'>").append(row("Project", projectName)).append(row("Environment", environment))
            .append(row("Retest Date", LocalDate.now().toString())).append("</table>");

        html.append("<table class='findings'><tr><th>ID</th><th>Title</th><th>Original Status</th>")
            .append("<th>Retest Status</th><th>Verdict</th><th>Evidence</th></tr>");

        Map<String, FindingResult> retestById = retestResults.stream()
                .collect(Collectors.toMap(FindingResult::getFindingId, r -> r, (a, b) -> a));

        for (FindingResult original : originalFailures) {
            FindingResult retest = retestById.get(original.getFindingId());
            String verdict = retest == null ? "NOT RETESTED"
                    : retest.getStatus() == FindingResult.Status.PASS ? "CLOSED - FIX VERIFIED" : "REOPENED - STILL FAILING";
            html.append("<tr class='").append(verdict.startsWith("CLOSED") ? "ok" : "fail").append("'>")
                .append("<td>").append(esc(original.getFindingId())).append("</td>")
                .append("<td>").append(esc(original.getTitle())).append("</td>")
                .append("<td>").append(original.getStatus()).append("</td>")
                .append("<td>").append(retest == null ? "-" : retest.getStatus()).append("</td>")
                .append("<td>").append(verdict).append("</td>")
                .append("<td>").append(retest == null ? "" : evidenceLinks(retest)).append("</td>")
                .append("</tr>");
        }
        html.append("</table></body></html>");
        Files.writeString(out.toPath(), html.toString());
        return out;
    }

    public File generateClosureTrackerXlsx(String projectName, List<FindingResult> results, File outDir) throws IOException {
        Files.createDirectories(outDir.toPath());
        File out = new File(outDir, projectName + "_Closure_Tracker_" + LocalDate.now() + ".xlsx");

        try (Workbook wb = new XSSFWorkbook()) {
            Sheet sheet = wb.createSheet("Closure Tracker");
            String[] headers = {"Finding ID", "Title", "Severity", "CWE", "Module", "Status",
                    "First Raised Date", "Fix Deployed Date", "Retest Date", "Retested By",
                    "Closure Status", "Sign-off By", "Sign-off Date", "Remarks"};
            Row headerRow = sheet.createRow(0);
            CellStyle headerStyle = wb.createCellStyle();
            Font bold = wb.createFont();
            bold.setBold(true);
            headerStyle.setFont(bold);
            for (int i = 0; i < headers.length; i++) {
                Cell c = headerRow.createCell(i);
                c.setCellValue(headers[i]);
                c.setCellStyle(headerStyle);
            }

            int rowNum = 1;
            for (FindingResult r : results) {
                Row row = sheet.createRow(rowNum++);
                row.createCell(0).setCellValue(r.getFindingId());
                row.createCell(1).setCellValue(nullToEmpty(r.getTitle()));
                row.createCell(2).setCellValue(nullToEmpty(r.getSeverity()));
                row.createCell(3).setCellValue(nullToEmpty(r.getCweScore()));
                row.createCell(4).setCellValue(nullToEmpty(r.getModule()));
                row.createCell(5).setCellValue(r.getStatus() == null ? "" : r.getStatus().toString());
                row.createCell(6).setCellValue(nullToEmpty(r.getFirstRaisedDate()));
                row.createCell(7).setCellValue(""); // filled by dev/release team
                row.createCell(8).setCellValue(nullToEmpty(r.getRetestDate()));
                row.createCell(9).setCellValue(nullToEmpty(r.getExecutedBy()));
                row.createCell(10).setCellValue(nullToEmpty(r.getClosureStatus() == null ? "OPEN" : r.getClosureStatus()));
                row.createCell(11).setCellValue(""); // sign-off by (QA/Security lead) - manual
                row.createCell(12).setCellValue(""); // sign-off date - manual
                row.createCell(13).setCellValue(nullToEmpty(r.getNotes()));
            }
            for (int i = 0; i < headers.length; i++) sheet.autoSizeColumn(i);

            try (FileOutputStream fos = new FileOutputStream(out)) {
                wb.write(fos);
            }
        }
        return out;
    }

    private String evidenceLinks(FindingResult r) {
        if (r.getEvidencePaths() == null || r.getEvidencePaths().isEmpty()) return "-";
        return r.getEvidencePaths().stream().map(p -> "<a href='" + esc(p) + "'>evidence</a>")
                .collect(Collectors.joining(", "));
    }

    private String row(String k, String v) { return "<tr><td><b>" + esc(k) + "</b></td><td>" + esc(v) + "</td></tr>"; }
    private String esc(Object o) {
        if (o == null) return "";
        return MaskUtil.mask(String.valueOf(o)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
    private String nullToEmpty(Object o) { return o == null ? "" : MaskUtil.mask(String.valueOf(o)); }

    private String style() {
        return "<style>"
            + "body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1a1a1a}"
            + "h1{color:#0b3d91} h2{color:#0b3d91;border-bottom:2px solid #0b3d91}"
            + "table{border-collapse:collapse;width:100%;margin-bottom:20px}"
            + "table.meta td{padding:4px 10px}"
            + "th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;text-align:left}"
            + "th{background:#0b3d91;color:#fff}"
            + "tr.fail{background:#fdecea}"
            + "tr.ok{background:#eafaf1}"
            + "</style>";
    }
}
