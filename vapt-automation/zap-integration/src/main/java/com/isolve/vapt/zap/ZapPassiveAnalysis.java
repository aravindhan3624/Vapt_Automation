package com.isolve.vapt.zap;

import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Phase 4: ZAP passive analysis. Two ways to feed ZAP, both passive:
 *  - live: the recorder routes the tester's own browser through the local ZAP proxy
 *    (see the recorder's --zap option); ZAP only watches that traffic;
 *  - offline: {@link #analyzeHar} imports an exported HAR file; nothing is sent anywhere.
 * There is no spider and no active scan here.
 *
 * CLI (offline):
 *   ZapPassiveAnalysis --project CKYC-7.0 --hosts dev-host --har C:\captures\walk.har[,more.har]
 *                      [--out C:\captures\CKYC-7.0] [--zap-dir C:\Tools\ZAP_2.17.0] [--zap-home C:\Tools\zap-home]
 */
public final class ZapPassiveAnalysis {

    public static final Path DEFAULT_ZAP_DIR = Path.of("C:\\Tools\\ZAP_2.17.0");
    public static final Path DEFAULT_ZAP_HOME = Path.of("C:\\Tools\\zap-home");
    public static final Duration START_TIMEOUT = Duration.ofSeconds(240);
    public static final Duration PASSIVE_TIMEOUT = Duration.ofMinutes(10);

    /** Paths and counts of one passive-analysis run. */
    public static final class Result {
        public int messagesRecorded;
        public int alerts;
        public int leads;
        public int high;
        public int medium;
        public int low;
        public int informational;
        public Path html;
        public Path csv;
        public Path json;

        @Override
        public String toString() {
            return leads + " leads (High " + high + ", Medium " + medium + ", Low " + low + ", Info " + informational
                    + ") from " + alerts + " in-scope alerts";
        }
    }

    private ZapPassiveAnalysis() {
    }

    /**
     * Waits for the passive scanner, reads in-scope alerts and writes the redacted report.
     * Used by the recorder (live) and by {@link #analyzeHar} (offline).
     */
    public static Result finish(ZapPassiveSession session, String project, String source, Path outDir,
                                String baseName, List<String> extraNotes) throws Exception {
        session.waitForPassiveScan(PASSIVE_TIMEOUT);
        List<ZapAlert> alerts = session.alerts();
        PassiveAnalysisReport report = PassiveAnalysisReport.build(project, source, session.approvedHosts(),
                session.messageCount(), alerts);
        if (extraNotes != null) extraNotes.forEach(report::addNote);
        Result r = new Result();
        r.messagesRecorded = report.messagesRecorded;
        r.alerts = report.alertCount;
        r.leads = report.leads.size();
        r.high = report.leadsByRisk.getOrDefault("High", 0);
        r.medium = report.leadsByRisk.getOrDefault("Medium", 0);
        r.low = report.leadsByRisk.getOrDefault("Low", 0);
        r.informational = report.leadsByRisk.getOrDefault("Informational", 0);
        r.html = report.writeHtml(outDir, baseName + "-zap-passive");
        r.csv = report.writeCsv(outDir, baseName + "-zap-passive");
        r.json = report.writeJson(outDir, baseName + "-zap-passive");
        return r;
    }

    /** Offline: imports HAR files into a fresh local ZAP and reports passive leads. Sends no requests. */
    public static Result analyzeHar(Path zapDir, Path zapHome, String project, List<String> approvedHosts,
                                    List<Path> harFiles, Path outDir) throws Exception {
        if (harFiles.isEmpty()) throw new IllegalArgumentException("No HAR file given");
        try (ZapDaemon zap = ZapDaemon.start(zapDir, zapHome, 0, START_TIMEOUT)) {
            ZapPassiveSession session = new ZapPassiveSession(zap, safe(project) + "-passive", approvedHosts);
            List<String> names = new ArrayList<>();
            for (Path har : harFiles) {
                session.importHar(har);
                names.add(har.getFileName().toString());
            }
            String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            return finish(session, project, "Imported HAR: " + String.join(", ", names), outDir,
                    safe(project) + "-har-" + stamp,
                    List.of("Imported from an exported file; ZAP did not contact the application."));
        }
    }

    public static void main(String[] args) throws Exception {
        String project = "PROJECT";
        List<String> hosts = new ArrayList<>();
        List<Path> hars = new ArrayList<>();
        String out = "";
        Path zapDir = DEFAULT_ZAP_DIR;
        Path zapHome = DEFAULT_ZAP_HOME;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project" -> project = args[++i];
                case "--hosts" -> hosts.addAll(split(args[++i]));
                case "--har" -> split(args[++i]).forEach(h -> hars.add(Path.of(h)));
                case "--out" -> out = args[++i];
                case "--zap-dir" -> zapDir = Path.of(args[++i]);
                case "--zap-home" -> zapHome = Path.of(args[++i]);
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        if (hosts.isEmpty()) throw new IllegalArgumentException("--hosts is required (approved host names only)");
        Path outDir = out.isBlank() ? Path.of("C:\\captures", project) : Path.of(out);

        System.out.println("ZAP passive analysis - offline HAR import (no requests are sent)");
        System.out.println("  Project : " + project);
        System.out.println("  Hosts   : " + hosts);
        System.out.println("  HAR     : " + hars);
        System.out.println("Starting local ZAP (about a minute)...");
        Result r = analyzeHar(zapDir, zapHome, project, hosts, hars, outDir);
        System.out.println("Passive analysis: " + r);
        System.out.println("Report (redacted): " + r.html);
        System.out.println("CSV              : " + r.csv);
    }

    private static List<String> split(String s) {
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).toList();
    }

    static String safe(String s) {
        return s == null ? "x" : s.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
