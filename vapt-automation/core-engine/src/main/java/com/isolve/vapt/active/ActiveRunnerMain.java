package com.isolve.vapt.active;

import com.isolve.vapt.config.ConfigLoader;
import com.isolve.vapt.config.ProjectConfig;

import java.net.URI;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Phase 6 runner. Loads the project config (which must pass the scope / non-PROD guardrails), the
 * recorder capture, builds the run options, passes {@link ActiveTestGate}, runs the READ-ONLY
 * active checks and writes the report.
 *
 * The session for the tester's CURRENT requests is read from environment variables
 * {@code VAPT_SESSION_HEADER} (e.g. "Cookie") and {@code VAPT_SESSION_VALUE} - never a command-line
 * flag and never stored. {@code VAPT_ACTIVE_APPROVAL} must equal the approval reference.
 *
 *   ActiveRunnerMain --config config/ckyc-config.yaml --capture C:\captures\CKYC-7.0\x.capture.jsonl
 *                    --approval ISOLVE-... [--hosts h1,h2] [--checks UNAUTH_DOCUMENT_ACCESS]
 *                    [--other-ids 999,888] [--out C:\captures\CKYC-7.0] [--delay-ms 1000] [--max 200]
 */
public final class ActiveRunnerMain {

    public static void main(String[] args) throws Exception {
        String configPath = null, capturePath = null, approval = "", out = "";
        List<String> hosts = new ArrayList<>();
        List<String> otherIds = new ArrayList<>();
        List<ActiveCheckType> checks = new ArrayList<>();
        long delay = 1_000;
        int max = 200;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> configPath = args[++i];
                case "--capture" -> capturePath = args[++i];
                case "--approval" -> approval = args[++i];
                case "--hosts" -> hosts.addAll(split(args[++i]));
                case "--other-ids" -> otherIds.addAll(split(args[++i]));
                case "--checks" -> split(args[++i]).forEach(s -> checks.add(ActiveCheckType.valueOf(s.trim().toUpperCase())));
                case "--out" -> out = args[++i];
                case "--delay-ms" -> delay = Long.parseLong(args[++i]);
                case "--max" -> max = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        if (configPath == null || capturePath == null) {
            throw new IllegalArgumentException("--config and --capture are required");
        }
        ProjectConfig config = ConfigLoader.load(new java.io.File(configPath));   // enforces scope + non-PROD
        if (checks.isEmpty()) checks.add(ActiveCheckType.UNAUTH_DOCUMENT_ACCESS);  // safe default
        if (hosts.isEmpty() && config.getApiBaseUrl() != null) hosts.add(hostOf(config.getApiBaseUrl()));

        ActiveRunOptions o = new ActiveRunOptions();
        o.confirmedActiveTesting = true;      // running this tool IS the confirmation; the gate still checks everything else
        o.approvalReference = approval;
        o.approvedHosts = hosts;
        o.enabledChecks = checks;
        o.otherObjectIds = otherIds;
        o.delayBetweenRequestsMs = delay;
        o.maxRequests = max;

        System.out.println("Phase 6 active checks - READ-ONLY re-sends only (no create/update/approve/delete/submit).");
        System.out.println("  Project : " + config.getProjectName() + "   Env: " + config.getEnvironment());
        System.out.println("  Hosts   : " + hosts);
        System.out.println("  Checks  : " + checks);
        System.out.println("  Pacing  : " + delay + " ms between requests, max " + max + " requests");

        ActiveTestGate.Authorization auth;
        try {
            auth = ActiveTestGate.authorize(config, o);   // throws unless everything is in place
        } catch (SecurityException e) {
            System.err.println();
            System.err.println("REFUSED by the safety gate: " + e.getMessage());
            System.err.println("Active checks did not run. Nothing was sent to the target.");
            System.exit(2);
            return;
        }

        String sessHeader = env("VAPT_SESSION_HEADER");
        String sessValue = env("VAPT_SESSION_VALUE");
        if ((sessValue == null || sessValue.isBlank())
                && checks.stream().anyMatch(c -> c != ActiveCheckType.UNAUTH_DOCUMENT_ACCESS
                        && c != ActiveCheckType.UNAUTHENTICATED_ACCESS)) {
            System.out.println("  Note    : no VAPT_SESSION_VALUE set; baseline comparisons use no session.");
        }
        HttpActiveTarget target = new HttpActiveTarget(
                sessHeader == null || sessHeader.isBlank() ? "Cookie" : sessHeader, sessValue, null, null);

        List<RecordedCall> recorded = CaptureCallLoader.load(Path.of(capturePath));
        ActiveChecks engine = new ActiveChecks(auth, target, o).run(recorded);
        ActiveCheckReport report = ActiveCheckReport.build(config.getProjectName(), auth, engine);

        Path dir = out.isBlank() ? Path.of("C:\\captures", config.getProjectName()) : Path.of(out);
        String base = config.getProjectName().replaceAll("[^A-Za-z0-9._-]", "_") + "-active-"
                + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        Path html = report.writeHtml(dir, base);
        report.writeCsv(dir, base);
        report.writeJson(dir, base);

        System.out.println();
        System.out.println("Requests sent: " + engine.requestsSent() + "   Confirmed: " + report.confirmed()
                + "   " + report.byStatus);
        System.out.println("Report: " + html);
        if (!engine.skippedNotes().isEmpty()) {
            System.out.println("Not run: " + engine.skippedNotes());
        }
    }

    private static String hostOf(String url) {
        URI u = URI.create(url);
        return u.getPort() > 0 ? u.getHost() + ":" + u.getPort() : u.getHost();
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return v == null ? "" : v;
    }

    private static List<String> split(String s) {
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).toList();
    }
}
