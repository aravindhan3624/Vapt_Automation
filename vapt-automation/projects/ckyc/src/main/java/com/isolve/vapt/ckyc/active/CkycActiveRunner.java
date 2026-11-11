package com.isolve.vapt.ckyc.active;

import com.isolve.vapt.active.ActiveCheckReport;
import com.isolve.vapt.active.ActiveCheckType;
import com.isolve.vapt.active.ActiveChecks;
import com.isolve.vapt.active.ActiveRunOptions;
import com.isolve.vapt.active.ActiveTestGate;
import com.isolve.vapt.active.CaptureCallLoader;
import com.isolve.vapt.active.HttpActiveTarget;
import com.isolve.vapt.active.RecordedCall;
import com.isolve.vapt.active.ResponseAdapter;
import com.isolve.vapt.config.ConfigLoader;
import com.isolve.vapt.config.ProjectConfig;
import com.isolve.vapt.crypto.EnvelopeCrypto;

import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Phase 6 runner for CKYC 7.0. Same gate, guard and read-only checks as the generic runner, but
 * wired to CKYC's request/response encryption so the checks also work on the encrypted API
 * endpoints: the engine builds a plain (possibly id-swapped) body, this bridge re-encrypts it into
 * the CKYC envelope, sends it, and decrypts the reply so the real HTTP/inner status is seen.
 *
 * Still read-only: it only re-sends calls the tester already made, with the authorization weakened.
 * The CKYC server public key (public material) is read from VAPT_SERVER_PUBLIC_KEY (a PEM/base64
 * string or a file path). The session, for baseline comparison only, is read from
 * VAPT_SESSION_HEADER / VAPT_SESSION_VALUE and never stored.
 */
public final class CkycActiveRunner {

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
        ProjectConfig config = ConfigLoader.load(new File(configPath));     // enforces scope + non-PROD
        if (checks.isEmpty()) checks.add(ActiveCheckType.UNAUTH_DOCUMENT_ACCESS);
        if (hosts.isEmpty() && config.getApiBaseUrl() != null) hosts.add(hostOf(config.getApiBaseUrl()));

        boolean needsCrypto = checks.stream().anyMatch(c ->
                c == ActiveCheckType.UNAUTHENTICATED_ACCESS || c == ActiveCheckType.IDOR_BOLA || c == ActiveCheckType.JWT_TAMPER);
        String serverKey = resolveServerKey(env("VAPT_SERVER_PUBLIC_KEY"));
        if (needsCrypto && serverKey == null) {
            System.err.println("The checks " + checks + " re-send encrypted API calls, so the CKYC server public key is needed.");
            System.err.println("Set VAPT_SERVER_PUBLIC_KEY to the app's RSA public key (PEM/base64) or a file path, or run only");
            System.err.println("UNAUTH_DOCUMENT_ACCESS (documents are not encrypted).");
            System.exit(3);
            return;
        }

        ActiveRunOptions o = new ActiveRunOptions();
        o.confirmedActiveTesting = true;
        o.approvalReference = approval;
        o.approvedHosts = hosts;
        o.enabledChecks = checks;
        o.otherObjectIds = otherIds;
        o.delayBetweenRequestsMs = delay;
        o.maxRequests = max;

        System.out.println("Phase 6 active checks (CKYC) - READ-ONLY re-sends only (no create/update/approve/delete/submit).");
        System.out.println("  Project : " + config.getProjectName() + "   Env: " + config.getEnvironment());
        System.out.println("  Hosts   : " + hosts + "   Checks: " + checks);
        System.out.println("  Crypto  : " + (serverKey != null ? "envelope bridge ON (encrypted API checks enabled)" : "documents only"));
        System.out.println("  Pacing  : " + delay + " ms between requests, max " + max);

        ActiveTestGate.Authorization auth;
        try {
            auth = ActiveTestGate.authorize(config, o);
        } catch (SecurityException e) {
            System.err.println("\nREFUSED by the safety gate: " + e.getMessage());
            System.err.println("Active checks did not run. Nothing was sent to the target.");
            System.exit(2);
            return;
        }

        String sessHeader = orDefault(env("VAPT_SESSION_HEADER"), "Cookie");
        String sessValue = env("VAPT_SESSION_VALUE");

        HttpActiveTarget.BodyCipher cipher = null;
        ResponseAdapter adapter = null;
        if (serverKey != null) {
            EnvelopeCrypto envelope = new EnvelopeCrypto(serverKey);    // one session key pair for this run
            cipher = CkycEnvelopeBridge.bodyCipher(envelope);
            adapter = CkycEnvelopeBridge.responseAdapter(envelope);
        }
        HttpActiveTarget target = new HttpActiveTarget(sessHeader, sessValue, null, cipher, adapter);

        List<RecordedCall> recorded = CaptureCallLoader.load(Path.of(capturePath));
        ActiveChecks engine = new ActiveChecks(auth, target, o).run(recorded);
        ActiveCheckReport report = ActiveCheckReport.build(config.getProjectName(), auth, engine);

        Path dir = out.isBlank() ? Path.of("C:\\captures", config.getProjectName()) : Path.of(out);
        String base = config.getProjectName().replaceAll("[^A-Za-z0-9._-]", "_") + "-active-"
                + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        Path html = report.writeHtml(dir, base);
        report.writeCsv(dir, base);
        report.writeJson(dir, base);

        System.out.println("\nRequests sent: " + engine.requestsSent() + "   Confirmed: " + report.confirmed()
                + "   " + report.byStatus);
        System.out.println("Report: " + html);
        if (!engine.skippedNotes().isEmpty()) System.out.println("Not run: " + engine.skippedNotes());
    }



    private static String resolveServerKey(String raw) throws Exception {
        if (raw == null || raw.isBlank()) return null;
        Path p = Path.of(raw);
        if (Files.isRegularFile(p)) return Files.readString(p);
        return raw;       // treat as inline PEM/base64
    }

    private static String hostOf(String url) {
        URI u = URI.create(url);
        return u.getPort() > 0 ? u.getHost() + ":" + u.getPort() : u.getHost();
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return v == null ? "" : v;
    }

    private static String orDefault(String v, String def) {
        return v == null || v.isBlank() ? def : v;
    }

    private static List<String> split(String s) {
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).toList();
    }
}
