package com.isolve.vapt.recorder;

import java.nio.file.Path;
import java.util.Arrays;

/**
 * Command-line entry for a live recording session.
 *
 *   RecorderMain --project CKYC-7.0 --role Maker --start-url https://uat-host/app
 *                [--hosts host1,host2:port] [--out C:\captures\CKYC-7.0] [--proxy 127.0.0.1:8080]
 *                [--no-overlay] [--no-bodies]
 *
 * Opens Edge; the tester logs in and walks the modules; closing the browser window ends the
 * session and writes the redacted capture file plus the endpoint discovery report.
 */
public final class RecorderMain {

    public static void main(String[] args) throws Exception {
        RecorderConfig cfg = new RecorderConfig();
        String out = "";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project" -> cfg.project = args[++i];
                case "--role" -> cfg.role = args[++i];
                case "--start-url" -> cfg.startUrl = args[++i];
                case "--hosts" -> cfg.approvedHosts.addAll(Arrays.stream(args[++i].split(","))
                        .map(String::trim).filter(s -> !s.isEmpty()).toList());
                case "--out" -> out = args[++i];
                case "--proxy" -> cfg.proxy = args[++i];
                case "--no-overlay" -> cfg.overlay = false;
                case "--no-bodies" -> cfg.captureBodies = false;
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        cfg.outDir = out.isBlank() ? Path.of("C:\\captures", cfg.project) : Path.of(out);
        cfg.resolve();

        System.out.println("VAPT recorder - PASSIVE capture only (no requests are sent by this tool)");
        System.out.println("  Project : " + cfg.project + "   Role: " + cfg.role);
        System.out.println("  Captures: API calls to " + cfg.approvedHosts);
        System.out.println("  Output  : " + cfg.outDir);
        if (!cfg.proxy.isBlank()) System.out.println("  Via proxy " + cfg.proxy + " (TLS errors ignored for the proxy's own certificate)");
        System.out.println();
        System.out.println("Edge will open with a fresh empty profile. Log in yourself, then use the application normally.");
        System.out.println("Type the module name in the 'VAPT module' box (bottom right) before each module.");
        System.out.println("Close the browser window when you are finished.");

        try (Recorder rec = Recorder.start(cfg)) {
            if (!cfg.startUrl.isBlank()) rec.page().navigate(cfg.startUrl);
            while (rec.isOpen()) {
                rec.waitAndStep(1000);
            }
            Recorder.Summary s = rec.stop();
            System.out.println();
            System.out.printf("Captured %d API calls (%d request bodies and %d response bodies read as plain text).%n",
                    s.captured, s.decryptedRequests, s.decryptedResponses);
            System.out.printf("Unique endpoints: %d%n", s.uniqueEndpoints);
            System.out.println("Capture file (redacted): " + s.captureFile);
            System.out.println("Discovery report       : " + s.reportHtml);
            System.out.println("Endpoint inventory     : " + s.inventoryCsv);
        }
    }
}
