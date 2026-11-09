package com.isolve.vapt.recorder;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Settings for one recording session (one role walking the application). */
public final class RecorderConfig {
    public String project = "PROJECT";
    public String role = "role";
    public String startUrl = "";
    /** Hosts (optionally host:port) whose API calls are captured. Everything else is ignored. */
    public List<String> approvedHosts = new ArrayList<>();
    /** Where capture files and the discovery report go. Keep outside OneDrive / git. */
    public Path outDir = Path.of("C:\\captures");
    /** Optional upstream proxy (Burp / ZAP), e.g. "127.0.0.1:8080". */
    public String proxy = "";
    public boolean headless = false;
    public boolean overlay = true;
    /** Store redacted bodies (needed later to build negative tests from real calls). */
    public boolean captureBodies = true;
    public int maxBodyChars = 20_000;
    /**
     * Phase 4: route the browser through a local ZAP (started and stopped by the recorder) for
     * passive analysis. ZAP only watches; no spider, no active scan. Null = off.
     */
    public Path zapInstallDir;
    public Path zapHomeDir = Path.of("C:\\Tools\\zap-home");

    /** Fills approvedHosts from the start URL when none were given. */
    public RecorderConfig resolve() {
        if (approvedHosts.isEmpty() && !startUrl.isBlank()) {
            URI u = URI.create(startUrl);
            approvedHosts.add(u.getPort() > 0 ? u.getHost() + ":" + u.getPort() : u.getHost());
        }
        if (approvedHosts.isEmpty()) throw new IllegalArgumentException("No approved host: give --hosts or --start-url");
        if (zapInstallDir != null && !proxy.isBlank()) {
            throw new IllegalArgumentException("Use either --zap or --proxy, not both");
        }
        return this;
    }

    /** True when the URL's host (and port, if the approved entry has one) is approved. */
    public boolean inScope(URI u) {
        if (u.getHost() == null) return false;
        String host = u.getHost().toLowerCase();
        int port = u.getPort();
        for (String a : approvedHosts) {
            String ah = a.trim().toLowerCase();
            if (ah.contains(":")) {
                String h = ah.substring(0, ah.indexOf(':'));
                int p = Integer.parseInt(ah.substring(ah.indexOf(':') + 1));
                if (host.equals(h) && port == p) return true;
            } else if (host.equals(ah)) {
                return true;
            }
        }
        return false;
    }
}
