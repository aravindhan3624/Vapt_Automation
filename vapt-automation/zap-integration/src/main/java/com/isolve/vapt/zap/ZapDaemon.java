package com.isolve.vapt.zap;

import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApi;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Starts and stops a local OWASP ZAP daemon for one framework run.
 *
 * Safety defaults (not configurable away):
 *  - binds the proxy/API listener to 127.0.0.1 only (-host);
 *  - fresh random API key per run, kept in memory (never logged or written to reports);
 *  - {@code -silent}: ZAP makes no unsolicited outbound calls (no update checks);
 *  - ZAP "protect" mode: potentially dangerous actions are only allowed on in-scope URLs.
 *
 * The ZAP application itself is a separate install (e.g. C:\Tools\ZAP_2.17.0); the
 * zap-clientapi library only talks to it over its REST API.
 */
public final class ZapDaemon implements AutoCloseable {

    private final Process process;
    private final ClientApi api;
    private final int port;
    private final Path logFile;

    private ZapDaemon(Process process, ClientApi api, int port, Path logFile) {
        this.process = process;
        this.api = api;
        this.port = port;
        this.logFile = logFile;
    }

    /**
     * @param zapInstallDir folder containing zap-&lt;version&gt;.jar
     * @param zapHomeDir    ZAP home (config, session, add-on state) for this framework
     * @param port          proxy/API port on 127.0.0.1, or 0 to pick a free one
     */
    public static ZapDaemon start(Path zapInstallDir, Path zapHomeDir, int port, Duration startTimeout) throws Exception {
        Path jar = findZapJar(zapInstallDir);
        Files.createDirectories(zapHomeDir);
        int p = port > 0 ? port : freePort();
        String apiKey = HexFormat.of().formatHex(randomBytes(24));
        Path log = zapHomeDir.resolve("zap-daemon-console.log");

        List<String> cmd = new ArrayList<>(List.of(
                javaExecutable(), "-Xmx1g", "-jar", jar.toString(),
                "-daemon", "-silent",
                "-host", "127.0.0.1", "-port", String.valueOf(p),
                "-dir", zapHomeDir.toString(),
                "-config", "api.key=" + apiKey,
                // Keep ZAP's default permitted API addresses (localhost, 127.0.0.1 and the "zap"
                // virtual host the Java client uses). The listener itself is bound to 127.0.0.1
                // by -host, so nothing off this machine can reach the proxy or API.
                "-config", "database.recoverylog=false"));
        ProcessBuilder pb = new ProcessBuilder(cmd)
                .directory(zapInstallDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()));
        Process proc = pb.start();

        ClientApi api = new ClientApi("127.0.0.1", p, apiKey);
        Instant deadline = Instant.now().plus(startTimeout);
        Exception last = null;
        while (Instant.now().isBefore(deadline)) {
            if (!proc.isAlive()) {
                throw new IllegalStateException("ZAP exited during start-up (exit " + proc.exitValue() + "); see " + log);
            }
            try {
                api.callApi("core", "view", "version", Map.of());
                ZapDaemon d = new ZapDaemon(proc, api, p, log);
                d.call("core", "action", "setMode", Map.of("mode", "protect"));
                return d;
            } catch (Exception e) {
                last = e;
                TimeUnit.SECONDS.sleep(2);
            }
        }
        proc.destroy();
        throw new IllegalStateException("ZAP API not ready within " + startTimeout.toSeconds() + "s; see " + log, last);
    }

    public ClientApi api() {
        return api;
    }

    /** Proxy port on 127.0.0.1 (route test traffic here). */
    public int port() {
        return port;
    }

    public Path consoleLog() {
        return logFile;
    }

    public String version() throws Exception {
        return value(call("core", "view", "version", Map.of()));
    }

    public String mode() throws Exception {
        return value(call("core", "view", "mode", Map.of()));
    }

    ApiResponse call(String component, String type, String method, Map<String, String> params) throws Exception {
        return api.callApi(component, type, method, params);
    }

    byte[] callOther(String component, String method, Map<String, String> params) throws Exception {
        return api.callApiOther(component, "other", method, params);
    }

    static String value(ApiResponse r) {
        String s = r.toString();
        int colon = s.indexOf('=');
        return colon >= 0 ? s.substring(colon + 1).trim() : s.trim();
    }

    /** Shuts ZAP down via its API; force-stops the process if it doesn't exit in time. */
    @Override
    public void close() {
        try {
            api.callApi("core", "action", "shutdown", Map.of());
        } catch (Exception ignore) { /* already stopping */ }
        try {
            if (!process.waitFor(60, TimeUnit.SECONDS)) process.destroyForcibly();
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    // ---------------- helpers ----------------
    private static Path findZapJar(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) throw new IllegalArgumentException("ZAP install dir not found: " + dir);
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(f -> f.getFileName().toString().matches("zap-\\d.*\\.jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("No zap-<version>.jar in " + dir));
        }
    }

    private static String javaExecutable() {
        String home = System.getProperty("java.home");
        File exe = new File(home, "bin" + File.separator + (isWindows() ? "java.exe" : "java"));
        return exe.isFile() ? exe.getPath() : "java";
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
