package com.isolve.vapt.zap;

import com.sun.net.httpserver.HttpServer;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.testng.Assert.*;

/**
 * Local-only check of the ZAP integration: a loopback fake server that omits security headers,
 * one request routed through the ZAP proxy, then passive alerts + report. Nothing leaves this PC.
 *
 * Runs only when -Dzap.install.dir is set, e.g.
 *   mvn -pl zap-integration -am test -Dzap.install.dir=C:\Tools\ZAP_2.17.0 -Dzap.home.dir=C:\Tools\zap-home
 */
public class ZapPassiveLocalIT {

    private HttpServer fake;
    private int fakePort;
    private ZapDaemon zap;

    private static String prop(String name) {
        String v = System.getProperty(name, "");
        return v.isBlank() || v.startsWith("${") ? "" : v;
    }

    @BeforeClass
    public void setUp() throws Exception {
        String installDir = prop("zap.install.dir");
        if (installDir.isEmpty()) throw new SkipException("zap.install.dir not set - ZAP integration test skipped");
        String home = prop("zap.home.dir");
        Path homeDir = home.isEmpty() ? Path.of("target", "zap-home") : Path.of(home);

        fake = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        fake.createContext("/", ex -> {
            byte[] out = "<html><body>fake target - no security headers on purpose</body></html>"
                    .getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "text/html");
            ex.getResponseHeaders().add("Set-Cookie", "SESSIONID=fake-local-value; Path=/");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        fake.start();
        fakePort = fake.getAddress().getPort();

        zap = ZapDaemon.start(Path.of(installDir), homeDir, 0, Duration.ofSeconds(180));
    }

    @AfterClass(alwaysRun = true)
    public void tearDown() {
        if (zap != null) zap.close();
        if (fake != null) fake.stop(0);
    }

    @Test
    public void passiveAlertsForLocalFakeTarget() throws Exception {
        assertTrue(zap.version().startsWith("2."), "ZAP version");
        assertEquals(zap.mode(), "protect", "ZAP must run in protected mode");

        String base = "http://127.0.0.1:" + fakePort;
        ZapPassiveSession session = new ZapPassiveSession(zap, "local-fake-target", List.of("127.0.0.1:" + fakePort));

        Response r = RestAssured.given().proxy("127.0.0.1", zap.port()).get(base + "/home");
        assertEquals(r.statusCode(), 200);

        session.waitForPassiveScan(Duration.ofSeconds(60));
        assertTrue(session.messageCount(base) >= 1, "request should be recorded by ZAP");

        List<ZapAlert> alerts = session.alerts(base);
        alerts.forEach(a -> System.out.println("ZAP ALERT: " + a));
        assertFalse(alerts.isEmpty(), "missing security headers should raise passive alerts");
        assertTrue(alerts.stream().allMatch(a -> a.url.startsWith(base)), "only in-scope alerts returned");

        Path report = Path.of("target", "zap-local-passive-report.html");
        Files.writeString(report, session.htmlReport(), StandardCharsets.UTF_8);
        assertTrue(Files.size(report) > 1000, "ZAP HTML report written");
    }

    @Test
    public void contextRequiresApprovedHosts() {
        assertThrows(IllegalArgumentException.class, () -> new ZapPassiveSession(zap, "empty", List.of()));
    }
}
