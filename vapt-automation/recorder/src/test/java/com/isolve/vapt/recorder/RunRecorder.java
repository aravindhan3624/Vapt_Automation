package com.isolve.vapt.recorder;

import org.testng.SkipException;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * IDE launcher for the recorder. Run it from the green gutter in IntelliJ (Run 'run') after setting
 * the parameters as VM options in the run configuration, e.g.:
 *
 *   -Dvapt.project=CKYC-7.0 -Dvapt.role=Maker -Dvapt.startUrl=https://&lt;dev-host&gt;/ -Dvapt.zap=true
 *
 * It is a normal TestNG method so the IDE shows a Run button, but its name does not match this
 * module's surefire pattern (*Test / *IT), so a plain {@code mvn} build never triggers it; and it
 * skips (does nothing) unless you supply a start URL. Equivalent to {@code tools/record.ps1}.
 */
public class RunRecorder {

    @Test
    public void run() throws Exception {
        String startUrl = System.getProperty("vapt.startUrl", "").trim();
        if (startUrl.isEmpty()) {
            throw new SkipException("Set -Dvapt.startUrl=https://<dev-host>/ (and -Dvapt.project, -Dvapt.role) "
                    + "in the run configuration to launch the recorder from the IDE.");
        }
        List<String> a = new ArrayList<>(List.of(
                "--project", System.getProperty("vapt.project", "PROJECT"),
                "--role", System.getProperty("vapt.role", "Maker"),
                "--start-url", startUrl));
        addIfSet(a, "--hosts", "vapt.hosts");
        addIfSet(a, "--out", "vapt.out");
        if (Boolean.parseBoolean(System.getProperty("vapt.zap", "false"))) a.add("--zap");
        if (Boolean.parseBoolean(System.getProperty("vapt.noBodies", "false"))) a.add("--no-bodies");
        RecorderMain.main(a.toArray(new String[0]));
    }

    private static void addIfSet(List<String> a, String flag, String prop) {
        String v = System.getProperty(prop, "").trim();
        if (!v.isEmpty()) {
            a.add(flag);
            a.add(v);
        }
    }
}
