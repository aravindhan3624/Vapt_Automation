package com.isolve.vapt.passive;

import org.testng.SkipException;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * IDE launcher for the offline passive checks over a HAR file. Run from the gutter in IntelliJ with,
 * for example:
 *
 *   -Dvapt.project=CKYC-7.0 -Dvapt.hosts=&lt;dev-host&gt; -Dvapt.har=C:\captures\walk.har
 *
 * The name does not match the default surefire pattern, so a plain {@code mvn} build never runs it;
 * it skips unless a HAR file is given. Sends no requests. Equivalent to {@code tools/passive-checks-har.ps1}.
 */
public class RunPassiveChecks {

    @Test
    public void run() throws Exception {
        String har = System.getProperty("vapt.har", "").trim();
        String hosts = System.getProperty("vapt.hosts", "").trim();
        if (har.isEmpty() || hosts.isEmpty()) {
            throw new SkipException("Set -Dvapt.har=... and -Dvapt.hosts=<approved host> (and optionally -Dvapt.project) "
                    + "in the run configuration to run passive checks from the IDE.");
        }
        List<String> a = new ArrayList<>(List.of(
                "--project", System.getProperty("vapt.project", "PROJECT"),
                "--hosts", hosts,
                "--har", har));
        String out = System.getProperty("vapt.out", "").trim();
        if (!out.isEmpty()) {
            a.add("--out");
            a.add(out);
        }
        HarPassiveChecks.main(a.toArray(new String[0]));
    }
}
