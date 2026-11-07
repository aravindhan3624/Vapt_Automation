package com.isolve.vapt.discovery;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Phase 1 entry point: PASSIVE endpoint discovery from a capture file the tester exported
 * (Burp Suite "Save items" XML, or a HAR from Burp / the browser).
 *
 * This class never opens a network connection. It reads the capture, de-duplicates the
 * endpoints, drops every header/cookie/token/body value, and writes:
 *   <out>/<project>-endpoints.redacted.json
 *   <out>/<project>-endpoints.redacted.csv
 *   <out>/<project>-endpoint-discovery.html
 *
 * Usage:
 *   java -cp core-engine/target/classes;<deps> com.isolve.vapt.discovery.EndpointDiscovery \
 *        --project CKYC-7.0 --out reports/output/discovery [--skip prefix1,prefix2] capture1.xml [capture2.har ...]
 */
public final class EndpointDiscovery {

    public static void main(String[] args) throws Exception {
        String project = "PROJECT";
        File outDir = new File("reports/output/discovery");
        List<File> inputs = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project" -> project = args[++i];
                case "--out" -> outDir = new File(args[++i]);
                case "--skip" -> EndpointInventory.addSkipSegments(List.of(args[++i].split(",")));
                default -> inputs.add(new File(args[i]));
            }
        }
        if (inputs.isEmpty()) {
            System.err.println("Usage: EndpointDiscovery --project <name> --out <dir> <capture.xml|capture.har> [...]");
            System.exit(2);
        }

        List<CapturedCall> calls = new ArrayList<>();
        List<String> sourceNames = new ArrayList<>();
        for (File f : inputs) {
            if (!f.isFile()) throw new IllegalArgumentException("Capture file not found: " + f);
            List<CapturedCall> parsed = CaptureParsers.parse(f);
            System.out.printf("Parsed %d calls from %s%n", parsed.size(), f.getName());
            calls.addAll(parsed);
            sourceNames.add(f.getName());   // file name only, never the full local path
        }

        List<Endpoint> endpoints = EndpointInventory.build(calls);
        if (!outDir.isDirectory() && !outDir.mkdirs()) throw new IllegalStateException("Cannot create " + outDir);

        String base = project.replaceAll("[^A-Za-z0-9._-]", "_");
        DiscoveryReport report = new DiscoveryReport(project, sourceNames, calls.size(), endpoints);
        File json = report.writeJson(outDir, base + "-endpoints");
        File csv = report.writeCsv(outDir, base + "-endpoints");
        File html = report.writeHtml(outDir, base + "-endpoint-discovery");

        System.out.printf("Unique endpoints: %d (from %d calls)%n", endpoints.size(), calls.size());
        System.out.println("Wrote: " + json.getPath());
        System.out.println("Wrote: " + csv.getPath());
        System.out.println("Wrote: " + html.getPath());
    }
}
