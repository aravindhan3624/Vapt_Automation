package com.isolve.vapt.ckyc.runners;

import com.isolve.vapt.ckyc.stepdefs.CkycApiSecuritySteps;
import com.isolve.vapt.report.ReportEngine;
import io.cucumber.testng.AbstractTestNGCucumberTests;
import io.cucumber.testng.CucumberOptions;
import org.testng.annotations.AfterSuite;

import java.io.File;

@CucumberOptions(
        features = "src/test/resources/features",
        glue = {"com.isolve.vapt.ckyc.stepdefs", "com.isolve.vapt.ckyc.mock"},
        plugin = {"pretty", "html:../../reports/output/ckyc-cucumber-report.html"},
        tags = "@ckyc"
)
public class CkycTestRunner extends AbstractTestNGCucumberTests {

    @AfterSuite(alwaysRun = true)
    public void generateVaptReports() throws Exception {
        ReportEngine reportEngine = new ReportEngine();
        File outDir = new File("../../reports/output");
        // Label reports with the project/environment actually loaded (e.g. CKYC-MOCK / LOCAL-MOCK)
        var results = CkycApiSecuritySteps.RESULTS;
        String project = results.isEmpty() ? "CKYC" : results.get(0).getProjectName();
        String env = results.isEmpty() ? "UAT" : results.get(0).getEnvironment();
        reportEngine.generateVaptReportHtml(project, env, results, outDir);
        reportEngine.generateClosureTrackerXlsx(project, results, outDir);
    }
}
