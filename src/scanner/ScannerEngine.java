package scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.http.message.HttpRequestResponse;
import model.Config;
import model.ScanOptions;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Main engine that orchestrates Nuclei scanning.
 */
public class ScannerEngine implements ScanCheck {
    private final MontoyaApi api;
    private final List<IScanModule> modules;
    private final Config config;

    public ScannerEngine(MontoyaApi api, Config config) {
        this.api = api;
        this.modules = new ArrayList<>();
        this.config = config;
    }

    public void addModule(IScanModule module) {
        modules.add(module);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return passiveAudit(baseRequestResponse, ScanOptions.defaultOptions());
    }

    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse, ScanOptions options) {
        List<AuditIssue> allIssues = new ArrayList<>();
        for (IScanModule module : modules) {
            List<AuditIssue> issues = module.doPassiveScan(baseRequestResponse, options);
            if (issues != null) {
                allIssues.addAll(issues);
            }
        }
        return auditResult(allIssues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        return activeAudit(baseRequestResponse, insertionPoint, ScanOptions.defaultOptions());
    }

    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, ScanOptions options) {
        List<AuditIssue> allIssues = new ArrayList<>();
        for (IScanModule module : modules) {
            List<AuditIssue> issues = module.doActiveScan(baseRequestResponse, insertionPoint, options);
            if (issues != null) {
                allIssues.addAll(issues);
            }
        }
        return auditResult(allIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name()) &&
            existingIssue.baseUrl().equals(newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
