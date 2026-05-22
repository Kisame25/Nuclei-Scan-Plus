package scanner;

import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.http.message.HttpRequestResponse;
import domain.ScanOptions;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Main engine that orchestrates Nuclei scanning.
 */
public class ScannerEngine implements ScanCheck {
    private final List<IScanModule> modules;

    public ScannerEngine() {
        this.modules = new ArrayList<>();
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

    public AuditResult activeAuditBatch(List<HttpRequestResponse> baseRequestResponses, AuditInsertionPoint insertionPoint, ScanOptions options) {
        List<AuditIssue> allIssues = new ArrayList<>();
        for (IScanModule module : modules) {
            List<AuditIssue> issues = module.doActiveScanBatch(baseRequestResponses, insertionPoint, options);
            if (issues != null) {
                allIssues.addAll(issues);
            }
        }
        return auditResult(allIssues);
    }

    public AuditResult passiveAuditBatch(List<HttpRequestResponse> baseRequestResponses, ScanOptions options) {
        List<AuditIssue> allIssues = new ArrayList<>();
        for (IScanModule module : modules) {
            List<AuditIssue> issues = module.doPassiveScanBatch(baseRequestResponses, options);
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

    public void stop() {
        for (IScanModule module : modules) {
            module.stop();
        }
    }
}
