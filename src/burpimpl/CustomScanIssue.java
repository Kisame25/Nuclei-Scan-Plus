package burpimpl;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

public class CustomScanIssue implements AuditIssue {
    private final String name;
    private final String detail;
    private final String remediation;
    private final String baseUrl;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final List<HttpRequestResponse> httpMessages;
    private final AuditIssueDefinition definition;

    public CustomScanIssue(
            String name,
            String detail,
            String remediation,
            String baseUrl,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence,
            HttpRequestResponse... httpMessages) {
        this.name = name;
        this.detail = detail;
        this.remediation = remediation;
        this.baseUrl = baseUrl;
        this.severity = severity;
        this.confidence = confidence;
        this.httpMessages = Arrays.asList(httpMessages);
        
        // Create a definition for better Burp integration
        this.definition = AuditIssueDefinition.auditIssueDefinition(name, detail, remediation, severity);
    }

    @Override
    public String name() { return name; }

    @Override
    public String detail() { return detail; }

    @Override
    public String remediation() { return remediation; }

    @Override
    public String baseUrl() { return baseUrl; }

    @Override
    public AuditIssueSeverity severity() { return severity; }

    @Override
    public AuditIssueConfidence confidence() { return confidence; }

    @Override
    public List<HttpRequestResponse> requestResponses() { return httpMessages; }

    @Override
    public HttpService httpService() {
        return httpMessages.isEmpty() ? null : httpMessages.get(0).httpService();
    }

    @Override
    public List<Interaction> collaboratorInteractions() {
        return new ArrayList<>();
    }

    @Override
    public AuditIssueDefinition definition() {
        return definition;
    }
}
