package scanner;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import domain.ScanOptions;
import java.util.List;

/**
 * Interface for all vulnerability scanning modules.
 */
public interface IScanModule {
    /**
     * Get the name of the module.
     */
    String getModuleName();

    /**
     * Perform active scanning on a specific request/response pair.
     */
    List<AuditIssue> doActiveScan(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, ScanOptions options);

    /**
     * Perform passive scanning on a specific request/response pair.
     */
    List<AuditIssue> doPassiveScan(HttpRequestResponse baseRequestResponse, ScanOptions options);

    /**
     * Perform active scanning on a list of request/response pairs.
     */
    default List<AuditIssue> doActiveScanBatch(List<HttpRequestResponse> baseRequestResponses, AuditInsertionPoint insertionPoint, ScanOptions options) {
        return null;
    }

    /**
     * Perform passive scanning on a list of request/response pairs.
     */
    default List<AuditIssue> doPassiveScanBatch(List<HttpRequestResponse> baseRequestResponses, ScanOptions options) {
        return null;
    }

    /**
     * Stop all ongoing scans in this module.
     */
    default void stop() {
    }
}
