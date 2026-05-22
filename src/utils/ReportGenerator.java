package utils;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import domain.ScanTask;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.File;
import java.util.Base64;
import java.util.List;
import java.text.SimpleDateFormat;
import java.util.Date;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burpimpl.CustomScanIssue;
import com.google.gson.JsonElement;
import java.net.URL;

import com.google.gson.JsonParser;
import burp.api.montoya.core.ByteArray;

public class ReportGenerator {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public static ScanTask importJSON(File file, MontoyaApi api) throws Exception {
        String jsonStr = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        JsonObject root = JsonParser.parseString(jsonStr).getAsJsonObject();

        String taskName = root.get("taskName").getAsString();
        ScanTask task = new ScanTask(taskName);
        task.setStatus("Finished");
        task.setProgress(100);

        JsonArray findings = root.getAsJsonArray("findings");
        for (JsonElement element : findings) {
            JsonObject f = element.getAsJsonObject();
            String name = f.get("name").getAsString();
            String severity = f.get("severity").getAsString();
            String urlStr = f.get("url").getAsString();
            String detail = f.get("description").getAsString();

            HttpRequestResponse reqRes = null;
            if (f.has("request")) {
                byte[] reqBytes = Base64.getDecoder().decode(f.get("request").getAsString());
                byte[] resBytes = f.has("response") ? Base64.getDecoder().decode(f.get("response").getAsString()) : new byte[0];
                
                HttpService service = getServiceFromUrl(urlStr);
                HttpRequest req = HttpRequest.httpRequest(service, ByteArray.byteArray(reqBytes));
                HttpResponse res = resBytes.length > 0 ? HttpResponse.httpResponse(ByteArray.byteArray(resBytes)) : null;
                reqRes = HttpRequestResponse.httpRequestResponse(req, res);
            }

            AuditIssue issue = new CustomScanIssue(
                name,
                detail,
                "Refer to imported report for details.",
                urlStr,
                mapSeverity(severity),
                AuditIssueConfidence.FIRM,
                reqRes != null ? new HttpRequestResponse[]{reqRes} : new HttpRequestResponse[0]
            );
            task.addIssue(issue);
        }

        return task;
    }

    private static HttpService getServiceFromUrl(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String host = url.getHost();
            int port = url.getPort();
            boolean secure = url.getProtocol().equalsIgnoreCase("https");
            if (port == -1) port = secure ? 443 : 80;
            return HttpService.httpService(host, port, secure);
        } catch (Exception e) {
            return null;
        }
    }

    private static AuditIssueSeverity mapSeverity(String sev) {
        try { return AuditIssueSeverity.valueOf(sev.toUpperCase()); }
        catch (Exception e) { return AuditIssueSeverity.INFORMATION; }
    }

    public static void exportHTML(ScanTask task, File file) throws Exception {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Nuclei Scan Report - ").append(task.getName()).append("</title>");
        html.append("<style>");
        html.append("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f7f9; }");
        html.append(".header { background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 30px; }");
        html.append(".header h1 { margin: 0; color: #1a202c; font-size: 28px; }");
        html.append(".summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 20px; }");
        html.append(".summary-card { padding: 15px; border-radius: 8px; text-align: center; color: #fff; font-weight: bold; }");
        html.append(".high { background: #d32f2f; } .medium { background: #f57c00; } .low { background: #1976d2; } .info { background: #616161; }");
        html.append(".issue { background: #fff; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; overflow: hidden; border-left: 5px solid #ccc; }");
        html.append(".issue-header { padding: 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #fafafa; border-bottom: 1px solid #eee; }");
        html.append(".issue-content { padding: 20px; display: none; background: #fff; }");
        html.append(".code-block { background: #2d3748; color: #edf2f7; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 13px; white-space: pre-wrap; margin-top: 10px; }");
        html.append(".badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; }");
        html.append("</style>");
        html.append("<script>function toggle(id) { var el = document.getElementById(id); el.style.display = (el.style.display === 'block') ? 'none' : 'block'; }</script>");
        html.append("</head><body>");

        // Header & Summary
        html.append("<div class='header'>");
        html.append("<h1>").append(task.getName()).append("</h1>");
        html.append("<p>Scan ID: #").append(task.getId()).append(" | Date: ").append(sdf.format(new Date())).append("</p>");
        html.append("<div class='summary'>");
        html.append("<div class='summary-card high'>High: ").append(task.getHighCount()).append("</div>");
        html.append("<div class='summary-card medium'>Medium: ").append(task.getMediumCount()).append("</div>");
        html.append("<div class='summary-card low'>Low: ").append(task.getLowCount()).append("</div>");
        html.append("<div class='summary-card info'>Info: ").append(task.getInfoCount()).append("</div>");
        html.append("</div></div>");

        // Issues
        List<AuditIssue> issues = task.getIssues();
        for (int i = 0; i < issues.size(); i++) {
            AuditIssue issue = issues.get(i);
            String sevClass = issue.severity().name().toLowerCase();
            String id = "issue-" + i;
            
            html.append("<div class='issue' style='border-left-color: ").append(getSeverityColor(sevClass)).append(";'>");
            html.append("<div class='issue-header' onclick=\"toggle('").append(id).append("')\">");
            html.append("<div><strong>").append(issue.name()).append("</strong><br><small>").append(issue.baseUrl()).append("</small></div>");
            html.append("<span class='badge' style='background:").append(getSeverityColor(sevClass)).append("; color:#fff;'>").append(sevClass).append("</span>");
            html.append("</div>");
            
            html.append("<div class='issue-content' id='").append(id).append("'>");
            html.append("<h3>Description</h3><div>").append(issue.detail()).append("</div>");
            
            if (!issue.requestResponses().isEmpty()) {
                html.append("<h3>Evidence</h3>");
                String req = new String(issue.requestResponses().get(0).request().toByteArray().getBytes(), StandardCharsets.UTF_8);
                html.append("<h4>Request</h4><div class='code-block'>").append(escapeHtml(req)).append("</div>");
                
                if (issue.requestResponses().get(0).response() != null) {
                    String res = new String(issue.requestResponses().get(0).response().toByteArray().getBytes(), StandardCharsets.UTF_8);
                    html.append("<h4>Response</h4><div class='code-block'>").append(escapeHtml(res)).append("</div>");
                }
            }
            html.append("</div></div>");
        }

        html.append("</body></html>");
        Files.write(file.toPath(), html.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static void exportMarkdown(ScanTask task, File file) throws Exception {
        StringBuilder md = new StringBuilder();
        md.append("# Nuclei Scan Report: ").append(task.getName()).append("\n\n");
        md.append("- **Scan ID:** #").append(task.getId()).append("\n");
        md.append("- **Date:** ").append(sdf.format(new Date())).append("\n\n");
        
        md.append("## Summary\n\n");
        md.append("| Severity | Count |\n| :--- | :--- |\n");
        md.append("| High | ").append(task.getHighCount()).append(" |\n");
        md.append("| Medium | ").append(task.getMediumCount()).append(" |\n");
        md.append("| Low | ").append(task.getLowCount()).append(" |\n");
        md.append("| Info | ").append(task.getInfoCount()).append(" |\n\n");

        md.append("## Findings\n\n");
        for (AuditIssue issue : task.getIssues()) {
            md.append("### ").append(issue.name()).append(" [").append(issue.severity().name()).append("]\n");
            md.append("- **URL:** ").append(issue.baseUrl()).append("\n\n");
            md.append("#### Description\n").append(stripHtml(issue.detail())).append("\n\n");
            
            if (!issue.requestResponses().isEmpty()) {
                md.append("#### Request\n```http\n").append(new String(issue.requestResponses().get(0).request().toByteArray().getBytes(), StandardCharsets.UTF_8)).append("\n```\n\n");
                if (issue.requestResponses().get(0).response() != null) {
                    md.append("#### Response\n```http\n").append(new String(issue.requestResponses().get(0).response().toByteArray().getBytes(), StandardCharsets.UTF_8)).append("\n```\n\n");
                }
            }
            md.append("---\n\n");
        }
        Files.write(file.toPath(), md.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static void exportJSON(ScanTask task, File file) throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("taskName", task.getName());
        root.addProperty("taskId", task.getId());
        root.addProperty("exportDate", sdf.format(new Date()));
        
        JsonObject summary = new JsonObject();
        summary.addProperty("high", task.getHighCount());
        summary.addProperty("medium", task.getMediumCount());
        summary.addProperty("low", task.getLowCount());
        summary.addProperty("info", task.getInfoCount());
        root.add("summary", summary);

        JsonArray findings = new JsonArray();
        for (AuditIssue issue : task.getIssues()) {
            JsonObject finding = new JsonObject();
            finding.addProperty("name", issue.name());
            finding.addProperty("severity", issue.severity().name());
            finding.addProperty("url", issue.baseUrl());
            finding.addProperty("description", issue.detail());
            
            if (!issue.requestResponses().isEmpty()) {
                finding.addProperty("request", Base64.getEncoder().encodeToString(issue.requestResponses().get(0).request().toByteArray().getBytes()));
                if (issue.requestResponses().get(0).response() != null) {
                    finding.addProperty("response", Base64.getEncoder().encodeToString(issue.requestResponses().get(0).response().toByteArray().getBytes()));
                }
            }
            findings.add(finding);
        }
        root.add("findings", findings);
        Files.write(file.toPath(), gson.toJson(root).getBytes(StandardCharsets.UTF_8));
    }

    private static String getSeverityColor(String sev) {
        switch (sev) {
            case "high": return "#d32f2f";
            case "medium": return "#f57c00";
            case "low": return "#1976d2";
            default: return "#616161";
        }
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String stripHtml(String html) {
        return html.replaceAll("<[^>]*>", "");
    }
}
