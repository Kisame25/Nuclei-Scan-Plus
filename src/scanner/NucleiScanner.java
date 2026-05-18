package scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import model.Config;
import model.CustomScanIssue;
import model.ScanOptions;
import model.ScanTask;
import ui.MainTab;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.Set;

public class NucleiScanner implements IScanModule {
    private final MontoyaApi api;
    private final Config config;
    private final MainTab mainTab;
    private final Gson gson;
    private final Semaphore scanSemaphore = new Semaphore(10);

    public NucleiScanner(MontoyaApi api, Config config, MainTab mainTab) {
        this.api = api;
        this.config = config;
        this.mainTab = mainTab;
        this.gson = new Gson();
    }

    @Override
    public String getModuleName() {
        return "Nuclei Wrapper";
    }

    @Override
    public List<AuditIssue> doActiveScan(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, ScanOptions options) {
        return runNuclei(baseRequestResponse, options);
    }

    @Override
    public List<AuditIssue> doPassiveScan(HttpRequestResponse baseRequestResponse, ScanOptions options) {
        return runNuclei(baseRequestResponse, options);
    }

    private List<AuditIssue> runNuclei(HttpRequestResponse baseRequestResponse, ScanOptions options) {
        String nucleiPath = config.getNucleiPath();
        if (nucleiPath == null || nucleiPath.isEmpty()) {
            mainTab.log("Nuclei path not configured!");
            return null;
        }

        ScanTask task = (options != null) ? options.getTask() : null;
        if (task != null && task.isStopped()) return null;

        try {
            scanSemaphore.acquire();
        } catch (InterruptedException e) {
            return null;
        }

        List<AuditIssue> issues = new ArrayList<>();
        File tempBurpXml = null;

        try {
            List<String> command = buildCommand(options);
            
            if (options != null && options.keepOriginalReq()) {
                tempBurpXml = File.createTempFile("nuclei_req_", ".xml");
                String xmlContent = generateBurpXml(baseRequestResponse);
                java.nio.file.Files.write(tempBurpXml.toPath(), xmlContent.getBytes(StandardCharsets.UTF_8));
                
                command.add("-l");
                command.add(tempBurpXml.getAbsolutePath());
                command.add("-im");
                command.add("burp");
            } else {
                command.add("-u");
                command.add(baseRequestResponse.request().url());
            }

            mainTab.log("Executing: " + String.join(" ", command));

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            if (task != null) {
                task.setCurrentProcess(process);
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (task != null && task.isStopped()) {
                        process.destroyForcibly();
                        break;
                    }
                    
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    
                    if (task != null) {
                        task.setLatestLog(line);
                        mainTab.updateTasks();
                    }
                    
                    mainTab.log("NUCLEI: " + line);
                    processOutputLine(line, issues, baseRequestResponse);
                }
            }
            
            boolean finished = process.waitFor(10, TimeUnit.MINUTES);
            if (!finished) {
                mainTab.log("Nuclei process timed out for " + baseRequestResponse.request().url());
                process.destroyForcibly();
            }
        } catch (Exception e) {
            mainTab.log("Error running Nuclei: " + e.getMessage());
        } finally {
            scanSemaphore.release();
            if (tempBurpXml != null && tempBurpXml.exists()) {
                tempBurpXml.delete();
            }
        }

        return issues;
    }

    private List<String> buildCommand(ScanOptions options) {
        List<String> command = new ArrayList<>();
        command.add(config.getNucleiPath());
        command.add("-j"); 
        command.add("-irr");
        command.add("-nc");
        command.add("-silent");

        if (options != null) {
            if (options.getSelectedNucleiTemplates() != null) {
                for (String tplDir : options.getSelectedNucleiTemplates()) {
                    if(tplDir.equals("dast") || tplDir.equals("file") || tplDir.equals("code") || tplDir.equals("headless")){ 
                        command.add("-" + tplDir);
                    }else if(tplDir.equals("workflows")){
                        command.add("-w");
                        command.add(tplDir);
                    }else if(tplDir.equals("cloud")){
                        command.add("-t");
                        command.add(tplDir);
                        command.add("-esc");
                    }else{
                        command.add("-t");
                        command.add(tplDir);
                    }  
                }
            }
            if (options.getSingleTemplatePath() != null && !options.getSingleTemplatePath().isEmpty()) {
                command.add("-t");
                command.add(options.getSingleTemplatePath());
                command.add("-esc");
            }
            if (options.getCustomNucleiArgs() != null && !options.getCustomNucleiArgs().isEmpty()) {
                String[] args = options.getCustomNucleiArgs().split("\\s+");
                for (String arg : args) {
                    if (!arg.isEmpty()) command.add(arg);
                }
            }
        }
        return command;
    }

    private void processOutputLine(String line, List<AuditIssue> issues, HttpRequestResponse baseRequestResponse) {
        String strippedLine = stripAnsi(line);
        if (strippedLine.startsWith("{") && strippedLine.endsWith("}")) {
            try {
                JsonElement element = JsonParser.parseString(strippedLine);
                if (element.isJsonObject()) {
                    issues.add(parseNucleiJsonFinding(element.getAsJsonObject(), baseRequestResponse));
                    return;
                }
            } catch (Exception e) {
                mainTab.log("JSON Parse Error: " + e.getMessage());
            }
        }
        parseNucleiTextFinding(strippedLine, issues, baseRequestResponse);
    }

    private String generateBurpXml(HttpRequestResponse baseRequestResponse) {
        HttpRequest req = baseRequestResponse.request();
        HttpResponse res = baseRequestResponse.response();
        
        String url = req.url();
        String host = req.httpService().host();
        int port = req.httpService().port();
        String protocol = req.httpService().secure() ? "https" : "http";
        String method = req.method();
        String path = req.path();
        
        String requestBase64 = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
        String responseBase64 = (res != null) ? Base64.getEncoder().encodeToString(res.toByteArray().getBytes()) : "";
        
        String extension = "";
        int lastDot = path.lastIndexOf('.');
        if (lastDot != -1 && lastDot > path.lastIndexOf('/')) {
            extension = path.substring(lastDot + 1);
            if (extension.contains("?")) {
                extension = extension.substring(0, extension.indexOf('?'));
            }
        }

        SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
        String now = sdf.format(new Date());
        
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\"?>\n");
        xml.append("<!DOCTYPE items [\n");
        xml.append("<!ELEMENT items (item*)>\n");
        xml.append("<!ATTLIST items burpVersion CDATA \"\">\n");
        xml.append("<!ATTLIST items exportTime CDATA \"\">\n");
        xml.append("<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>\n");
        xml.append("<!ELEMENT time (#PCDATA)>\n");
        xml.append("<!ELEMENT url (#PCDATA)>\n");
        xml.append("<!ELEMENT host (#PCDATA)>\n");
        xml.append("<!ATTLIST host ip CDATA \"\">\n");
        xml.append("<!ELEMENT port (#PCDATA)>\n");
        xml.append("<!ELEMENT protocol (#PCDATA)>\n");
        xml.append("<!ELEMENT method (#PCDATA)>\n");
        xml.append("<!ELEMENT path (#PCDATA)>\n");
        xml.append("<!ELEMENT extension (#PCDATA)>\n");
        xml.append("<!ELEMENT request (#PCDATA)>\n");
        xml.append("<!ATTLIST request base64 (true|false) \"false\">\n");
        xml.append("<!ELEMENT status (#PCDATA)>\n");
        xml.append("<!ELEMENT responselength (#PCDATA)>\n");
        xml.append("<!ELEMENT mimetype (#PCDATA)>\n");
        xml.append("<!ELEMENT response (#PCDATA)>\n");
        xml.append("<!ATTLIST response base64 (true|false) \"false\">\n");
        xml.append("<!ELEMENT comment (#PCDATA)>\n");
        xml.append("]>\n");
        xml.append("<items burpVersion=\"2026.4.3\" exportTime=\"" + now + "\">\n");
        xml.append("  <item>\n");
        xml.append("    <time>" + now + "</time>\n");
        xml.append("    <url><![CDATA[" + url + "]]></url>\n");
        xml.append("    <host ip=\"" + host + "\">" + host + "</host>\n");
        xml.append("    <port>" + port + "</port>\n");
        xml.append("    <protocol>" + protocol + "</protocol>\n");
        xml.append("    <method><![CDATA[" + method + "]]></method>\n");
        xml.append("    <path><![CDATA[" + path + "]]></path>\n");
        xml.append("    <extension>" + extension + "</extension>\n");
        xml.append("    <request base64=\"true\"><![CDATA[" + requestBase64 + "]]></request>\n");
        xml.append("    <status>" + (res != null ? res.statusCode() : "") + "</status>\n");
        xml.append("    <responselength>" + (res != null ? res.toByteArray().length() : 0) + "</responselength>\n");
        xml.append("    <mimetype>" + (res != null && res.mimeType() != null ? res.mimeType().toString() : "") + "</mimetype>\n");
        xml.append("    <response base64=\"true\"><![CDATA[" + responseBase64 + "]]></response>\n");
        xml.append("    <comment></comment>\n");
        xml.append("  </item>\n");
        xml.append("</items>\n");
        
        return xml.toString();
    }

    private void parseNucleiTextFinding(String line, List<AuditIssue> issues, HttpRequestResponse baseRequestResponse) {
        Pattern pattern = Pattern.compile("^\\[([^\\]]+)\\] \\[([^\\]]+)\\] \\[([^\\]]+)\\] (\\S+)");
        Matcher matcher = pattern.matcher(line);
        
        if (matcher.find()) {
            String templateId = matcher.group(1);
            String proto = matcher.group(2);
            String severityStr = matcher.group(3);
            String url = matcher.group(4);
            
            HttpService service = baseRequestResponse.request().httpService();
            String path = getPathFromUrl(url);
            HttpRequest request = HttpRequest.httpRequest(service, "GET " + path + " HTTP/1.1\r\nHost: " + service.host() + "\r\n\r\n");
            
            HttpResponse response;
            if (url.equals(baseRequestResponse.request().url()) && baseRequestResponse.response() != null) {
                response = baseRequestResponse.response();
            } else {
                response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }

            HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(request, response);

            String detail = String.format("<html><body><b>Nuclei Template:</b> %s<br><b>Protocol:</b> %s<br><b>Matched at:</b> %s<br><br><font color='red'><i>Warning: Full request/response only available in JSON mode. Ensure Nuclei outputs JSON findings.</i></font></body></html>",
                    templateId, proto, url);

            issues.add(new CustomScanIssue(
                    templateId,
                    detail,
                    "Refer to Nuclei template for remediation.",
                    url,
                    mapSeverity(severityStr),
                    AuditIssueConfidence.FIRM,
                    new HttpRequestResponse[]{reqRes}
            ));
        }
    }

    private AuditIssue parseNucleiJsonFinding(JsonObject json, HttpRequestResponse baseRequestResponse) {
        String templateId = json.has("template-id") ? json.get("template-id").getAsString() : "Nuclei Finding";
        String matcherName = json.has("matcher-name") ? json.get("matcher-name").getAsString() : "";
        String extractorName = json.has("extractor-name") ? json.get("extractor-name").getAsString() : "";
        
        if (matcherName.isEmpty() && templateId.contains(":")) {
            int colonIndex = templateId.indexOf(':');
            matcherName = templateId.substring(colonIndex + 1);
            templateId = templateId.substring(0, colonIndex);
        }

        String name = templateId;
        if (!matcherName.isEmpty()) name += " (" + matcherName + ")";
        else if (!extractorName.isEmpty()) name += " (" + extractorName + ")";

        JsonObject info = json.getAsJsonObject("info");
        String severityStr = info != null && info.has("severity") && !info.get("severity").isJsonNull() ? info.get("severity").getAsString() : "info";
        String description = info != null && info.has("description") && !info.get("description").isJsonNull() ? info.get("description").getAsString() : "";
        String remediation = info != null && info.has("remediation") && !info.get("remediation").isJsonNull() ? info.get("remediation").getAsString() : "";
        String templateName = info != null && info.has("name") && !info.get("name").isJsonNull() ? info.get("name").getAsString() : "";
        
        AuditIssueSeverity severity = mapSeverity(severityStr);
        
        String rawRequest = json.has("request") && !json.get("request").isJsonNull() ? json.get("request").getAsString() : "";
        String rawResponse = json.has("response") && !json.get("response").isJsonNull() ? json.get("response").getAsString() : "";
        
        String matchedAt = "";
        if (json.has("matched-at") && !json.get("matched-at").isJsonNull()) matchedAt = json.get("matched-at").getAsString();
        else if (json.has("url") && !json.get("url").isJsonNull()) matchedAt = json.get("url").getAsString();
        
        if (matchedAt.isEmpty()) {
            matchedAt = baseRequestResponse.request().url();
        }

        StringBuilder metadata = new StringBuilder();
        metadata.append("<html><body>");
        metadata.append("<h3>Detail Vuln</h3>");
        if (!description.isEmpty()) {
            metadata.append("<p>").append(description.replace("\n", "<br>")).append("</p>");
        } else {
            metadata.append("<p><i>No description provided by template.</i></p>");
        }

        metadata.append("<h3>Remediation</h3>");
        if (!remediation.isEmpty()) {
            metadata.append("<p>").append(remediation.replace("\n", "<br>")).append("</p>");
        } else {
            metadata.append("<p><i>Refer to Nuclei template for remediation.</i></p>");
        }

        metadata.append("<hr>");
        metadata.append("<b>Nuclei Template:</b> ").append(templateId).append("<br>");
        metadata.append("<b>Template Name:</b> ").append(templateName).append("<br>");
        metadata.append("<b>Matched at:</b> ").append(matchedAt).append("<br><br>");
        
        if (json.has("extracted-results") && !json.get("extracted-results").isJsonNull()) {
            metadata.append("<b>Extracted Results:</b><br>");
            JsonElement extracted = json.get("extracted-results");
            if (extracted.isJsonArray()) {
                for (JsonElement e : extracted.getAsJsonArray()) {
                    if (!e.isJsonNull()) {
                        metadata.append("- ").append(e.getAsString().replace("<", "&lt;").replace(">", "&gt;")).append("<br>");
                    }
                }
            } else {
                metadata.append("- ").append(extracted.getAsString().replace("<", "&lt;").replace(">", "&gt;")).append("<br>");
            }
            metadata.append("<br>");
        }

        if (json.has("curl-command") && !json.get("curl-command").isJsonNull()) {
            metadata.append("<b>Curl Command:</b><br><code>")
                    .append(json.get("curl-command").getAsString().replace("<", "&lt;").replace(">", "&gt;"))
                    .append("</code><br><br>");
        }

        if (info != null && info.has("classification") && !info.get("classification").isJsonNull()) {
            JsonObject classif = info.getAsJsonObject("classification");
            if (classif.has("cve-id") && !classif.get("cve-id").isJsonNull()) {
                metadata.append("<b>CVE:</b> ");
                JsonElement cve = classif.get("cve-id");
                metadata.append(cve.isJsonArray() ? cve.getAsJsonArray().toString() : cve.getAsString());
                metadata.append("<br>");
            }
            if (classif.has("cwe-id") && !classif.get("cwe-id").isJsonNull()) {
                metadata.append("<b>CWE:</b> ");
                JsonElement cwe = classif.get("cwe-id");
                metadata.append(cwe.isJsonArray() ? cwe.getAsJsonArray().toString() : cwe.getAsString());
                metadata.append("<br>");
            }
        }
        
        if (info != null && info.has("reference") && !info.get("reference").isJsonNull()) {
            metadata.append("<b>References:</b><br>");
            JsonElement refs = info.get("reference");
            if (refs.isJsonArray()) {
                for (JsonElement ref : refs.getAsJsonArray()) {
                    if (!ref.isJsonNull()) {
                        metadata.append("- <a href='").append(ref.getAsString()).append("'>")
                                .append(ref.getAsString()).append("</a><br>");
                    }
                }
            } else {
                metadata.append("- <a href='").append(refs.getAsString()).append("'>")
                        .append(refs.getAsString()).append("</a><br>");
            }
        }

        if (json.has("ip") && !json.get("ip").isJsonNull()) {
            metadata.append("<br><b>IP:</b> ").append(json.get("ip").getAsString());
        }
        if (json.has("timestamp") && !json.get("timestamp").isJsonNull()) {
            metadata.append("<br><b>Timestamp:</b> ").append(json.get("timestamp").getAsString());
        }
        metadata.append("</body></html>");

        HttpService service = baseRequestResponse.request().httpService();
        
        HttpRequest request;
        if (rawRequest.isEmpty() || rawRequest.equals("Raw request")) {
            String path = getPathFromUrl(matchedAt);
            request = HttpRequest.httpRequest(service, "GET " + path + " HTTP/1.1\r\nHost: " + service.host() + "\r\n\r\n");
        } else {
            request = HttpRequest.httpRequest(service, rawRequest);
        }
        
        HttpResponse response;
        response = HttpResponse.httpResponse(rawResponse);

        HttpRequestResponse reqRes = HttpRequestResponse.httpRequestResponse(request, response);

        return new CustomScanIssue(
                name,
                metadata.toString(),
                remediation.isEmpty() ? "Refer to Nuclei template for remediation." : remediation,
                matchedAt,
                severity,
                AuditIssueConfidence.FIRM,
                new HttpRequestResponse[]{reqRes}
        );
    }

    private String getPathFromUrl(String urlStr) {
        try {
            if (urlStr.startsWith("http")) {
                URL url = new URL(urlStr);
                String path = url.getPath();
                if (path == null || path.isEmpty()) path = "/";
                if (url.getQuery() != null) path += "?" + url.getQuery();
                return path;
            }
            return urlStr;
        } catch (Exception e) {
            return "/";
        }
    }

    private AuditIssueSeverity mapSeverity(String severity) {
        if (severity == null) return AuditIssueSeverity.INFORMATION;
        switch (severity.toLowerCase().trim()) {
            case "critical":
                return AuditIssueSeverity.HIGH;
            case "high":
                return AuditIssueSeverity.HIGH;
            case "medium":
                return AuditIssueSeverity.MEDIUM;
            case "low":
                return AuditIssueSeverity.LOW;
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    private String stripAnsi(String text) {
        if (text == null) return "";
        return text.replaceAll("\u001B\\[[;\\d]*[mK]", "");
    }
}
