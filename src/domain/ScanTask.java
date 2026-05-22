package domain;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class ScanTask {
    private static final AtomicInteger idCounter = new AtomicInteger(1);
    private final int id;
    private final String name;
    private String status = "Running...";
    private int progress = 0;
    
    private final List<AuditIssue> issues = new ArrayList<>();
    
    private int highIssues = 0;
    private int mediumIssues = 0;
    private int lowIssues = 0;
    private int infoIssues = 0;
    private volatile boolean stopped = false;
    private Process currentProcess;

    public ScanTask(String name) {
        this.id = idCounter.getAndIncrement();
        this.name = name;
    }

    public void stop() {
        this.stopped = true;
        this.status = "Stopped";
        if (currentProcess != null && currentProcess.isAlive()) {
            currentProcess.destroyForcibly();
        }
    }

    public boolean isStopped() {
        return stopped;
    }

    public void setCurrentProcess(Process process) {
        this.currentProcess = process;
    }

    public int getId() { return id; }
    public String getName() { return name; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getProgress() { return progress; }
    public void setProgress(int progress) { this.progress = progress; }

    public synchronized void addIssue(AuditIssue issue) {
        issues.add(issue);
        switch (issue.severity()) {
            case HIGH: highIssues++; break;
            case MEDIUM: mediumIssues++; break;
            case LOW: lowIssues++; break;
            case INFORMATION: infoIssues++; break;
        }
    }

    public List<AuditIssue> getIssues() {
        return new ArrayList<>(issues);
    }

    public int getHighCount() { return highIssues; }
    public int getMediumCount() { return mediumIssues; }
    public int getLowCount() { return lowIssues; }
    public int getInfoCount() { return infoIssues; }

    public void clearData() {
        this.issues.clear();
        this.currentProcess = null;
    }

}
