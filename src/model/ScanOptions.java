package model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ScanOptions {
    private final List<String> selectedNucleiTemplates;
    private final String singleTemplatePath;
    private final String customNucleiArgs;
    private final boolean scanPostReq;
    private ScanTask task;

    public ScanOptions(String singleTemplatePath, String customNucleiArgs, boolean scanPostReq) {
        this.singleTemplatePath = singleTemplatePath;
        this.customNucleiArgs = customNucleiArgs;
        this.scanPostReq = scanPostReq;
        this.selectedNucleiTemplates = new ArrayList<>();
    }

    public void setTask(ScanTask task) {
        this.task = task;
    }

    public ScanTask getTask() {
        return task;
    }

    public void addNucleiTemplate(String templateDir) {
        selectedNucleiTemplates.add(templateDir);
    }

    public List<String> getSelectedNucleiTemplates() {
        return selectedNucleiTemplates;
    }

    public String getSingleTemplatePath() {
        return singleTemplatePath;
    }

    public String getCustomNucleiArgs() {
        return customNucleiArgs;
    }

    public boolean scanPostReq() {
        return scanPostReq;
    }

    public static ScanOptions defaultOptions() {
        return new ScanOptions("", "", false);
    }
}
