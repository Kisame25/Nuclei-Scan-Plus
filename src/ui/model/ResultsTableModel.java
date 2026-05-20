package ui.model;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ResultsTableModel extends AbstractTableModel {
    private List<AuditIssue> issues = new ArrayList<>();
    private final String[] columnNames = {"#", "URL", "Issue", "Severity", "Confidence"};

    public synchronized void setIssues(List<AuditIssue> newIssues) {
        this.issues = newIssues;
        fireTableDataChanged();
    }

    public synchronized void addIssue(AuditIssue issue) {
        issues.add(issue);
        fireTableRowsInserted(issues.size() - 1, issues.size() - 1);
    }

    @Override
    public int getRowCount() {
        return issues.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= issues.size()) return "";
        AuditIssue issue = issues.get(rowIndex);
        switch (columnIndex) {
            case 0: return rowIndex + 1;
            case 1: return issue.baseUrl();
            case 2: return issue.name();
            case 3: return issue.severity().name();
            case 4: return issue.confidence().name();
            default: return "";
        }
    }
    
    public AuditIssue getIssueAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < issues.size()) {
            return issues.get(rowIndex);
        }
        return null;
    }
}
