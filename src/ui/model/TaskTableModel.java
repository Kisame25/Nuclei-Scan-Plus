package ui.model;

import domain.ScanTask;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class TaskTableModel extends AbstractTableModel {
    private final List<ScanTask> tasks = new ArrayList<>();
    private final String[] columnNames = {"Task"};

    public synchronized void addTask(ScanTask task) {
        tasks.add(0, task); // New tasks at the top
        fireTableDataChanged();
    }

    public synchronized void updateTask() {
        fireTableDataChanged();
    }

    public synchronized void removeTask(ScanTask task) {
        tasks.remove(task);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return tasks.size();
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
        return tasks.get(rowIndex);
    }

    public ScanTask getTaskAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < tasks.size()) {
            return tasks.get(rowIndex);
        }
        return null;
    }
}
