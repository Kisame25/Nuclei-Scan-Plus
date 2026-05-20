package ui.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import javax.swing.table.AbstractTableModel;
import java.util.List;

public class UrlsTableModel extends AbstractTableModel {
    private final List<HttpRequestResponse> items;
    private final String[] columnNames = {"#", "URL"};

    public UrlsTableModel(List<HttpRequestResponse> items) {
        this.items = items;
    }

    @Override
    public int getRowCount() {
        return items.size();
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
        HttpRequestResponse item = items.get(rowIndex);
        switch (columnIndex) {
            case 0: return rowIndex + 1;
            case 1: return item.request().url();
            default: return "";
        }
    }
}
