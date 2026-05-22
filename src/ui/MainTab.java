package ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import config.Config;
import domain.ScanTask;
import ui.model.ResultsTableModel;
import ui.model.TaskTableModel;
import ui.util.FontUtils;
import utils.ReportGenerator;
import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.JsonParser;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;


public class MainTab extends JTabbedPane {

    private static final int TASK_CARD_MARGIN_LEFT = 4;
    private static final int TASK_CARD_MARGIN_TOP = 4;
    private static final int TASK_CARD_PADDING_TOP = 12;
    private static final int TASK_CARD_PADDING_RIGHT = 15;
    private static final int TASK_MENU_ICON_SIZE = 24;

    private static final int MAX_LOG_LINES = 1000;
    private final Config config;
    private final ResultsTableModel resultsTableModel;
    private final TaskTableModel taskTableModel;
    private final MontoyaApi api;
    
    private JTable tasksTable;
    private JLabel selectedTaskLabel;
    private ScanTask currentSelectedTask;
    
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JEditorPane advisoryViewer;
    
    private JTextArea logArea;
    private Timer progressAnimationTimer;
    private int progressAnimationFrame = 0;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public MainTab(MontoyaApi api, Config config) {
        this.api = api;
        this.config = config;
        this.resultsTableModel = new ResultsTableModel();
        this.taskTableModel = new TaskTableModel();

        setupDashboard();
        setupSettings();
        setupLogs();
        startProgressAnimationTimer();
    }

    public void addTask(ScanTask task) {
        SwingUtilities.invokeLater(() -> {
            taskTableModel.addTask(task);
            tasksTable.setRowSelectionInterval(0, 0);
            selectTask(task);
        });
    }

    public void updateTasks() {
        SwingUtilities.invokeLater(() -> {
            taskTableModel.updateTask();
            if (currentSelectedTask != null) {
                resultsTableModel.setIssues(currentSelectedTask.getIssues());
            }
        });
    }

    public void addIssue(ScanTask task, AuditIssue issue) {
        task.addIssue(issue);
        SwingUtilities.invokeLater(() -> {
            taskTableModel.updateTask();
            if (currentSelectedTask == task) {
                resultsTableModel.addIssue(issue);
            }
        });
    }
    
    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = dateFormat.format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            
            // Limit log size to prevent memory leak
            if (logArea.getLineCount() > MAX_LOG_LINES) {
                try {
                    int end = logArea.getLineEndOffset(logArea.getLineCount() - MAX_LOG_LINES - 1);
                    logArea.replaceRange("", 0, end);
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    public void stop() {
        if (progressAnimationTimer != null) {
            progressAnimationTimer.stop();
        }
        
        // Explicitly clear data to help GC when extension unloads
        taskTableModel.clear();
        resultsTableModel.setIssues(new ArrayList<>());
        
        if (requestViewer != null) requestViewer.setRequest(null);
        if (responseViewer != null) responseViewer.setResponse(null);
        if (advisoryViewer != null) advisoryViewer.setText("");
        if (logArea != null) logArea.setText("");
    }

    private void handleImport() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Scan Task (JSON)");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"));

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                ScanTask importedTask = ReportGenerator.importJSON(file, api);
                addTask(importedTask);
                JOptionPane.showMessageDialog(this, "Task imported successfully!");
            } catch (Exception ex) {
                log("Error importing task: " + ex.getMessage());
                JOptionPane.showMessageDialog(this, "Error importing task: " + ex.getMessage());
            }
        }
    }

    private void handleExport(String format) {
        int row = tasksTable.getSelectedRow();
        if (row == -1) return;
        
        ScanTask task = taskTableModel.getTaskAt(row);
        if (task.getIssues().isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export for this task.");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Report");
        
        SimpleDateFormat fileDateFmt = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
        String timestamp = fileDateFmt.format(new Date());
        String defaultName = timestamp + "." + format;
        
        fileChooser.setSelectedFile(new File(defaultName));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                switch (format) {
                    case "html": ReportGenerator.exportHTML(task, file); break;
                    case "markdown": ReportGenerator.exportMarkdown(task, file); break;
                    case "json": ReportGenerator.exportJSON(task, file); break;
                }
                JOptionPane.showMessageDialog(this, "Report exported successfully to:\n" + file.getAbsolutePath());
            } catch (Exception ex) {
                log("Error exporting report: " + ex.getMessage());
                JOptionPane.showMessageDialog(this, "Error exporting report: " + ex.getMessage());
            }
        }
    }

    private void setupDashboard() {
        JPanel dashboardPanel = new JPanel(new BorderLayout());

        // Sidebar: Tasks List
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(320, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UIManager.getColor("Separator.foreground")));

        // Header Panel for Sidebar
        JPanel sidebarHeader = new JPanel(new BorderLayout());
        sidebarHeader.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JLabel tasksLabel = new JLabel("Tasks");
        tasksLabel.setFont(FontUtils.getHeadingFont());
        sidebarHeader.add(tasksLabel, BorderLayout.WEST);
        
        JButton importBtn = new JButton("📥 Import");
        importBtn.setToolTipText("Import Scan results from JSON file");
        importBtn.addActionListener(e -> handleImport());
        sidebarHeader.add(importBtn, BorderLayout.EAST);
        
        sidebar.add(sidebarHeader, BorderLayout.NORTH);

        tasksTable = new JTable(taskTableModel);
        tasksTable.setRowHeight(120); // More room
        tasksTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tasksTable.setShowGrid(false);
        tasksTable.setIntercellSpacing(new Dimension(0, 0));
        tasksTable.setDefaultRenderer(Object.class, new TaskCellRenderer());
        tasksTable.setBackground(UIManager.getColor("Table.background"));

        // Popup Menu for Tasks
        JPopupMenu taskPopupMenu = new JPopupMenu();
        JMenuItem stopItem = new JMenuItem("⏹ Stop");
        taskPopupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                int row = tasksTable.getSelectedRow();
                ScanTask task = row != -1 ? taskTableModel.getTaskAt(row) : null;
                stopItem.setEnabled(isTaskStoppable(task));
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });
        stopItem.addActionListener(e -> {
            int row = tasksTable.getSelectedRow();
            if (row != -1) {
                ScanTask task = taskTableModel.getTaskAt(row);
                if (isTaskStoppable(task)) {
                    task.stop();
                    updateTasks();
                    tasksTable.repaint();
                }
            }
        });
        JMenuItem deleteItem = new JMenuItem("🗙 Delete");
        deleteItem.addActionListener(e -> {
            int row = tasksTable.getSelectedRow();
            if (row != -1) {
                ScanTask task = taskTableModel.getTaskAt(row);
                task.stop();
                task.clearData();
                taskTableModel.removeTask(task);
                
                if (currentSelectedTask == task) {
                    currentSelectedTask = null;
                    SwingUtilities.invokeLater(() -> {
                        selectedTaskLabel.setText("Select a task to view details");
                        resultsTableModel.setIssues(new ArrayList<>());
                        advisoryViewer.setText("");
                        requestViewer.setRequest(null);
                        responseViewer.setResponse(null);
                    });
                }
            }
        });

        // Export Report Submenu
        JMenu exportMenu = new JMenu("📤 Export Report");
        JMenuItem exportHtml = new JMenuItem("HTML Report (.html)");
        JMenuItem exportMd = new JMenuItem("Markdown Report (.md)");
        JMenuItem exportJson = new JMenuItem("JSON Data (.json)");
        
        exportMenu.add(exportHtml);
        exportMenu.add(exportMd);
        exportMenu.add(exportJson);

        exportHtml.addActionListener(e -> handleExport("html"));
        exportMd.addActionListener(e -> handleExport("markdown"));
        exportJson.addActionListener(e -> handleExport("json"));

        taskPopupMenu.add(stopItem);
        taskPopupMenu.add(exportMenu);
        taskPopupMenu.add(new JPopupMenu.Separator());
        taskPopupMenu.add(deleteItem);

        // Right-click selects the row; left-click on the menu icon opens the task menu.
        tasksTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                int row = tasksTable.rowAtPoint(e.getPoint());
                if (SwingUtilities.isRightMouseButton(e)) {
                    if (row != -1) {
                        tasksTable.setRowSelectionInterval(row, row);
                    }
                } else if (row != -1 && SwingUtilities.isLeftMouseButton(e) && isTaskMenuIconHit(e.getPoint())) {
                    tasksTable.setRowSelectionInterval(row, row);
                    taskPopupMenu.show(tasksTable, e.getX(), e.getY());
                }
            }
        });

        tasksTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = tasksTable.getSelectedRow();
                if (row != -1) {
                    selectTask(taskTableModel.getTaskAt(row));
                }
            }
        });

        tasksTable.setComponentPopupMenu(taskPopupMenu);

        JScrollPane sidebarScroll = new JScrollPane(tasksTable);
        sidebarScroll.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0)); // Space on top
        sidebarScroll.getViewport().setBackground(UIManager.getColor("Table.background"));
        sidebar.add(sidebarScroll, BorderLayout.CENTER);

        // Main Content Area
        JPanel mainContent = new JPanel(new BorderLayout());
        
        // Header for selected task
        JPanel taskHeaderPanel = new JPanel(new BorderLayout());
        taskHeaderPanel.setBackground(UIManager.getColor("InternalFrame.activeTitleBackground"));
        taskHeaderPanel.setPreferredSize(new Dimension(0, 50));
        
        selectedTaskLabel = new JLabel("Select a task to view details");
        selectedTaskLabel.setFont(FontUtils.getHeadingFont());
        taskHeaderPanel.add(selectedTaskLabel, BorderLayout.WEST);
        
        mainContent.add(taskHeaderPanel, BorderLayout.NORTH);

        // Tab: Audit Items (Only one tab now)
        JSplitPane auditSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        auditSplit.setDividerLocation(300);

        JTable resultsTable = new JTable(resultsTableModel);
        resultsTable.setAutoCreateRowSorter(true); // Enable sorting
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row != -1) {
                    // Use convertRowIndexToModel to handle sorted view
                    int modelRow = resultsTable.convertRowIndexToModel(row);
                    AuditIssue issue = resultsTableModel.getIssueAt(modelRow);
                    updateRequestResponseView(issue);
                }
            }
        });
        
        auditSplit.setTopComponent(new JScrollPane(resultsTable));

        // Bottom Pane: Request/Response
        JTabbedPane messageTabs = new JTabbedPane();
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        
        advisoryViewer = new JEditorPane();
        advisoryViewer.setEditable(false);
        advisoryViewer.setContentType("text/html");
        
        messageTabs.addTab("Description", new JScrollPane(advisoryViewer));
        messageTabs.addTab("Request", requestViewer.uiComponent());
        messageTabs.addTab("Response", responseViewer.uiComponent());
        
        auditSplit.setBottomComponent(messageTabs);
        
        mainContent.add(auditSplit, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sidebar, mainContent);
        splitPane.setDividerLocation(320);
        dashboardPanel.add(splitPane, BorderLayout.CENTER);

        addTab("Dashboard", dashboardPanel);
    }

    private void selectTask(ScanTask task) {
        this.currentSelectedTask = task;
        selectedTaskLabel.setText("  " + task.getId() + ". " + task.getName());
        resultsTableModel.setIssues(task.getIssues());
        
        // Clear viewers when switching tasks
        advisoryViewer.setText("");
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
    }

    private void updateRequestResponseView(AuditIssue issue) {
        if (issue != null) {
            advisoryViewer.setText(issue.detail());
            advisoryViewer.setCaretPosition(0);

            if (!issue.requestResponses().isEmpty()) {
                requestViewer.setRequest(issue.requestResponses().get(0).request());
                if (issue.requestResponses().get(0).response() != null) {
                    responseViewer.setResponse(issue.requestResponses().get(0).response());
                }
            } else {
                requestViewer.setRequest(null);
                responseViewer.setResponse(null);
            }
        }
    }

    private void setupSettings() {
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        // Nuclei Binary Path
        gbc.gridx = 0; gbc.gridy = 0;
        settingsPanel.add(new JLabel("Nuclei Binary Path:"), gbc);
        JTextField nucleiPathField = new JTextField(config.getNucleiPath(), 30);
        gbc.gridx = 1; settingsPanel.add(nucleiPathField, gbc);
        JButton browseNucleiBtn = new JButton("Browse");
        browseNucleiBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                nucleiPathField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        gbc.gridx = 2; settingsPanel.add(browseNucleiBtn, gbc);

        // Nuclei Templates Path
        gbc.gridx = 0; gbc.gridy = 1;
        settingsPanel.add(new JLabel("Nuclei Templates Path:"), gbc);
        JTextField templatesPathField = new JTextField(config.getTemplatesPath(), 30);
        gbc.gridx = 1; settingsPanel.add(templatesPathField, gbc);
        JButton browseTemplatesBtn = new JButton("Browse");
        browseTemplatesBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                templatesPathField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        gbc.gridx = 2; settingsPanel.add(browseTemplatesBtn, gbc);

        // Section: Nuclei Updates
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 3;
        gbc.insets = new Insets(20, 5, 10, 5);
        JLabel updateLabel = new JLabel("Nuclei Update Management");
        updateLabel.setFont(updateLabel.getFont().deriveFont(Font.BOLD));
        settingsPanel.add(updateLabel, gbc);

        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridwidth = 1;

        // Update Engine Button
        gbc.gridy++; gbc.gridx = 0;
        settingsPanel.add(new JLabel("Update Nuclei Engine (-up)"), gbc);
        JButton upBtn = new JButton("Update");
        gbc.gridx = 1; settingsPanel.add(upBtn, gbc);
        upBtn.addActionListener(e -> runNucleiCommand(nucleiPathField.getText(), "-up"));
        settingsPanel.add(upBtn, gbc);

        // Update Templates Button
        gbc.gridy++; gbc.gridx = 0;
        settingsPanel.add(new JLabel("Update Nuclei Template (-ut)"), gbc);
        JButton utBtn = new JButton("Update");
        gbc.gridx = 1; settingsPanel.add(utBtn, gbc);
        utBtn.addActionListener(e -> runNucleiCommand(nucleiPathField.getText(), "-ut"));
        settingsPanel.add(utBtn, gbc);

        // Custom Template Update Dir
        gbc.gridy++; gbc.gridx = 0;
        settingsPanel.add(new JLabel("Custom Template Update Dir (-ud):"), gbc);
        JTextField updateDirField = new JTextField(25);
        gbc.gridx = 1; settingsPanel.add(updateDirField, gbc);
        JButton updateCustomBtn = new JButton("Update at Custom Dir");
        updateCustomBtn.addActionListener(e -> {
            if (updateDirField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a directory first.");
                return;
            }
            runNucleiCommand(nucleiPathField.getText(), "-ut", "-ud", updateDirField.getText().trim());
        });
        gbc.gridx = 2; settingsPanel.add(updateCustomBtn, gbc);


        // // Save All Button
        gbc.gridy++; gbc.gridx = 1;
        gbc.insets = new Insets(25, 5, 5, 5);
        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.addActionListener(e -> {
            config.setNucleiPath(nucleiPathField.getText().trim());
            config.setTemplatesPath(templatesPathField.getText().trim());
            // In a real app we'd save duc state to config too
            JOptionPane.showMessageDialog(this, "Configuration Saved!");
        });
        settingsPanel.add(saveBtn, gbc);

        // Spacer
        gbc.gridy++; gbc.weighty = 1.0;
        settingsPanel.add(new JPanel(), gbc);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(new JScrollPane(settingsPanel), BorderLayout.CENTER);
        addTab("Settings", wrapper);
    }
    
    private void runNucleiCommand(String nucleiPath, String... args) {
        if (nucleiPath == null || nucleiPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Nuclei binary path not set!");
            return;
        }
        
        new Thread(() -> {
            try {
                List<String> command = new ArrayList<>();
                command.add(nucleiPath);
                for (String arg : args) command.add(arg);
                
                log("Executing update command: " + String.join(" ", command));
                
                ProcessBuilder pb = new ProcessBuilder(command);
                pb.redirectErrorStream(true);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    log("NUCLEI UPDATE: " + line);
                }
                int exitCode = process.waitFor();
                log("Nuclei command finished with exit code: " + exitCode);
                
                SwingUtilities.invokeLater(() -> {
                    if (exitCode == 0) JOptionPane.showMessageDialog(this, "Nuclei update command completed successfully!");
                    else JOptionPane.showMessageDialog(this, "Nuclei update command failed. Check Logs tab.");
                });
                
            } catch (Exception ex) {
                log("Error running update command: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage()));
            }
        }).start();
    }

    private void setupLogs() {
        JPanel logPanel = new JPanel(new BorderLayout());
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(FontUtils.getCodeFont());
        logArea.setBackground(UIManager.getColor("TextArea.background"));
        logArea.setForeground(UIManager.getColor("TextArea.foreground"));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        logPanel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("Clear Logs");
        clearBtn.addActionListener(e -> logArea.setText(""));
        toolbar.add(clearBtn);
        logPanel.add(toolbar, BorderLayout.NORTH);
        
        addTab("Logs", logPanel);
    }

    private void startProgressAnimationTimer() {
        progressAnimationTimer = new Timer(80, e -> {
            if (hasRunningTasks()) {
                progressAnimationFrame++;
                tasksTable.repaint();
            }
        });
        progressAnimationTimer.start();
    }

    private boolean hasRunningTasks() {
        for (int i = 0; i < taskTableModel.getRowCount(); i++) {
            ScanTask task = taskTableModel.getTaskAt(i);
            if (task != null
                    && !task.getStatus().equalsIgnoreCase("Finished")
                    && !task.getStatus().equalsIgnoreCase("Stopped")
                    && !task.getStatus().equalsIgnoreCase("Error")) {
                return true;
            }
        }
        return false;
    }

    private boolean isTaskStoppable(ScanTask task) {
        if (task == null || task.isStopped()) return false;

        String status = task.getStatus();
        return status == null
                || (!status.equalsIgnoreCase("Finished")
                && !status.equalsIgnoreCase("Stopped")
                && !status.equalsIgnoreCase("Error"));
    }

    private boolean isTaskMenuIconHit(Point point) {
        int row = tasksTable.rowAtPoint(point);
        int column = tasksTable.columnAtPoint(point);
        if (row == -1 || column == -1) return false;

        Rectangle cell = tasksTable.getCellRect(row, column, false);
        int iconX = cell.x + cell.width
                - TASK_CARD_MARGIN_LEFT
                - TASK_CARD_PADDING_RIGHT
                - TASK_MENU_ICON_SIZE;
        int iconY = cell.y + TASK_CARD_MARGIN_TOP + TASK_CARD_PADDING_TOP - 2;

        Rectangle iconBounds = new Rectangle(iconX, iconY, TASK_MENU_ICON_SIZE, TASK_MENU_ICON_SIZE);
        return iconBounds.contains(point);
    }

    private class TaskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            ScanTask task = (ScanTask) value;
            
            Color tableBg = UIManager.getColor("Table.background");
            boolean isDark = (tableBg.getRed() + tableBg.getGreen() + tableBg.getBlue()) / 3 < 128;

            Color cardBg;
            Color titleFg;
            Color subFg;
            Color progressBg;

            if (isSelected) {
                cardBg = UIManager.getColor("Table.selectionBackground");
                titleFg = UIManager.getColor("Table.selectionForeground");
                subFg = UIManager.getColor("Table.selectionForeground");
                progressBg = isDark ? cardBg.darker() : cardBg.brighter();
            } else {
                if (isDark) {
                    cardBg = new Color(tableBg.getRed() + 15, tableBg.getGreen() + 15, tableBg.getBlue() + 15);
                } else {
                    cardBg = new Color(Math.max(0, tableBg.getRed() - 15), Math.max(0, tableBg.getGreen() - 15), Math.max(0, tableBg.getBlue() - 15));
                }
                titleFg = UIManager.getColor("Label.foreground");
                subFg = UIManager.getColor("Label.disabledForeground");
                progressBg = isDark ? new Color(50, 50, 50) : new Color(220, 220, 220);
            }

            // Outer wrapper for margin - Bottom only
            JPanel wrapper = new JPanel(new BorderLayout());
            wrapper.setBorder(BorderFactory.createEmptyBorder(4, 4, 8, 4));
            wrapper.setOpaque(true);
            wrapper.setBackground(tableBg);

            // The actual card
            JPanel card = new JPanel(new GridBagLayout()) {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(getBackground());
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                    
                    if (isSelected) {
                        g2.setColor(new Color(0, 122, 204)); // Vibrant selection blue
                        g2.fillRoundRect(getWidth() - 5, 0, 5, getHeight(), 6, 6);
                        g2.fillRect(getWidth() - 5, 0, 2, getHeight());
                    }
                    g2.dispose();
                }
            };
            card.setOpaque(false);
            card.setBackground(cardBg);
            card.setBorder(BorderFactory.createEmptyBorder(12, 15, 12, 15));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;

            // 1. Title and task menu affordance
            JLabel nameLabel = new JLabel(task.getId() + ". " + task.getName());
            nameLabel.setFont(FontUtils.getTitleFont());
            nameLabel.setForeground(titleFg);
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 1.0;
            gbc.insets = new Insets(0, 0, 0, 8);
            card.add(nameLabel, gbc);

            JLabel menuLabel = new JLabel("⋮");
            menuLabel.setFont(FontUtils.getTitleFont().deriveFont(Font.BOLD, 18f));
            menuLabel.setForeground(subFg);
            menuLabel.setHorizontalAlignment(SwingConstants.CENTER);
            menuLabel.setToolTipText("Task actions");
            menuLabel.setPreferredSize(new Dimension(TASK_MENU_ICON_SIZE, TASK_MENU_ICON_SIZE));
            menuLabel.setMinimumSize(new Dimension(TASK_MENU_ICON_SIZE, TASK_MENU_ICON_SIZE));
            gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 0;
            gbc.insets = new Insets(-2, 0, 0, 0);
            card.add(menuLabel, gbc);

            // 2. Subtitle / Streaming Log
            String subText = task.getStatus().equalsIgnoreCase("Finished") ? "Audit finished" : "Auditting";
            
            // Truncate long log lines
            if (subText.length() > 40) subText = subText.substring(0, 37) + "...";

            JLabel subLabel = new JLabel(subText);
            subLabel.setFont(FontUtils.getSubTitleFont());
            subLabel.setForeground(subFg);
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
            gbc.insets = new Insets(2, 0, 12, 0); // More room below subtitle
            card.add(subLabel, gbc);

            // 3. Progress Bar
            JProgressBar progressBar = createBurpProgressBar(task, progressBg, isDark);
            gbc.gridy = 2; gbc.insets = new Insets(0, 0, 12, 0); // More room below progress bar
            card.add(progressBar, gbc);

            // 4. Bottom Row: Status (Left) and Issues (Right)
            JPanel bottomRow = new JPanel(new GridBagLayout());
            bottomRow.setOpaque(false);
            GridBagConstraints bottomGbc = new GridBagConstraints();

            // Status with Icon
            String statusIcon = task.getStatus().equalsIgnoreCase("Finished") ? "✓ " : "⚡ ";
            JLabel statusLabel = new JLabel(statusIcon + task.getStatus());
            statusLabel.setFont(FontUtils.getSubTitleFont());
            if (task.getStatus().equalsIgnoreCase("Finished")) {
                statusLabel.setForeground(isDark ? new Color(0, 180, 0) : new Color(0, 120, 0));
            } else if (task.getStatus().equalsIgnoreCase("Stopped")) {
                statusLabel.setForeground(Color.RED);
            } else {
                statusLabel.setForeground(subFg);
            }
            
            bottomGbc.gridx = 0; bottomGbc.gridy = 0; bottomGbc.weightx = 1.0;
            bottomGbc.anchor = GridBagConstraints.WEST;
            bottomRow.add(statusLabel, bottomGbc);

            // Issues Container
            JPanel issuePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
            issuePanel.setOpaque(false);
            JLabel issuesText = new JLabel("Issues: ");
            issuesText.setFont(FontUtils.getSubTitleFont());
            issuesText.setForeground(subFg);
            issuePanel.add(issuesText);
            
            // Fixed order: High, Medium, Low, Info
            issuePanel.add(createCountBadge(task.getHighCount(), new Color(215, 0, 50)));   // Red
            issuePanel.add(createCountBadge(task.getMediumCount(), new Color(255, 120, 0))); // Orange
            issuePanel.add(createCountBadge(task.getLowCount(), new Color(0, 120, 215)));    // Blue
            issuePanel.add(createCountBadge(task.getInfoCount(), new Color(120, 120, 120))); // Gray

            bottomGbc.gridx = 1; bottomGbc.weightx = 0;
            bottomGbc.anchor = GridBagConstraints.EAST;
            bottomRow.add(issuePanel, bottomGbc);

            gbc.gridy = 3; gbc.weightx = 1.0;
            gbc.insets = new Insets(0, 0, 0, 0);
            card.add(bottomRow, gbc);

            wrapper.add(card, BorderLayout.CENTER);
            return wrapper;
        }

        private JProgressBar createBurpProgressBar(ScanTask task, Color trackColor, boolean isDark) {
            boolean finished = task.getStatus().equalsIgnoreCase("Finished");
            boolean stopped = task.getStatus().equalsIgnoreCase("Stopped");
            boolean running = !finished && !stopped;

            JProgressBar progressBar = new JProgressBar(0, 100) {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                    int width = getWidth();
                    int height = getHeight();
                    int arc = Math.max(6, height);

                    g2.setColor(getBackground());
                    g2.fillRoundRect(0, 0, width, height, arc, arc);

                    int value = Math.max(getMinimum(), Math.min(getMaximum(), getValue()));
                    int fillWidth = running ? Math.max(width / 3, 36) : Math.round(width * (value / 100f));
                    fillWidth = Math.min(width, Math.max(0, fillWidth));

                    if (fillWidth > 0) {
                        int fillX = 0;
                        if (running) {
                            int travel = Math.max(1, width - fillWidth);
                            int cycle = travel * 2;
                            int position = (progressAnimationFrame * 4) % cycle;
                            fillX = position <= travel ? position : cycle - position;
                        }

                        Color start = getForeground();
                        Color end = getForeground().darker();
                        g2.setPaint(new GradientPaint(fillX, 0, start, fillX + fillWidth, 0, end));
                        g2.fillRoundRect(fillX, 0, fillWidth, height, arc, arc);
                    }

                    g2.setColor(isDark ? new Color(255, 255, 255, 35) : new Color(0, 0, 0, 35));
                    g2.drawRoundRect(0, 0, width - 1, height - 1, arc, arc);
                    g2.dispose();
                }
            };

            progressBar.setValue(task.getProgress());
            progressBar.setPreferredSize(new Dimension(100, 8));
            progressBar.setMinimumSize(new Dimension(80, 8));
            progressBar.setBorder(BorderFactory.createEmptyBorder());
            progressBar.setBorderPainted(false);
            progressBar.setStringPainted(false);
            progressBar.setOpaque(false);
            progressBar.setBackground(trackColor);

            if (finished) {
                progressBar.setForeground(new Color(0, 120, 215));
            } else if (stopped) {
                progressBar.setForeground(new Color(190, 70, 70));
            } else {
                progressBar.setForeground(new Color(0, 120, 215));
            }

            return progressBar;
        }

        private JLabel createCountBadge(int count, Color color) {
            JLabel label = new JLabel(String.valueOf(count)) {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(getBackground());
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                    super.paintComponent(g2);
                    g2.dispose();
                }
            };
            label.setOpaque(false);
            label.setBackground(color);
            label.setForeground(Color.WHITE);
            label.setHorizontalAlignment(SwingConstants.CENTER);
            label.setPreferredSize(new Dimension(22, 16)); // Slightly narrower to fit all 4
            label.setMinimumSize(new Dimension(22, 16));
            label.setFont(FontUtils.getSmallFont());
            return label;
        }
    }
}
