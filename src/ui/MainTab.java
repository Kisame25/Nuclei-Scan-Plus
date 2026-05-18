package ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import model.Config;
import model.ScanTask;
import utils.FontUtils;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.BufferedReader;
import java.io.InputStreamReader;


public class MainTab extends JTabbedPane {

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
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public MainTab(MontoyaApi api, Config config) {
        this.api = api;
        this.config = config;
        this.resultsTableModel = new ResultsTableModel();
        this.taskTableModel = new TaskTableModel();

        setupDashboard();
        setupSettings();
        setupLogs();
    }

    public void addTask(ScanTask task) {
        taskTableModel.addTask(task);
    }

    public void updateTasks() {
        taskTableModel.updateTask();
        if (currentSelectedTask != null) {
            resultsTableModel.setIssues(currentSelectedTask.getIssues());
        }
    }
    
    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = dateFormat.format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
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
        sidebarHeader.add(tasksLabel, BorderLayout.NORTH);
        
        sidebar.add(sidebarHeader, BorderLayout.NORTH);

        tasksTable = new JTable(taskTableModel);
        tasksTable.setRowHeight(120); // More room
        tasksTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tasksTable.setShowGrid(false);
        tasksTable.setIntercellSpacing(new Dimension(0, 0));
        tasksTable.setDefaultRenderer(Object.class, new TaskCellRenderer());
        tasksTable.setBackground(UIManager.getColor("Table.background"));

        // Right-click to select row
        tasksTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = tasksTable.rowAtPoint(e.getPoint());
                    if (row != -1) {
                        tasksTable.setRowSelectionInterval(row, row);
                    }
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

        // Popup Menu for Tasks
        JPopupMenu taskPopupMenu = new JPopupMenu();
        JMenuItem stopItem = new JMenuItem("Stop Task");
        stopItem.addActionListener(e -> {
            int row = tasksTable.getSelectedRow();
            if (row != -1) {
                ScanTask task = taskTableModel.getTaskAt(row);
                task.stop();
                updateTasks();
            }
        });
        JMenuItem deleteItem = new JMenuItem("Delete Task");
        deleteItem.addActionListener(e -> {
            int row = tasksTable.getSelectedRow();
            if (row != -1) {
                ScanTask task = taskTableModel.getTaskAt(row);
                task.stop();
                taskTableModel.removeTask(task);
                
                if (currentSelectedTask == task) {
                    currentSelectedTask = null;
                    SwingUtilities.invokeLater(() -> {
                        selectedTaskLabel.setText("Select a task to view details");
                        resultsTableModel.setIssues(new ArrayList<>());
                        requestViewer.setRequest(null);
                        responseViewer.setResponse(null);
                    });
                }
            }
        });
        taskPopupMenu.add(stopItem);
        taskPopupMenu.add(deleteItem);
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
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row != -1) {
                    AuditIssue issue = resultsTableModel.getIssueAt(row);
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
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(200, 200, 200));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        logPanel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("Clear Logs");
        clearBtn.addActionListener(e -> logArea.setText(""));
        toolbar.add(clearBtn);
        logPanel.add(toolbar, BorderLayout.NORTH);
        
        addTab("Logs", logPanel);
    }

    private class TaskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            ScanTask task = (ScanTask) value;
            
            // Outer wrapper for margin - Bottom only
            JPanel wrapper = new JPanel(new BorderLayout());
            wrapper.setBorder(BorderFactory.createEmptyBorder(4, 4, 8, 4));
            wrapper.setOpaque(true);
            wrapper.setBackground(UIManager.getColor("Table.background"));

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
            card.setBackground(isSelected ? new Color(42, 54, 70) : new Color(54, 54, 54));
            card.setBorder(BorderFactory.createEmptyBorder(12, 15, 12, 15));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;

            // 1. Title
            JLabel nameLabel = new JLabel(task.getId() + ". " + task.getName());
            nameLabel.setFont(FontUtils.getTitleFont());
            nameLabel.setForeground(Color.WHITE);
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.weightx = 1.0;
            card.add(nameLabel, gbc);

            // 2. Subtitle / Streaming Log
            String subText = task.getStatus().equalsIgnoreCase("Finished") ? "Audit finished" : "Auditting";
            
            // Truncate long log lines
            if (subText.length() > 40) subText = subText.substring(0, 37) + "...";

            JLabel subLabel = new JLabel(subText);
            subLabel.setFont(FontUtils.getSubTitleFont());
            subLabel.setForeground(new Color(160, 160, 160));
            gbc.gridy = 1; gbc.insets = new Insets(2, 0, 12, 0); // More room below subtitle
            card.add(subLabel, gbc);

            // 3. Progress Bar
            JProgressBar progressBar = new JProgressBar(0, 100);
            progressBar.setValue(task.getProgress());
            progressBar.setPreferredSize(new Dimension(100, 4));
            progressBar.setForeground(new Color(0, 120, 215));
            progressBar.setBackground(new Color(50, 50, 50));
            progressBar.setBorderPainted(false);
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
            if (task.getStatus().equalsIgnoreCase("Finished")) statusLabel.setForeground(new Color(0, 180, 0));
            else if (task.getStatus().equalsIgnoreCase("Stopped")) statusLabel.setForeground(Color.RED);
            else statusLabel.setForeground(new Color(180, 180, 180));
            
            bottomGbc.gridx = 0; bottomGbc.gridy = 0; bottomGbc.weightx = 1.0;
            bottomGbc.anchor = GridBagConstraints.WEST;
            bottomRow.add(statusLabel, bottomGbc);

            // Issues Container
            JPanel issuePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
            issuePanel.setOpaque(false);
            JLabel issuesText = new JLabel("Issues: ");
            issuesText.setFont(FontUtils.getSubTitleFont());
            issuesText.setForeground(new Color(160, 160, 160));
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
