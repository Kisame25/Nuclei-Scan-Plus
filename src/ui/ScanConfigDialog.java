package ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import model.Config;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import utils.FontUtils;

public class ScanConfigDialog extends JDialog {
    private boolean confirmed = false;
    private final MontoyaApi api;
    private final List<HttpRequestResponse> selectedItems;
    private HttpRequestEditor requestViewer;
    
    // 1. Dynamic Nuclei Checkboxes (Top)
    private final Map<String, JCheckBox> nucleiDirCheckboxes = new HashMap<>();

    // 2. Single Template Selection (Middle)
    private final JTextField singleTemplateField;

    // 3. Custom Args (Bottom)
    private final JCheckBox customArgsCheckbox;
    private final JTextField customArgsField;
    private final JCheckBox scanPostReq;

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel contentPanel = new JPanel(cardLayout);
    private final JList<String> sidebarList;

    public ScanConfigDialog(Frame owner, MontoyaApi api, Config globalConfig, List<HttpRequestResponse> selectedItems) {
        super(owner, "Nuclei Scan Configuration", true);
        this.api = api;
        this.selectedItems = selectedItems;
        
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(960, 720));

        // Sidebar Navigation
        String[] navItems = {" 🎯 Targets", " ⚙️ Options"};
        sidebarList = new JList<>(navItems);
        sidebarList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sidebarList.setSelectedIndex(0); // Default to Targets
        
        // Custom renderer for larger font and padding
        sidebarList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                label.setFont(FontUtils.getTitleFont());
                label.setBorder(BorderFactory.createEmptyBorder(12, 10, 12, 10));
                return label;
            }
        });
        
        sidebarList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                cardLayout.show(contentPanel, sidebarList.getSelectedValue());
            }
        });

        JScrollPane sidebarScroll = new JScrollPane(sidebarList);
        sidebarScroll.setPreferredSize(new Dimension(180, 0));
        add(sidebarScroll, BorderLayout.WEST);

        // Content Panels
        add(contentPanel, BorderLayout.CENTER);

        // 1. Request Card
        JPanel requestCard = new JPanel(new BorderLayout());
        if (selectedItems.size() == 1) {
            this.requestViewer = api.userInterface().createHttpRequestEditor();
            requestViewer.setRequest(selectedItems.get(0).request());
            requestCard.add(requestViewer.uiComponent(), BorderLayout.CENTER);
        } else {
            JPanel multiUrlPanel = new JPanel(new BorderLayout());
            multiUrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            
            JLabel titleLabel = new JLabel("Scanning multiple items (" + selectedItems.size() + " total):");
            titleLabel.setFont(FontUtils.getSubTitleFont());
            titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
            multiUrlPanel.add(titleLabel, BorderLayout.NORTH);

            UrlsTableModel tableModel = new UrlsTableModel(selectedItems);
            JTable urlTable = new JTable(tableModel);
            
            // Set column widths
            urlTable.getColumnModel().getColumn(0).setPreferredWidth(50);
            urlTable.getColumnModel().getColumn(0).setMaxWidth(100);
            
            multiUrlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);
            requestCard.add(multiUrlPanel, BorderLayout.CENTER);
        }
        contentPanel.add(requestCard, " 🎯 Targets");

        // 2. Nuclei Configuration Card (Reordered)
        JPanel configCard = new JPanel(new GridBagLayout());
        configCard.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        int row = 0;

        // --- SECTION 1: Nuclei Template Selection (Top) ---
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3;
        JLabel nucleiTplLabel = new JLabel("Template Categories");
        nucleiTplLabel.setFont(nucleiTplLabel.getFont().deriveFont(Font.BOLD, 13f));
        configCard.add(nucleiTplLabel, gbc);

        gbc.gridy = row++; gbc.gridwidth = 3; gbc.insets = new Insets(5, 8, 15, 8);
        JPanel tplPanel = new JPanel(new GridLayout(0, 3, 5, 5));
        populateNucleiTemplates(globalConfig.getTemplatesPath(), tplPanel);
        configCard.add(tplPanel, gbc);

        // --- SECTION 2: Single Template Selection (Middle) ---
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3; gbc.insets = new Insets(15, 8, 8, 8);
        JLabel singleLabel = new JLabel("Single Template Selection");
        singleLabel.setFont(singleLabel.getFont().deriveFont(Font.BOLD, 13f));
        configCard.add(singleLabel, gbc);

        gbc.gridy = row++; gbc.gridwidth = 1; gbc.insets = new Insets(5, 8, 15, 8);
        configCard.add(new JLabel("Select File (.yaml):"), gbc);
        singleTemplateField = new JTextField(30);
        gbc.gridx = 1; configCard.add(singleTemplateField, gbc);
        JButton browseSingleBtn = new JButton("Browse");
        browseSingleBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            String rootPath = globalConfig.getTemplatesPath();
            if (rootPath != null && !rootPath.isEmpty()) {
                File root = new File(rootPath);
                if (root.exists()) fc.setCurrentDirectory(root);
            }
            fc.setFileFilter(new FileNameExtensionFilter("Nuclei Template (*.yaml, *.yml)", "yaml", "yml"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                singleTemplateField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        gbc.gridx = 2; configCard.add(browseSingleBtn, gbc);

        // --- SECTION 3: Additional Nuclei Options (Bottom) ---
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3; gbc.insets = new Insets(15, 8, 8, 8);
        JLabel customLabel = new JLabel("Advanced Arguments");
        customLabel.setFont(customLabel.getFont().deriveFont(Font.BOLD, 13f));
        configCard.add(customLabel, gbc);

        gbc.gridy = row++; gbc.gridwidth = 1; gbc.insets = new Insets(5, 8, 5, 8);
        customArgsCheckbox = new JCheckBox("Custom Arguments:");
        configCard.add(customArgsCheckbox, gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        customArgsField = new JTextField(30);
        customArgsField.setEnabled(false);
        customArgsCheckbox.addActionListener(e -> customArgsField.setEnabled(customArgsCheckbox.isSelected()));
        configCard.add(customArgsField, gbc);

        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3;
        JLabel helpLabel = new JLabel("e.g., -rl 10 -v -debug. These will be appended to the command.");
        helpLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        configCard.add(helpLabel, gbc);

        // In nuclei when scan it not use the original request from burp suite 
        // Instead it just send what in side the payload.
        // This option allow user to controll the req want to scan with option keep original request when user click on check
        // And normal request scan
        gbc.gridy = row++; gbc.gridheight = 1; gbc.insets = new Insets(5, 8, 5, 8);
        scanPostReq = new JCheckBox("Scan Post Method");
        if (selectedItems.size() > 1) {
            scanPostReq.setEnabled(false);
            scanPostReq.setToolTipText("Scan Post Method is only available for single request scans.");
        }
        configCard.add(scanPostReq, gbc);


        // Spacer
        gbc.gridy = row++; gbc.weighty = 1.0;
        configCard.add(new JPanel(), gbc);

        contentPanel.add(new JScrollPane(configCard), " ⚙️ Options");
  
        cardLayout.show(contentPanel, sidebarList.getSelectedValue());

        // Bottom Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton scanButton = new JButton("Scan");
        scanButton.addActionListener(e -> { confirmed = true; setVisible(false); });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> setVisible(false));
        buttonPanel.add(scanButton); buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(owner);
    }

    private void populateNucleiTemplates(String rootPath, JPanel panel) {
        if (rootPath == null || rootPath.isEmpty()) {
            panel.add(new JLabel("Templates path not set in Settings!"));
            return;
        }

        File root = new File(rootPath);
        if (!root.exists() || !root.isDirectory()) {
            panel.add(new JLabel("Invalid templates path!"));
            return;
        }

        File[] files = root.listFiles();
        if (files == null) return;

        for (File f : files) {
            if (f.isDirectory() && !f.getName().startsWith(".")) {
                if(!f.getName().equals("helpers") && !f.getName().equals("profiles")){
                    JCheckBox cb = new JCheckBox(f.getName(), false);
                    nucleiDirCheckboxes.put(f.getName(), cb);
                    panel.add(cb);
                }
            }
        }
        
        if (nucleiDirCheckboxes.isEmpty()) {
            panel.add(new JLabel("No subdirectories found."));
        }
    }

    public boolean isConfirmed() { return confirmed; }
    
    public List<String> getSelectedNucleiTemplates() {
        List<String> selected = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : nucleiDirCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selected.add(entry.getKey());
            }
        }
        return selected;
    }

    public String getSingleTemplatePath() {
        return singleTemplateField.getText().trim();
    }

    public String getCustomNucleiArgs() {
        return customArgsCheckbox.isSelected() ? customArgsField.getText().trim() : "";
    }

    public boolean scanPostReq() {
        return scanPostReq.isSelected();
    }

    public burp.api.montoya.http.message.requests.HttpRequest getEditedRequest() {
        return (requestViewer != null) ? requestViewer.getRequest() : null;
    }
}
