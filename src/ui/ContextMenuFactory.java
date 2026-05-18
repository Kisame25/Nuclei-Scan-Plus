package ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import model.Config;
import model.ScanTask;
import model.ScanOptions;
import scanner.ScannerEngine;
import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.awt.Frame;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class ContextMenuFactory implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ScannerEngine scannerEngine;
    private final MainTab mainTab;
    private final Config config;
    private final ExecutorService scanExecutor = Executors.newFixedThreadPool(10); // Run up to 10 items in parallel

    public ContextMenuFactory(MontoyaApi api, ScannerEngine scannerEngine, MainTab mainTab, Config config) {
        this.api = api;
        this.scannerEngine = scannerEngine;
        this.mainTab = mainTab;
        this.config = config;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();
        
        // Support Repeater, Proxy, Logger, and Intruder by checking for request/response data
        List<HttpRequestResponse> selectedItems = new ArrayList<>();
        
        if (event.messageEditorRequestResponse().isPresent()) {
            selectedItems.add(event.messageEditorRequestResponse().get().requestResponse());
        } else if (!event.selectedRequestResponses().isEmpty()) {
            selectedItems.addAll(event.selectedRequestResponses());
        }

        if (selectedItems.isEmpty()) {
            return menuList;
        }

        // Direct item
        JMenuItem item = new JMenuItem("Nuclei Scanner+");
        item.addActionListener(e -> {
            Frame parent = (Frame) SwingUtilities.getWindowAncestor(mainTab);
            ScanConfigDialog dialog = new ScanConfigDialog(parent, api, config, selectedItems.get(0));
            dialog.setVisible(true);

            if (dialog.isConfirmed()) {
                ScanOptions options = new ScanOptions(
                        dialog.getSingleTemplatePath(),
                        dialog.getCustomNucleiArgs(),
                        dialog.scanPostReq()
                );
                
                for (String tpl : dialog.getSelectedNucleiTemplates()) {
                    options.addNucleiTemplate(tpl);
                }

                ScanTask task = new ScanTask("Nuclei Audit (" + selectedItems.size() + " items)");
                options.setTask(task);
                mainTab.addTask(task);

                // Use the edited request for the first item (where the dialog was shown)
                burp.api.montoya.http.message.requests.HttpRequest editedRequest = dialog.getEditedRequest();
                
                new Thread(() -> {
                    AtomicInteger completedItems = new AtomicInteger(0);
                    int totalItems = selectedItems.size();

                    for (int i = 0; i < totalItems; i++) {
                        final int index = i;
                        HttpRequestResponse originalMessage = selectedItems.get(i);
                        
                        scanExecutor.submit(() -> {
                            try {
                                if (task.isStopped()) return;

                                HttpRequestResponse messageToScan = originalMessage;
                                // If it's the first item, use the edited request
                                if (index == 0 && editedRequest != null) {
                                    messageToScan = HttpRequestResponse.httpRequestResponse(editedRequest, originalMessage.response());
                                }

                                runScan(messageToScan, task, options);
                            } finally {
                                int currentCount = completedItems.incrementAndGet();
                                task.setProgress((int) (((double) currentCount / totalItems) * 100));
                                if (currentCount == totalItems) {
                                    task.setStatus("Finished");
                                }
                                mainTab.updateTasks();
                            }
                        });
                    }
                }).start();
            }
        });
        menuList.add(item);
        
        return menuList;
    }

    private void runScan(HttpRequestResponse message, ScanTask task, ScanOptions options) {
        List<AuditIssue> issues = scannerEngine.activeAudit(message, null, options).auditIssues();

        if (issues != null) {
            for (AuditIssue issue : issues) {
                task.addIssue(issue);
                api.siteMap().add(issue);
            }
        }
    }
}
