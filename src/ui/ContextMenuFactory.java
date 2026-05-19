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
            ScanConfigDialog dialog = new ScanConfigDialog(parent, api, config, selectedItems);
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
                    try {
                        List<HttpRequestResponse> itemsToScan = new ArrayList<>(selectedItems);
                        if (editedRequest != null && !itemsToScan.isEmpty()) {
                            HttpRequestResponse firstItem = itemsToScan.get(0);
                            itemsToScan.set(0, HttpRequestResponse.httpRequestResponse(editedRequest, firstItem.response()));
                        }

                        if (itemsToScan.size() > 1) {
                            // Batch Scan
                            task.setStatus("Auditting (Batch)");
                            mainTab.updateTasks();
                            
                            runScanBatch(itemsToScan, task, options);
                            
                            task.setProgress(100);
                            task.setStatus("Finished");
                            mainTab.updateTasks();
                        } else if (!itemsToScan.isEmpty()) {
                            // Single Scan
                            runScan(itemsToScan.get(0), task, options);
                            task.setProgress(100);
                            task.setStatus("Finished");
                            mainTab.updateTasks();
                        }
                    } catch (Exception ex) {
                        api.logging().logToError("Error in scan thread: " + ex.getMessage());
                        task.setStatus("Error");
                        mainTab.updateTasks();
                    }
                }).start();
            }
        });
        menuList.add(item);
        
        return menuList;
    }

    private void runScanBatch(List<HttpRequestResponse> messages, ScanTask task, ScanOptions options) {
        List<AuditIssue> issues = scannerEngine.activeAuditBatch(messages, null, options).auditIssues();

        if (issues != null) {
            for (AuditIssue issue : issues) {
                task.addIssue(issue);
                api.siteMap().add(issue);
            }
        }
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
