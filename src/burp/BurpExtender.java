package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import model.Config;
import scanner.ScannerEngine;
import scanner.NucleiScanner;
import ui.MainTab;
import ui.ContextMenuFactory;
import utils.Logger;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private ScannerEngine scannerEngine;
    private MainTab mainTab;
    private Logger logger;
    private Config config;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logger = new Logger(api.logging());
        this.config = new Config(api.persistence());

        api.extension().setName("Nuclei Scanner+");

        // Initialize UI first so scanner can use it for logging
        mainTab = new MainTab(api, config);
        api.userInterface().registerSuiteTab("Nuclei Scanner+", mainTab);

        // Initialize Scanner Engine
        scannerEngine = new ScannerEngine(api, config);
        // Only add NucleiScanner, pass mainTab for UI logging
        scannerEngine.addModule(new NucleiScanner(api, config, mainTab));

        // Register the scanner engine for Burp's internal scanning
        api.scanner().registerScanCheck(scannerEngine);

        // Register Context Menu
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuFactory(api, scannerEngine, mainTab, config));

        logger.info("Nuclei Scanner+ extension loaded successfully.");
    }
}
