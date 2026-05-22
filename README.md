# Nuclei Scanner+ (Burp Suite Extension)

Nuclei Scanner+ is a powerful Burp Suite extension built on the Montoya API that seamlessly integrates the **Nuclei** vulnerability scanner into your manual testing workflow. It allows security researchers to leverage Nuclei's extensive template library directly from within Burp Suite, providing a centralized dashboard for managing scans and viewing results.

## What is this project for?

This extension is designed for penetration testers and bug hunters who want to combine the manual flexibility of Burp Suite with the automated, template-based power of Nuclei. Instead of switching back and forth between the terminal and Burp, you can trigger targeted Nuclei scans on specific requests, monitor their progress, and analyze findings—all within the Burp Suite interface.

## Key Features

- **Integrated Nuclei Dashboard:** A modern, card-based UI to track multiple scan tasks with real-time progress bars.
- **Advanced Task Management:** 
    - **Single URL Optimization:** Automatically uses `-u` for single targets and `-l` for batch scans.
    - **Smart Naming:** Tasks are automatically named after the target URL for easy identification.
- **Comprehensive Reporting:** 
    - **HTML:** Professional, styled reports with collapsible evidence sections.
    - **Markdown:** Clean formatting ready for Bug Bounty platform submissions.
    - **JSON:** Raw data export for automation and backup.
- **Persistent Sessions (Import/Export):** 📥 Import previously exported JSON results back into the extension to restore full scan tasks, including all Request/Response evidence.
- **Resource & Memory Safety:** 
    - **Ghost Process Protection:** Automatically kills background Nuclei processes when tasks are deleted or the extension is unloaded.
    - **Memory Optimization:** Implements log rotation (1,000-line limit) and explicit reference clearing to prevent memory leaks during long sessions.
- **Interactive Results:** 
    - **Table Sorting:** Click column headers (Severity, Finding, URL) to organize findings.
    - **Full Evidence Mapping:** Found vulnerabilities map directly to the original Request/Response for manual verification.
- **One-Click Updates:** Update both the Nuclei engine and its templates directly from the Settings tab.

## How to Use

### 1. Installation
1. Ensure you have [Nuclei](https://github.com/projectdiscovery/nuclei) installed on your system.
2. Download the latest `nuclei-scan-plus.jar`.
3. In Burp Suite, navigate to **Extensions** -> **Installed**.
4. Click **Add**, select the JAR file, and follow the prompts to install.

### 2. Configuration
1. Go to the **Nuclei Scanner+** -> **Settings** tab.
2. Set the **Nuclei Binary Path** (e.g., `C:\tools\nuclei.exe`).
3. Set the **Nuclei Templates Path**.
4. Click **Save Configuration**.

### 3. Running a Scan
- **Start Scanning:** Right-click any request in Burp (Proxy, Repeater, etc.) -> **Extensions** -> **Nuclei Scanner+** -> Choose your scan mode.
- **Monitor:** Switch to the **Dashboard** tab to see your tasks.
- **Stop/Delete:** Click the three dots (⋮) on a task card to stop a running scan or delete the task data.

### 4. Managing Results
- **Sort Findings:** Click column headers in the Results table to sort by severity or name.
- **Exporting:** Right-click a task (or click ⋮) -> **📤 Export Report** -> Select HTML, Markdown, or JSON. Filenames are automatically timestamped.
- **Importing:** Click the **📥 Import** button in the sidebar header to load an old JSON report. This restores the task and all its evidence to your dashboard.
- **Clearing Logs:** Use the "Clear Logs" button in the Logs tab to wipe the terminal output.

## Technical Details
- **API:** Burp Montoya API
- **Language:** Java
- **Format Support:** HTML5, CommonMark, JSON
- **Memory Management:** Auto-trimming log buffers and process lifecycle hooks.

---
*Developed for modern security workflows.*
