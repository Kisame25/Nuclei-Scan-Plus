# Nuclei Scanner+ (Burp Suite Extension)

Nuclei Scanner+ is a powerful Burp Suite extension built on the Montoya API that seamlessly integrates the **Nuclei** vulnerability scanner into your manual testing workflow. It allows security researchers to leverage Nuclei's extensive template library directly from within Burp Suite, providing a centralized dashboard for managing scans and viewing results.

## What is this project for?

This extension is designed for penetration testers and bug hunters who want to combine the manual flexibility of Burp Suite with the automated, template-based power of Nuclei. Instead of switching back and forth between the terminal and Burp, you can trigger targeted Nuclei scans on specific requests, monitor their progress, and analyze findings—all within the Burp Suite interface.

## Key Features

- **Integrated Nuclei Dashboard:** A dedicated "Nuclei Scanner+" tab featuring a modern UI to track multiple scan tasks.
- **Task Management:** Real-time monitoring of scan progress, logs, and issue counts (High, Medium, Low, Info).
- **Seamless Result Mapping:** Nuclei findings are automatically converted into Burp Suite Audit Issues, complete with matched requests and responses (when JSON output is used).
- **Flexible Scanning Options:**
    - **Active Scanning:** Trigger specific templates or categories via the context menu.
    - **Passive Scanning:** Optionally run Nuclei on requests as they flow through Burp.
    - **Burp XML Integration:** High-fidelity scan mode that exports Burp requests to XML for Nuclei to consume, preserving complex request structures.
- **Template Management:** Easily configure Nuclei binary paths and template directories.
- **One-Click Updates:** Update both the Nuclei engine and its templates directly from the extension settings.
- **Rich Visualization:** Custom "card-based" task view and detailed issue reporting.

## How to Use

### 1. Installation
1. Ensure you have [Nuclei](https://github.com/projectdiscovery/nuclei) installed on your system.
2. Download the latest `nuclei-scanner+.jar`.
3. In Burp Suite, navigate to **Extensions** -> **Installed**.
4. Click **Add**, select the JAR file, and follow the prompts to install.

### 2. Configuration
1. Navigate to the **Nuclei Scanner+** tab.
2. Select the **Settings** sub-tab.
3. Provide the absolute path to your `nuclei` executable (e.g., `C:\tools\nuclei.exe` or `/usr/local/bin/nuclei`).
4. Set the path to your **Nuclei Templates** directory.
5. (Optional) Use the **Update** buttons to ensure you have the latest engine and templates.
6. Click **Save Configuration**.

### 3. Running a Scan
- **From Context Menu:** Right-click any request in the Proxy, Repeater, or Site Map tabs. Select **Extensions** -> **Nuclei Scanner+** and choose your desired scan option (e.g., "Full Scan", "Selected Templates").
- **From Dashboard:** View the progress of your triggered scans in the Dashboard sub-tab.

### 4. Analyzing Results
- Findings will appear in the **Dashboard** sub-tab under the specific task.
- Issues are also registered in Burp Suite's native **Issue Activity** (Target -> Issue activity).
- Selecting a finding in the Dashboard will show the associated Request and Response for further manual verification in Repeater or Intruder.

## Technical Details
- **API:** Burp Montoya API
- **Language:** Java
- **Dependencies:** Google Gson (for Nuclei JSON output parsing)
- **Engine:** Communicates with Nuclei via CLI for maximum compatibility with the latest templates.

---
*Developed for modern security workflows.*
