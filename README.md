** Note: This project may require maintenance to work remotely, but it functions well locally. Hope to revisit and improve it when time permits, but I've been occupied with other projects. **

## Remote-Disk-Cleanup

**Description:**

Remote-Disk-Cleanup is a PowerShell script designed to automate the process of cleaning temporary files and caches across all user profiles on a remote computer. This tool performs the following tasks:

- Cleans temporary file paths across all user profiles.
- Erases Internet Explorer, Mozilla Firefox, and Google Chrome browser caches.
- Runs Windows Disk Cleanup with sageset parameters.
- Empties old Recycle Bin contents.
- Logs the cleanup process and reports the space recovered.

**Features:**

- **Local and Remote Execution:** The script can be executed locally or remotely using PowerShell remoting.
- **Verbose Logging:** Provides detailed logging for the cleanup process, which can be enabled or disabled based on preference.
- **WMI Repair:** Includes an option to repair the WMI repository if needed.
- **Disk Cleanup Automation:** Automates the Windows Disk Cleanup utility with predefined sageset parameters.
- **Cross-Browser Cache Cleaning:** Cleans caches for popular browsers including Internet Explorer, Mozilla Firefox, and Google Chrome.

**Usage:**

1. **Set Global Flags:**
   - `$global:LocalRun` to `true` for local execution or `false` for remote execution.
   - `$global:EnableVerbose` to `true` to enable verbose logging or `false` to disable it.
   - `$global:RepairWMI` to `true` to enable WMI repair or `false` to disable it.

2. **Run the Script:**
   - Execute the script with administrative privileges.
   - Follow the prompts to enter the computer name and credentials for remote execution.

## Disclaimer
Please note that while I have taken care to ensure the script works correctly, I am not responsible for any damage or issues that may arise from its use. Use this script at your own risk.

## License
This project is licensed under the terms of the GNU General Public License v3.0.
