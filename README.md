#Port Manager (v2.0)
A Windows PowerShell GUI for viewing active TCP connections, reviewing the applications that own them, and managing selected Windows Defender Firewall rules. Port Manager can run in the system tray and monitor connections in the background.

Security notice: This utility changes firewall rules and can disrupt network access. Review each rule before applying it. It is a monitoring and rule-management aid, not antivirus software or a guarantee that a process or connection is safe.

Features
View TCP listening sockets and established connections, with process name, PID, executable path, publisher/signature status, local and remote endpoints, and connection state.
Search and filter the live connection list.
Review untrusted or suspiciously named processes and receive alerts about untrusted established connections.
Add or remove trusted applications.
Create Windows Defender Firewall block rules for an application, remote IP address, or port, with optional durations.
Inspect and remove rules created by Port Manager.
Use learning mode to record applications observed during a period and review them afterward.
View, clear, and export alert history as CSV.
Run in the system tray, optionally start at sign-in, and configure refresh intervals.
Look up a selected process or port online.
Requirements
Windows with Windows Defender Firewall and Windows PowerShell.
Administrator approval is required for firewall changes and some startup settings.
The script uses built-in Windows PowerShell/.NET components; no separate PowerShell modules are specified by the project source.
Run
Download PortManager-OnlineCheck.ps1 from the repository.

Review the script before running it.

Right-click the script and choose Run with PowerShell, or open PowerShell and run:

sh

Copy
.\PortManager-OnlineCheck.ps1
Approve the Windows UAC prompt if requested.

The window’s close button hides Port Manager to the tray. Use Quit in the app or its tray menu to stop it.

Understanding connection direction
Listening (inbound-ready) means a local process is waiting for incoming connections. It does not by itself mean the port is reachable from the internet.
Established (2-way) means a TCP connection exists. The connection table alone does not identify which endpoint initiated it; choose the local inbound port or remote outbound port explicitly when creating a port rule.
Firewall rules and scope
Port rules can target TCP or UDP and can apply to all programs or, where available, only the selected application. The confirmation dialog shows the direction, protocol, scope, and duration. A port-wide rule may affect unrelated applications that use the same port. The application-wide block action creates inbound and outbound rules for the selected executable.

Windows Defender Firewall applies its own policy and rule precedence. Existing rules or organization-managed policies can affect the result; verify the active firewall configuration after making changes.

Data and privacy
Port Manager stores its settings, trusted-app list, learned-app list, block metadata, history, and error log under %ProgramData%\PortManager. Online lookups search selected port/process terms through your web browser; review the query before sharing sensitive process names.

Limitations
The live connection reader in the supplied script uses netstat -ano and parses TCP entries. UDP does not have TCP-style established/listening states and is not represented as a live UDP connection list by that reader. UDP support applies to creating firewall port rules.
A publisher/signature result or trusted status is only one signal; it does not establish that an application is safe.
Firewall changes require appropriate Windows permissions and may be limited by Group Policy or other management software.
Contributing

