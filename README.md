SuperComputer Project Manual (v4.8a)

1. Introduction

The SuperComputer Project (SCP) is a distributed task management system designed for clusters of nodes.
SCP enables remote commands, node self-checks, and secure arithmetic evaluations while offering both a graphical (GUI) and a text-based (CUI) interface.

What`s New (v4.8a):

Security Enhancements:
TLS for TCP Communications: All TCP traffic can be encrypted using TLS (if certificate and key files are present in SCP_config).

HMAC Verification: UDP discovery messages now include an HMAC to ensure authenticity.

Handshake Refresh: The authentication token is automatically refreshed every 5 minutes via a secure handshake mechanism.

Rate Limiting: Prevents abuse by limiting the number of connections from a single IP.

Cleanup: Unused and deprecated features have been removed.

2. Architecture & Key Features

Distributed Task Management:
SCP uses UDP broadcasts for node discovery and TCP (optionally wrapped with TLS) for task communication between master and worker nodes.

Security Measures:
TLS Encryption: Protects TCP communication.

HMAC for Discovery: Ensures that UDP discovery messages are genuine.

Handshake Refresh: Periodically updates the shared authentication token.

Rate Limiting: Mitigates connection abuse and potential DoS attacks.

Safe Evaluation:
SCP includes a safe_eval function that securely evaluates arithmetic expressions using a restricted Python AST.

User Interfaces:
CUI (Console UI): Uses the curses library for an interactive terminal-based experience.

GUI (Graphical UI): Uses tkinter for a windowed command interface.

Configuration & Logging:
SCP creates a SCP_config directory for persistent data such as log files (scp.log) and external commands (user_cmds.json).

3. Command-Line Arguments

When launching SCP, you can use the following options:

--gui
Launches SCP in GUI mode.

--color <color>
Sets the UI text color (e.g., blue, red).

--auth <token>
Sets a custom authentication token for task verification.

--role <master|worker>
Specifies the node role. If not provided, the node defaults to master.

Note: With version 4.8a, secure TLS communication and rate limiting are automatically enabled if the necessary certificate files exist.

4. Command Descriptions

help
Usage: help
Description: Displays a list of available commands and their descriptions.

exit
Usage: exit
Description: Exits the command prompt.

nsc
Usage: nsc
Description: Runs a self-check on the local node, returning details like session ID and uptime.

nsc_all
Usage: nsc_all
Description: Requests self-checks from all discovered nodes.

nodes
Usage: nodes
Description: Lists the IP addresses of all discovered nodes.

status_all
Usage: status_all
Description: Retrieves the list of current tasks running on all nodes.

clear
Usage: clear
Description: Clears the output window or terminal.

quarantine
Usage: quarantine <on|off> [target]
Description: Toggles quarantine mode. If no target is specified, the command is broadcast to all nodes; otherwise, it targets a specific node (matched by session ID). A timed prompt awaits confirmation on remote nodes.

cal
Usage: cal <expression>
Description: Safely evaluates an arithmetic expression using a restricted evaluation function.

addcmd
Usage: addcmd <command_name> <lambda code>
Description: Registers a new external command. New commands require approval before they become active in subsequent sessions.

switch_role
Usage: switch_role <master|worker>
Description: Switches the node's role within the cluster.

Note: The handshake process (for updating the auth token) is handled automatically and is not exposed as a user command.

5. Networking & Distributed Tasks

Discovery:
Nodes use UDP on port 50000 to broadcast a discovery message. Each message includes an HMAC to validate its authenticity. Discovered nodes are tracked and cleaned up if inactive.

Task Communication:
TCP port 50001 is used for sending and receiving JSON-based task requests and responses. If TLS is enabled, these connections are secured.

Timed Input for Remote Commands:
Remote quarantine requests employ a timed prompt (10 seconds) to await a response; lack of input results in the command being declined.

Security & Rate Limiting

TLS Encryption:
Wraps TCP sockets to secure communications (requires valid certificate and key files in SCP_config).

HMAC Verification:
Ensures that discovery messages and certain task communications are authentic by using the shared authentication token.

Handshake Refresh:
Every 5 minutes, the authentication token is updated via a secure handshake process with all discovered nodes.

Rate Limiting:
Limits the number of allowed connections from a single IP within a given window to help prevent abuse.

6. Configuration & Logging

Configuration Folder:
Persistent data such as logs and user-defined commands are stored in the SCP_config directory.

Log Files:
The scp.log file records startup details, command executions, errors, node discovery events, and security-related events.

Troubleshooting & Debugging

Error Logging:
Refer to the scp.log file for detailed error messages and system logs.

Common Issues:
Missing dependencies may prevent the GUI or CUI from launching.

Incorrect command-line arguments can usually be resolved by reviewing the help message (help command).

7. Final Notes

Versioning:
This manual applies to SCP version 4.8a. Future updates may introduce additional features or modifications.

Support & Contributions:
Contributions, bug reports, and feature requests are welcome. Please open an issue report or submit a pull request on GitHub.
