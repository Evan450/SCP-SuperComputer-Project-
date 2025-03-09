SuperComputer Project Manual

Introduction

The SuperComputer Project (SCP) is designed for distributed task management within a cluster of nodes. 
It enables remote commands, node self-checks, and safe arithmetic evaluations, while providing both graphical (GUI) and text-based (CUI) interfaces.

Architecture & Key Features

Distributed Task Management:
Uses UDP broadcasts to discover nodes and TCP for task communication between master and worker nodes.

Safe Evaluation:
Contains a safe_eval function that securely evaluates arithmetic expressions using a restricted Python AST.

User Interfaces:
CUI (Console UI): Uses the curses library to present a terminal-based interactive prompt.
GUI (Graphical UI): Uses tkinter to offer a windowed interface.

Configuration & Logging:
SCP creates a SCP_config folder for log files (scp.log) and stores external user commands in user_cmds.json.

Command-Line Arguments
When running SCP, you can provide:

--gui: Launches the script in GUI mode.
--color <color>: Sets the UI text color (e.g., blue, red).
--auth <token>: Sets a custom authentication token for distributed tasks.
--role <master|worker>: Specifies the node role. Defaults to master if not provided.

Detailed Command Descriptions

help
Usage: help
Description: Displays a list of available commands and their descriptions.

exit
Usage: exit
Description: Exits the command prompt.

nsc
Usage: nsc
Description: Runs a self-check on the local node and returns details like session ID and uptime.

nsc_all
Usage: nsc_all
Description: Requests a self-check from all discovered nodes in the network.

nodes
Usage: nodes
Description: Lists the IP addresses of all discovered nodes.

status_all
Usage: status_all
Description: Retrieves the list of current tasks running on all nodes.

clear
Usage: clear
Description: Clears the output window (or terminal).

quarantine
Usage: quarantine <on|off> [target]
Description: Toggles quarantine mode on either all nodes (when no target is provided) or a specific node (when a target session ID is provided). A timed prompt awaits confirmation on remote nodes.

cal
Usage: cal <expression>
Description: Safely evaluates arithmetic expressions using a restricted evaluation function.

addcmd
Usage: addcmd <command_name> <lambda code>
Description: Allows you to register new commands. Newly added commands require approval to be activated in subsequent sessions.

switch_role
Usage: switch_role <master|worker>
Description: Switches the node's role within the cluster.

External & User-Defined Commands
SCP supports adding external commands via the addcmd command. When a new command is detected:

The script prompts for approval (if ran interactively).
Unapproved commands will not be executed until confirmed.
These commands are saved in the user_cmds.json file for persistence.

User Interface Details

CUI (Console User Interface):
Utilizes the curses library to show current node status, a dynamic prompt, and output window.
Note: If --role isn’t specified, a warning is issued and defaults to master mode.

GUI (Graphical User Interface):
Uses tkinter to create a window with an output text box, input field, and a send button for command entry.

Networking & Distributed Tasks

Discovery:
Nodes broadcast and listen on UDP port 50000 for service discovery.
Discovered nodes are tracked with a timeout cleanup mechanism.

Task Communication:

TCP port 50001 is used for sending and receiving JSON-based task requests and responses (e.g., node self-check, quarantine commands).

Timed Input for Remote Commands:
Remote quarantine requests use a timed prompt (10 seconds) to await a user’s decision. If no response is received, the command is declined by default.

Configuration & Logging

Configuration Folder:
All persistent data, such as logs and user commands, is stored in the SCP_config directory.

Log Files:
The scp.log file records startup details, command executions, errors, and node discovery events.

Troubleshooting & Debugging

Error Logging:
Check the scp.log file for detailed error messages and activity logs.

Common Issues:

Missing dependencies may prevent the GUI or CUI from launching.
Incorrect command-line arguments can be resolved by referring to the help message.

Final Notes
Versioning:
This manual applies to SCP version 4.6a. Future updates might introduce new features or modifications, please note that I will attempt to keep this manual as up-to-date as possible though, I am only a one-man-army, so please do not expect it to be soon.

Support & Contributions:
Contributions, bug reports, and/or feature requests are welcome. Please open an issue or submit a pull request on GitHub.
