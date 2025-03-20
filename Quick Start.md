SuperComputer Project – Quick-Start Guide (v4.8a)

For more details on each feature and command, see the Manual (README).

1. Installation and Setup

Clone the Repository:
git clone https://github.com/Evan450/SCP-SuperComputer-Project-.git

cd SCP-SuperComputer-Project-

Ensure the Dependencies are Installed:
SCP supports both text-based (CUI) and graphical (GUI) interfaces. Required libraries:

CUI (Terminal): Python’s built-in curses library (usually pre-installed on Unix-like systems)

GUI: tkinter (comes with most Python installations)

Configuration Directory:
On the first run, SCP creates a configuration folder (SCP_config) to hold log files (scp.log) and external commands (user_cmds.json).

2. Running the Script

Default (CUI) Mode:
Run the script from within the repository directory:

python SCP.py

GUI Mode:
Launch with the --gui flag (ideal for master nodes with a graphical interface):

python SCP.py --gui

Setting the Node Role:
By default, SCP runs as a master. To run as a worker:

python SCP.py --role worker

Additional Options:
Set a custom UI text color: --color <color>

Set an authentication token: --auth <token>

3. Basic Commands

Once running, enter the following commands at the prompt:
help – List available commands.

nsc – Perform a local node self-check.

nsc_all – Request a node self-check from all discovered nodes.

nodes – List discovered nodes.

status_all – Show current tasks on all nodes.

quarantine – Toggle quarantine mode (usage: quarantine <on|off> [target]).

cal – Evaluate arithmetic expressions safely.

addcmd – Register a new external command.

switch_role – Change the node role (master/worker).

4. Next Steps

Have fun—and don’t forget to report any bugs you encounter!
