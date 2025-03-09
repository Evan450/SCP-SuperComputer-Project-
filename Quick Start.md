SuperComputer Project
Quick-Start Guide

Note: For further details about each feature and command, please refer to the Manual (README).

1. Installation & Setup

Clone the Repository:

git clone https://github.com/Evan450/SCP-SuperComputer-Project-.git

Then CD into the directory

cd SCP-SuperComputer-Project-

Ensure The Dependencies Are Installed:

SCP supports both a text-based UI (CUI) and a graphical UI (GUI). Depending on your use-case, you may need to install:

For CUI (Terminal): Python’s built-in curses library (usually pre-installed on Unix-like systems)

For GUI: tkinter (comes with most Python installations)

Optional: matplotlib, numpy, imageio, sympy (for plotting and advanced math features)
Note: these are remnantes from an older version, You can still install them and they will work (however they will not, do anything), though please note that these will be removed in a later version.

Install missing libraries using pip:

pip install matplotlib numpy imageio sympy

Configuration Directory:

On the first run, SCP creates a configuration folder (SCP_config) that holds logs (scp.log) and any user-defined commands (user_cmds.json).

2. Running the Script

Default (CUI) Mode:

Run (Note: run the command when you are in the same directory as the script):

Python SCP.py

GUI Mode:

Launch with the --gui flag (ideal for master nodes with a graphical interface):

Python SCP.py --gui

Setting the Node Role:

By default, SCP runs as a master. To run as a worker use the following command:

Python SCP.py --role worker

Additional Options:

Set a custom UI text color: --color <color>

Set an authentication token: --auth <token>

3. Basic Commands

Once running, you can type the following commands at the prompt:

help – List all available commands.

nsc – Perform a local node self-check.

nsc_all – Request a node self-check from all discovered nodes.

nodes – List currently discovered nodes.

status_all – Show the status (active tasks) from all nodes.

quarantine – Toggle quarantine mode (usage: quarantine <on|off> [target]).

cal – Evaluate arithmetic expressions safely.

addcmd – Register a new external command.

switch_role – Change the node role (master/worker).

4. Next Steps

Have fun, and don`t forget to share any bugs you may encounter!
