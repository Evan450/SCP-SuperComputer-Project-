## Quick Start Guide

### Prerequisites

- **Python 3.7+** installed
- **Required packages**:
  - `cryptography` (`pip install cryptography`)
  - `psutil` (`pip install psutil`)
- **Optional packages**:
  - `netifaces` (`pip install netifaces`) for enhanced interface discovery
  - `curses` (usually included) for CUI enhancements
  - `tkinter` for GUI mode

### Installation

1. **Download the script**: place `SCP.py` in your working directory.
Note: To download the script using `git clone`: git clone https://github.com/Evan450/SCP-SuperComputer-Project-.git
2. **Install dependencies**:
   ```
   pip install cryptography psutil
   ```
3. **Run for the first time** to generate config folder:
   ```
   python3 SCP.py --auth <your_token>
   ```
   This creates `SCP_config/` alongside encrypted settings and logs.

### Initial Configuration

- **Authentication token**: `--auth <token>` (default: `defaultpass`)
- **Node role**: `--role master|worker` (default: `master`)
- **Mesh networking**: `--mesh`
- **GUI mode**: `--gui`
- **UI color**: `--color <color>`

Example:

```
python3 SCP.py --auth mysecret --role worker --mesh
```

### Using the SCP Prompt

Launch:

```
python3 SCP.py
```

At the `SCP> ` prompt:

- `help` — list all commands
- `status` — quick system summary
- `nsc` — node self-check diagnostics
- `nsc_all` — self-check across all nodes
- `mesh` — manage mesh networking
- `cal <expression>` — calculator
- `modules` — manage loadable modules
- `modules load <path>` — load a module file
- `modules list` — view loaded modules
- `modules approve <name>` — approve a pending module
- `modules info <name>` — view module metadata
- `modules unload <name>` — unload module

To load and use the **System Monitor** module (Note: The path must be complete and not abbreviated):

```
SCP> modules load SCP_config/system_monitor.py
SCP> modules approve system_monitor
SCP> sysinfo
```

Contributions, bug reports, and feature requests are welcome. Please open an issue report or submit a pull request on GitHub.
