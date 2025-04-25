## Manual

### 1. Overview

SuperComputer Project **v5.4b** is a distributed cluster management toolkit featuring secure communication, mesh networking, modular extensions, and diagnostic capabilities.

### 2. Architecture

- **SCP.py**: main application handling CLI, networking, security, and task dispatch.
- **SCP\_config/**: directory for encrypted configs, logs (`scp.log`), and user modules (`user_cmds.json`).

### 3. Command-Line Options

| Option           | Description                        |
| ---------------- | ---------------------------------- |
| `--auth <tk>`    | Set authentication token           |
| `--role <r>`     | Node role: `master` or `worker`    |
| `--mesh`         | Enable mesh networking             |
| `--gui`          | Launch in GUI mode                 |
| `--color <c>`    | Set text color in CUI              |
| `--bind-ip <ip>` | Bind sockets to specific interface |

### 4. Core Commands

- `help`, `exit`
- **System**:
  - `status`
  - `cal <expr>`
  - `interfaces`
- **Diagnostics**:
  - `nsc`, `nsc_all`
- **Networking**:
  - `nodes`, `mesh`
- **Security**:
  - `quarantine`, `quarantine_list`
- **Modules**:
  - `modules`

### 5. Module Development & Management

#### 5.1 Template Module

Use `Template_Module.py` as a blueprint:

```python
# Copy to SCP_config/your_module.py and update:
def get_module_info():
    return {"name":"your_module","version":"1.0","author":"You","description":"...","commands":{...}}

def template_cmd(args):
    return "Your implementation"

def register_commands():
    return {"template_cmd":(template_cmd, "Description")}
```

#### 5.2 Loading Modules

1. Copy your module file into `SCP_config/`.
2. Within SCP prompt:
   ```
   modules load SCP_config/your_module.py
   modules approve your_module
   ```
3. Run your commands:
   ```
   SCP> <cmd_of_your_module>
   ```

### 6. System Monitor Module

The example `System_Monitor.py` provides:

- **Commands**:
  - `sysinfo`: CPU, memory, disk, boot time summary
  - `proclist`: top processes by memory usage
  - `diskinfo`: per-partition disk usage
  - `netstat`: network I/O and active connections
  - `meminfo`: detailed RAM and swap stats
- **Installation**:
  ```
  pip install psutil
  ```
 `system_monitor.py` into `SCP_config/` and load as seen in 5.2, 2.

### 7. Security & Integrity

- **TLS** and **HMAC** for secure communications
- **IntegrityVerifier** checks critical file hashes on startup
- **Quarantine** controls to block misbehaving nodes

### 8. Troubleshooting

- Check missing dependencies: install via pip
- Review `scp.log` in `SCP_config/` for errors
- Module load issues: ensure correct file paths and approval

Contributions, bug reports, and feature requests are welcome. Please open an issue report or submit a pull request on GitHub.
