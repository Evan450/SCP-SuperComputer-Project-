#!/usr/bin/env python3
"""
 Copyright (C) 2025 Discover Interactive

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see https://choosealicense.com/licenses/gpl-3.0/ or https://www.gnu.org/licenses/gpl-3.0.en.html.

-- Updates and Secondary Header --

Name: SuperComputer Project (SCP)
Author: Discover Interactive
Version: 4.8a
Description:
  - Added security measures which include: TLS for TCP communication, HMAC verification, Handshake Refresh, and Rate limiting.
  - Cleaned up unused and deprecated features. 
"""

import os, sys, socket, threading, time, json, logging, uuid, argparse, base64, io, math, ast, operator as op, random, shlex, select, hmac, hashlib
from collections import deque

###############################################################################
# Persistent Configuration Folder Setup
###############################################################################
CONFIG_DIR = "SCP_config"
if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

LOG_FILE = os.path.join(CONFIG_DIR, "scp.log")
USER_CMDS_FILE = os.path.join(CONFIG_DIR, "user_cmds.json")

###############################################################################
# TLS Settings for TCP Communications
###############################################################################
USE_TLS = True
TLS_CERT = os.path.join(CONFIG_DIR, "cert.pem")
TLS_KEY  = os.path.join(CONFIG_DIR, "key.pem")
if USE_TLS:
    try:
        import ssl
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    except Exception as e:
        logging.error("TLS setup failed: %s", e)
        USE_TLS = False

###############################################################################
# Optional UI Libraries
###############################################################################
try:
    import curses
except ImportError:
    curses = None
try:
    import tkinter as tk
    from tkinter import scrolledtext
except ImportError:
    tk = None

###############################################################################
# Configuration, Command-Line Args, and Logging
###############################################################################
config = {
    "ui_mode": "cui",   # "cui" or "gui"
    "ui_color": "default",
    "auth_token": "defaultpass",
    "role": None
}

parser = argparse.ArgumentParser(
    description="SCP (SuperComputer Project) - Version: 4.7a\n"
                "On-run arguments:\n"
                "  --gui                : Launch in GUI mode (for master nodes)\n"
                "  --color <color>      : Set UI text color (e.g. 'blue')\n"
                "  --auth <token>       : Set the authentication token\n"
                "  --role <master|worker>: Set the node role in the cluster\n"
)
parser.add_argument("--gui", action="store_true", help="Launch in GUI mode")
parser.add_argument("--color", type=str, help="UI text color (e.g. 'blue')")
parser.add_argument("--auth", type=str, help="Authentication token")
parser.add_argument("--role", type=str, choices=["master", "worker"], help="Set node role (master/worker)")
args = parser.parse_args()
if args.gui:
    config["ui_mode"] = "gui"
if args.color:
    config["ui_color"] = args.color
if args.auth:
    config["auth_token"] = args.auth
if args.role:
    config["role"] = args.role
    role_defaulted = False
else:
    config["role"] = "master"
    role_defaulted = True

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logging.info("SCP starting up. UI mode: %s, color: %s, role: %s", config["ui_mode"], config["ui_color"], config["role"])

###############################################################################
# Globals for Networking & Task Management
###############################################################################
UDP_DISCOVERY_PORT = 50000
TCP_TASK_PORT = 50001
DISCOVERY_MESSAGE = "SCP_DISCOVER"
# For UDP, attach an HMAC using the shared secret (use the auth token as shared secret)
SHARED_SECRET = config["auth_token"]
RESPONSE_MESSAGE = "SCP_HERE"

discovered_nodes = {}
discovered_nodes_lock = threading.Lock()
quarantine_list = {}  # reserved for future use
session_id = str(uuid.uuid4())
quarantine_mode = False

message_queue = deque()
message_queue_lock = threading.Lock()
should_cancel = False

current_tasks_lock = threading.Lock()
current_tasks = set()

start_time = time.time()  # For node uptime

###############################################################################
# Rate Limiting Globals
###############################################################################
rate_limit_lock = threading.Lock()
connection_times = {}
RATE_LIMIT_COUNT = 5
RATE_LIMIT_WINDOW = 10  # seconds

###############################################################################
# Safe AST Evaluator for Local Arithmetic
###############################################################################
_allowed_operators = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.Pow: op.pow,
    ast.USub: op.neg
}
_allowed_functions = {
    'sqrt': math.sqrt,
    'sin': math.sin,
    'cos': math.cos,
    'tan': math.tan,
    'log': math.log,
    'exp': math.exp,
    'pi': math.pi,
    'e': math.e
}

def safe_eval(expr: str) -> float:
    """Safely evaluate arithmetic expressions using a restricted AST."""
    def _eval(node):
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type in _allowed_operators:
                return _allowed_operators[op_type](_eval(node.left), _eval(node.right))
            else:
                raise ValueError("Operator not allowed")
        elif isinstance(node, ast.UnaryOp):
            op_type = type(node.op)
            if op_type in _allowed_operators:
                return _allowed_operators[op_type](_eval(node.operand))
            else:
                raise ValueError("Unary operator not allowed")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _allowed_functions:
                args = [_eval(arg) for arg in node.args]
                return _allowed_functions[node.func.id](*args)
            else:
                raise ValueError("Function call not allowed")
        elif isinstance(node, ast.Expression):
            return _eval(node.body)
        else:
            raise ValueError("Unsupported expression")
    try:
        parsed = ast.parse(expr, mode='eval')
        return _eval(parsed.body)
    except ZeroDivisionError:
        raise
    except Exception as e:
        raise ValueError(f"Error in safe_eval: {e}")

###############################################################################
# Distributed Task Functions
###############################################################################
def node_self_check() -> dict:
    uptime = time.time() - start_time
    return {
        "session_id": session_id,
        "uptime_seconds": round(uptime, 2),
        "tasks_in_progress": list(current_tasks),
        "quarantine_mode": quarantine_mode
    }

def dispatch_nsc_all() -> dict:
    with discovered_nodes_lock:
        nodes = list(discovered_nodes.keys())
    results = {}
    if not nodes:
        results["localhost"] = node_self_check()
        return results
    def worker(ip):
        task_obj = {
            "auth_token": config["auth_token"],
            "origin": session_id,
            "query_id": str(uuid.uuid4()),
            "task_type": "nsc",
            "query": ""
        }
        r = send_task_to_node(ip, task_obj)
        results[ip] = r.get("nsc", r)
    threads = []
    for ip in nodes:
        t = threading.Thread(target=worker, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def dispatch_status_all() -> dict:
    with discovered_nodes_lock:
        nodes = list(discovered_nodes.keys())
    results = {}
    if not nodes:
        results["localhost"] = list(current_tasks)
        return results
    def worker(ip):
        task_obj = {
            "auth_token": config["auth_token"],
            "origin": session_id,
            "query_id": str(uuid.uuid4()),
            "task_type": "status",
            "query": ""
        }
        r = send_task_to_node(ip, task_obj)
        results[ip] = r.get("result", r)
    threads = []
    for ip in nodes:
        t = threading.Thread(target=worker, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def send_task_to_node(ip: str, task_obj: dict) -> dict:
    """Open a TLS-wrapped TCP connection to ip:TCP_TASK_PORT, send JSON, then read the response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if USE_TLS:
            s = ssl_context.wrap_socket(s, server_hostname=ip)
        s.connect((ip, TCP_TASK_PORT))
        s.sendall(json.dumps(task_obj).encode('utf-8'))
        resp_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_data += chunk
        s.close()
        if resp_data:
            return json.loads(resp_data.decode('utf-8'))
        else:
            return {"error": "No response"}
    except Exception as e:
        return {"error": str(e)}

###############################################################################
# TCP Server for Distributed Tasks
###############################################################################
def tcp_task_server() -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('', TCP_TASK_PORT))
    server_sock.listen(5)
    logging.info("TCP task server started on port %d", TCP_TASK_PORT)
    while True:
        try:
            conn, addr = server_sock.accept()
            if USE_TLS:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except Exception as e:
                    logging.error("TLS wrap failed: %s", e)
                    conn.close()
                    continue
            threading.Thread(target=handle_task_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error("Error accepting connection: %s", e)
            continue

# Helper: Timed input for non-blocking prompt with timeout
def timed_input(prompt, timeout=10):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    else:
        return "no"

# Rate limiting helper
def check_rate_limit(client_ip, query_id):
    now = time.time()
    with rate_limit_lock:
        times = connection_times.get(client_ip, [])
        times = [t for t in times if now - t < RATE_LIMIT_WINDOW]
        if len(times) >= RATE_LIMIT_COUNT:
            return False
        times.append(now)
        connection_times[client_ip] = times
    return True

def handle_task_connection(conn: socket.socket, addr) -> None:
    global quarantine_mode
    client_ip = addr[0]
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            return
        msg = json.loads(data.decode('utf-8'))
        if not check_rate_limit(client_ip, msg.get("query_id", "")):
            resp = {"query_id": msg.get("query_id", ""), "result": "Rate limit exceeded."}
            conn.sendall(json.dumps(resp).encode('utf-8'))
            return
        if msg.get("auth_token", "") != config["auth_token"]:
            resp = {"query_id": msg.get("query_id", ""), "result": "Authentication failed"}
            conn.sendall(json.dumps(resp).encode('utf-8'))
            return
        ttype = msg.get("task_type", "nsc")
        if ttype == "handshake":
            new_token = msg.get("new_token", "")
            received_hmac = msg.get("hmac", "")
            expected_hmac = hmac.new(config["auth_token"].encode(), new_token.encode(), hashlib.sha256).hexdigest()
            if received_hmac == expected_hmac:
                config["auth_token"] = new_token
                resp = {"query_id": msg.get("query_id", ""), "result": "Handshake successful. Auth token updated."}
            else:
                resp = {"query_id": msg.get("query_id", ""), "result": "Handshake failed: HMAC mismatch."}
            conn.sendall(json.dumps(resp).encode('utf-8'))
            return

        if ttype == "set_quarantine":
            mode = msg.get("mode", "").lower()
            if mode not in ("on", "off"):
                resp = {"query_id": msg.get("query_id", ""), "result": "Invalid mode for set_quarantine."}
                conn.sendall(json.dumps(resp).encode('utf-8'))
                return
            user_response = timed_input(f"Remote request: Set quarantine {mode}? (yes/no): ", timeout=10)
            if user_response.strip().lower() == "yes":
                quarantine_mode = (mode == "on")
                resp = {"query_id": msg.get("query_id", ""), "result": f"Quarantine mode set to {mode}."}
            else:
                resp = {"query_id": msg.get("query_id", ""), "result": "Quarantine change declined."}
            conn.sendall(json.dumps(resp).encode('utf-8'))
            return

        if ttype == "nsc":
            r = node_self_check()
            resp = {"query_id": msg.get("query_id", ""), "nsc": r}
            conn.sendall(json.dumps(resp).encode('utf-8'))
        elif ttype == "status":
            resp = {"query_id": msg.get("query_id", ""), "result": list(current_tasks)}
            conn.sendall(json.dumps(resp).encode('utf-8'))
        else:
            try:
                res = safe_eval(msg.get("query", ""))
            except Exception as e:
                res = f"Error: {e}"
            resp = {"query_id": msg.get("query_id", ""), "result": str(res)}
            conn.sendall(json.dumps(resp).encode('utf-8'))
        logging.info("Handled task from %s: type=%s", addr, ttype)
    except Exception as e:
        logging.error("Task connection error from %s: %s", addr, e)
    finally:
        conn.close()

###############################################################################
# Node Discovery & Cleanup with HMAC for UDP Discovery
###############################################################################
def broadcast_discovery() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            mac = hmac.new(SHARED_SECRET.encode(), DISCOVERY_MESSAGE.encode(), hashlib.sha256).hexdigest()
            discovery_data = json.dumps({"msg": DISCOVERY_MESSAGE, "hmac": mac})
            sock.sendto(discovery_data.encode('utf-8'), ('255.255.255.255', UDP_DISCOVERY_PORT))
        except Exception as e:
            logging.error("Broadcast error: %s", e)
        time.sleep(5)

def listen_for_discovery() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', UDP_DISCOVERY_PORT))
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            try:
                discovery_msg = json.loads(data.decode('utf-8'))
                msg = discovery_msg.get("msg", "")
                received_mac = discovery_msg.get("hmac", "")
                expected_mac = hmac.new(SHARED_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
                if msg == DISCOVERY_MESSAGE and received_mac == expected_mac:
                    resp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    resp_sock.sendto(RESPONSE_MESSAGE.encode('utf-8'), addr)
                    resp_sock.close()
                else:
                    logging.warning("Invalid discovery message from %s", addr)
            except Exception as ex:
                logging.error("Error parsing discovery message: %s", ex)
        except Exception as e:
            logging.error("Discovery listener error: %s", e)

def cleanup_nodes() -> None:
    while True:
        try:
            now = time.time()
            with discovered_nodes_lock:
                for ip in list(discovered_nodes.keys()):
                    if now - discovered_nodes[ip] > 15:
                        del discovered_nodes[ip]
            time.sleep(5)
        except Exception as e:
            logging.error("Error in cleanup_nodes: %s", e)
            time.sleep(5)

###############################################################################
# Command Dispatcher and External Command Persistence
###############################################################################
# External commands stored as: command name -> {"code": <lambda code>, "approved": <bool>}
user_commands = {}

def load_user_commands():
    global user_commands
    try:
        if os.path.exists(USER_CMDS_FILE):
            with open(USER_CMDS_FILE, "r") as f:
                user_commands = json.load(f)
            for cmd_name, cmd_data in user_commands.items():
                if not cmd_data.get("approved", False):
                    if sys.stdin.isatty():
                        answer = input(f"New external module '{cmd_name}' detected. Approve it? (yes/no): ")
                        if answer.strip().lower() == "yes":
                            cmd_data["approved"] = True
                            print(f"Module '{cmd_name}' approved. It will be available in the next session.")
                        else:
                            print(f"Module '{cmd_name}' not approved. Please check it before use.")
                    else:
                        print(f"Module '{cmd_name}' is unapproved. Skipping.")
                if cmd_data.get("approved", False):
                    safe_globals = {"__builtins__": {"True": True, "False": False, "None": None, "str": str, "int": int, "float": float}}
                    try:
                        func = eval(cmd_data["code"], safe_globals)
                        commands[cmd_name] = (func, "User defined command (persisted)")
                    except Exception as e:
                        logging.error("Error loading command %s: %s", cmd_name, e)
    except Exception as e:
        logging.error("Error loading user commands: %s", e)

def save_user_commands():
    try:
        with open(USER_CMDS_FILE, "w") as f:
            json.dump(user_commands, f)
    except Exception as e:
        logging.error("Error saving user commands: %s", e)

###############################################################################
# Built-in Command Functions
###############################################################################
def help_cmd(args):
    output = "Available commands:\n"
    for name, (func, desc) in commands.items():
        output += f"  {name}: {desc}\n"
    return output

def exit_cmd(args):
    sys.exit(0)

def nsc_cmd(args):
    return str(node_self_check())

def nsc_all_cmd(args):
    return str(dispatch_nsc_all())

def nodes_cmd(args):
    with discovered_nodes_lock:
        if discovered_nodes:
            return "\n".join(f" - {ip}" for ip in discovered_nodes.keys())
        else:
            return "No discovered nodes."

def status_all_cmd(args):
    return str(dispatch_status_all())

def clear_cmd(args):
    return "<CLEAR_SCREEN>"

def quarantine_cmd(args):
    global quarantine_mode
    if not args:
        return "Usage: quarantine <on|off> [target]"
    mode = args[0].lower()
    if mode not in ("on", "off"):
        return "Usage: quarantine <on|off> [target]"
    target = args[1] if len(args) > 1 else None
    if target is None:
        confirm = input(f"Send quarantine {mode} command to ALL nodes? (yes/no): ")
        if confirm.strip().lower() != "yes":
            return "Operation cancelled."
        results = {}
        with discovered_nodes_lock:
            nodes = list(discovered_nodes.keys())
        if not nodes:
            return "No remote nodes to send command to."
        for ip in nodes:
            task_obj = {
                "auth_token": config["auth_token"],
                "origin": session_id,
                "query_id": str(uuid.uuid4()),
                "task_type": "set_quarantine",
                "mode": mode
            }
            r = send_task_to_node(ip, task_obj)
            results[ip] = r.get("result", r)
        return f"Broadcast quarantine {mode} command sent. Responses: {results}"
    else:
        all_nsc = dispatch_nsc_all()
        matched_ips = []
        for ip, nsc in all_nsc.items():
            s_id = nsc.get("session_id", "")
            if s_id.startswith(target):
                matched_ips.append(ip)
        if not matched_ips:
            return f"No node found with session ID starting with '{target}'."
        elif len(matched_ips) > 1:
            return f"Multiple nodes match '{target}': {matched_ips}. Please refine your target."
        else:
            ip = matched_ips[0]
            task_obj = {
                "auth_token": config["auth_token"],
                "origin": session_id,
                "query_id": str(uuid.uuid4()),
                "task_type": "set_quarantine",
                "mode": mode
            }
            r = send_task_to_node(ip, task_obj)
            return f"Remote quarantine {mode} command sent to node {ip}. Response: {r.get('result', r)}"

def cal_cmd(args):
    expr = " ".join(args)
    try:
        result = safe_eval(expr)
        return str(result)
    except Exception as e:
        return f"Error in cal: {e}"

def addcmd_cmd(args):
    if len(args) < 2:
        return ("Usage: addcmd <command_name> <lambda code>\n"
                "Example: addcmd simple \"lambda args: 'Simple test successful.'\"")
    cmd_name = args[0].lower()
    lambda_code = " ".join(args[1:])
    safe_globals = {"__builtins__": {"True": True, "False": False, "None": None, "str": str, "int": int, "float": float}}
    try:
        new_func = eval(lambda_code, safe_globals)
        if not callable(new_func):
            return "Provided lambda code is not callable."
        user_commands[cmd_name] = {"code": lambda_code, "approved": False}
        save_user_commands()
        return f"Command '{cmd_name}' added and saved. It must be approved to be loaded (will be available in the next session)."
    except Exception as e:
        return f"Error adding command: {e}"

def switch_role_cmd(args):
    if len(args) != 1 or args[0] not in ("master", "worker"):
        return "Usage: switch_role <master|worker>"
    config["role"] = args[0]
    return f"Role switched to {args[0]}."

# Global command dispatcher dictionary.
commands = {
    "help": (help_cmd, "Display this help message"),
    "exit": (exit_cmd, "Exit the command prompt"),
    "nsc": (nsc_cmd, "Perform local node self-check"),
    "nsc_all": (nsc_all_cmd, "Request node self-check from all nodes"),
    "nodes": (nodes_cmd, "List discovered nodes"),
    "status_all": (status_all_cmd, "Show tasks from all nodes"),
    "clear": (clear_cmd, "Clear the output window"),
    "quarantine": (quarantine_cmd, "Toggle quarantine mode (usage: quarantine <on|off> [target])"),
    "cal": (cal_cmd, "Evaluate an arithmetic expression locally"),
    "addcmd": (addcmd_cmd, "Register a new command. Usage: addcmd <name> <lambda code>"),
    "switch_role": (switch_role_cmd, "Switch node role. Usage: switch_role <master|worker>")
}

# Load any saved external commands
load_user_commands()

def modular_dispatch_command(cmd_line: str) -> str:
    try:
        parts = shlex.split(cmd_line)
    except Exception as e:
        return f"Error parsing command: {e}"
    if not parts:
        return ""
    cmd = parts[0].lower()
    args = parts[1:]
    if cmd in commands:
        try:
            return commands[cmd][0](args)
        except Exception as e:
            return f"Error executing command '{cmd}': {e}"
    else:
        return f"Unknown command: {cmd}. Type 'help' for a list of commands."

def modular_prompt():
    if role_defaulted:
        print("WARNING: --role not provided. Defaulting to master mode.")
    print("SCP Command Prompt. Type 'help' for available commands.")
    while True:
        try:
            cmd_line = input("SCP> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting SCP prompt.")
            break
        output = modular_dispatch_command(cmd_line)
        if output == "<CLEAR_SCREEN>":
            os.system('cls' if os.name == 'nt' else 'clear')
        elif output is not None:
            print(output)

###############################################################################
# Curses UI (Split Windows Layout)
###############################################################################
def main_cui(stdscr):
    global quarantine_mode
    curses.curs_set(1)
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    crd_height = 7
    input_height = 3
    output_height = max_y - crd_height - input_height

    crd_win = curses.newwin(crd_height, max_x, 0, 0)
    crd_win.border(0)
    output_win = curses.newwin(output_height, max_x, crd_height, 0)
    output_win.scrollok(True)
    input_win = curses.newwin(input_height, max_x, crd_height + output_height, 0)
    input_win.border(0)

    output_win.addstr("SCP Command Prompt (CUI).\n")
    output_win.addstr("Type 'help' for available commands.\n")
    if role_defaulted:
        output_win.addstr("WARNING: --role not provided. Defaulting to master mode.\n")
    output_win.refresh()

    def flush_line(win, prompt):
        win.clear()
        win.border(0)
        win.addstr(1, 1, prompt)
        win.refresh()
        curses.echo()
        cmd = win.getstr(1, 1 + len(prompt)).decode('utf-8').strip()
        curses.noecho()
        win.clear()
        win.border(0)
        win.refresh()
        return cmd

    while True:
        crd_win.erase()
        crd_win.border(0)
        with discovered_nodes_lock:
            node_count = len(discovered_nodes)
        crd_win.addstr(1, 2, f"Nodes discovered: {node_count}")
        crd_win.addstr(2, 2, f"Quarantine: {'ON' if quarantine_mode else 'OFF'}")
        crd_win.refresh()

        cmd_line = flush_line(input_win, "SCP> ")
        if cmd_line.lower() in ("exit", "quit"):
            break
        result = modular_dispatch_command(cmd_line)
        if result == "<CLEAR_SCREEN>":
            output_win.clear()
            output_win.border(0)
        else:
            output_win.addstr(result + "\n")
        output_win.refresh()

###############################################################################
# Tkinter UI
###############################################################################
def process_gui_command(cmd, output_widget):
    result = modular_dispatch_command(cmd)
    output_widget.config(state='normal')
    if result == "<CLEAR_SCREEN>":
        output_widget.delete('1.0', tk.END)
    else:
        output_widget.insert(tk.END, result + "\n")
    output_widget.config(state='disabled')

def main_gui():
    root = tk.Tk()
    root.title("SuperComputer Project - Version 4.8a")
    root.resizable(True, True)
    header_label = tk.Label(root, text="SCP - Version 4.8a", font=("Helvetica", 14))
    header_label.pack(pady=5)
    output_text = tk.scrolledtext.ScrolledText(root, state='normal', width=80, height=20)
    output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    if role_defaulted:
        output_text.insert(tk.END, "WARNING: --role not provided. Defaulting to master mode.\n")
    command_entry = tk.Entry(root, width=80)
    command_entry.pack(padx=10, pady=(0, 10), fill=tk.X)
    def send_command(event=None):
        cmd = command_entry.get().strip()
        command_entry.delete(0, tk.END)
        if not cmd:
            return
        output_text.insert(tk.END, f"SCP> {cmd}\n")
        process_gui_command(cmd, output_text)
        output_text.see(tk.END)
    command_entry.bind("<Return>", send_command)
    send_button = tk.Button(root, text="Send", command=send_command)
    send_button.pack(pady=(0, 10))
    root.mainloop()

###############################################################################
# Handshake Refresh: Periodically update auth token and notify peers
###############################################################################
def handshake_refresh():
    global config
    old_token = config["auth_token"]
    while True:
        time.sleep(300)  # every 5 minutes
        new_token = uuid.uuid4().hex
        hmac_val = hmac.new(old_token.encode(), new_token.encode(), hashlib.sha256).hexdigest()
        handshake_message = {
            "auth_token": old_token,
            "origin": session_id,
            "query_id": str(uuid.uuid4()),
            "task_type": "handshake",
            "new_token": new_token,
            "hmac": hmac_val
        }
        with discovered_nodes_lock:
            nodes = list(discovered_nodes.keys())
        for ip in nodes:
            r = send_task_to_node(ip, handshake_message)
            logging.info("Handshake sent to %s, response: %s", ip, r)
        config["auth_token"] = new_token
        old_token = new_token
        logging.info("Auth token refreshed via handshake.")

###############################################################################
# Main Entry Point with Error Recovery
###############################################################################
def main():
    try:
        threading.Thread(target=broadcast_discovery, daemon=True).start()
        threading.Thread(target=listen_for_discovery, daemon=True).start()
        threading.Thread(target=cleanup_nodes, daemon=True).start()
        threading.Thread(target=tcp_task_server, daemon=True).start()
        threading.Thread(target=handshake_refresh, daemon=True).start()

        if config["role"] == "master":
            if config["ui_mode"] == "gui" and tk is not None:
                main_gui()
            elif config["ui_mode"] == "cui" and curses is not None:
                curses.wrapper(main_cui)
            else:
                print("No valid UI mode or libraries available. Exiting.")
        else:
            print("Worker node running in command mode. Type 'help' for commands.")
            if role_defaulted:
                print("WARNING: --role not provided. Defaulting to master mode.")
            modular_prompt()
    except Exception as critical_error:
        logging.critical("Critical error in main loop: %s", critical_error)
        print("A critical error occurred. Attempting to cancel non-critical operations and exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
