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
 along with this program. If not, see https://choosealicense.com/licenses/gpl-3.0/.

-- Updates and Secondary Header --

Name: SuperComputer Project (SCP)
Author: Discover Interactive
Version: 5.4b
Description:
  - Improved code organization and stability
  - Upgraded security and encryption
  - Added mesh networking support
  - Improved error handling and recovery
  - Added module management
  - Added system diagnostics and monitoring
  - Fixed UI stability issues
  - Added shutdown handling
"""

###############################################################################
# Import Statements and Version Control
###############################################################################
import os, sys, socket, threading, time, json, logging, uuid
import argparse, base64, io, math, ast, operator as op
import random, shlex, select, hmac, hashlib, secrets
from collections import deque
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Optional UI imports
try:
    import curses
except ImportError:
    curses = None
try:
    import tkinter as tk
    from tkinter import scrolledtext
except ImportError:
    tk = None

class SecureConfig:
    def __init__(self, config_path):
        self.config_path = config_path
        self._key = None
        self._fernet = None
        self.config = {}
        
    def initialize(self, password=None):
        if not password:
            password = secrets.token_hex(32)
            print(f"Generated secure password: {password}")
        
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        self._key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(self._key)
        
    def save(self):
        encrypted = self._fernet.encrypt(json.dumps(self.config).encode())
        with open(self.config_path, 'wb') as f:
            f.write(encrypted)
            
    def load(self, password):
        try:
            with open(self.config_path, 'rb') as f:
                encrypted = f.read()
            decrypted = self._fernet.decrypt(encrypted)
            self.config = json.loads(decrypted.decode())
        except Exception as e:
            logging.error(f"Failed to load secure config: {e}")
            return False
        return True

class SecurityError(Exception):
    pass

class SecureComm:
    def __init__(self, shared_key):
        self.fernet = Fernet(shared_key)
        self.nonce_cache = {}
        self.nonce_lock = threading.Lock()
        
    def encrypt_message(self, message, target_id):
        nonce = secrets.token_bytes(16)
        timestamp = str(time.time())
        payload = {
            "message": message,
            "nonce": base64.b64encode(nonce).decode(),
            "timestamp": timestamp
        }
        return self.fernet.encrypt(json.dumps(payload).encode())
        
    def decrypt_message(self, encrypted_data, sender_id):
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            payload = json.loads(decrypted.decode())
            
            # Prevent replay attacks
            with self.nonce_lock:
                if sender_id in self.nonce_cache:
                    if payload["nonce"] in self.nonce_cache[sender_id]:
                        raise SecurityError("Replay attack detected")
                    self.nonce_cache[sender_id].add(payload["nonce"])
                else:
                    self.nonce_cache[sender_id] = {payload["nonce"]}
                    
            # Check message timestamp
            if abs(float(payload["timestamp"]) - time.time()) > 30:
                raise SecurityError("Message too old or from future")
                
            return payload["message"]
        except Exception as e:
            logging.error(f"Secure communication error: {e}")
            return None

class IntegrityVerifier:
    def __init__(self):
        self.file_hashes = {}
        self._key = None
        
    def initialize(self, key):
        """Initialize the verifier with a key"""
        self._key = key
        self.file_hashes = self._load_stored_hashes()
        
    def _load_stored_hashes(self):
        """Load stored hashes from secure storage"""
        hash_file = os.path.join(CONFIG_DIR, "file_hashes.enc")
        if os.path.exists(hash_file):
            try:
                with open(hash_file, 'rb') as f:
                    encrypted_data = f.read()
                fernet = Fernet(self._key)
                decrypted = fernet.decrypt(encrypted_data)
                return json.loads(decrypted.decode())
            except Exception as e:
                logging.warning(f"Could not load stored hashes: {e}")
                return {}
        return {}
        
    def _save_hashes(self):
        """Save hashes to secure storage"""
        try:
            hash_file = os.path.join(CONFIG_DIR, "file_hashes.enc")
            fernet = Fernet(self._key)
            encrypted = fernet.encrypt(json.dumps(self.file_hashes).encode())
            with open(hash_file, 'wb') as f:
                f.write(encrypted)
        except Exception as e:
            logging.error(f"Failed to save file hashes: {e}")
        
    def calculate_hash(self, filepath):
        hasher = hashes.Hash(hashes.SHA256())
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return base64.b64encode(hasher.finalize()).decode()
        
    def verify_file(self, filepath):
        if filepath not in self.file_hashes:
            self.file_hashes[filepath] = self.calculate_hash(filepath)
            return True
        
        current_hash = self.calculate_hash(filepath)
        if current_hash != self.file_hashes[filepath]:
            logging.critical(f"File integrity violation detected: {filepath}")
            return False
        return True

class TaskValidator:
    def __init__(self):
        self.allowed_tasks = {
            "nsc": self.validate_nsc,
            "status": self.validate_status,
            "handshake": self.validate_handshake
        }
        
    def validate_nsc(self, task):
        required = {"auth_token", "origin", "query_id"}
        return all(k in task for k in required)
        
    def validate_status(self, task):
        required = {"auth_token", "origin", "query_id"}
        return all(k in task for k in required)
        
    def validate_handshake(self, task):
        required = {"auth_token", "origin", "query_id", "new_token", "hmac"}
        if not all(k in task for k in required):
            return False
        return self.verify_handshake_hmac(task)
        
    def verify_handshake_hmac(self, task):
        received_hmac = task["hmac"]
        expected_hmac = hmac.new(
            task["auth_token"].encode(),
            task["new_token"].encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(received_hmac, expected_hmac)

###############################################################################
# Security Components
###############################################################################

class SecurityManager:
    """Central security management class"""
    def __init__(self, shared_key):
        self.config = SecureConfig(os.path.join(CONFIG_DIR, "secure_config.enc"))
        self.comm = SecureComm(shared_key)
        self.verifier = IntegrityVerifier()
        self.access_control = AccessController()
        self._shared_key = shared_key

class SecurityEnhancements:
    """Added security features"""
    def __init__(self):
        self.password_attempts = {}
        self.blocked_until = {}
        self.session_tokens = {}
        self.last_activity = {}
        self.security_lock = threading.Lock()
        
    def check_auth_attempt(self, ip: str, password: str) -> bool:
        """Check authentication attempts and implement lockouts"""
        with self.security_lock:
            now = time.time()
            
            # Check if IP is blocked
            if ip in self.blocked_until:
                if now < self.blocked_until[ip]:
                    return False
                else:
                    del self.blocked_until[ip]
                    self.password_attempts[ip] = []
            
            # Record attempt
            if ip not in self.password_attempts:
                self.password_attempts[ip] = []
            self.password_attempts[ip].append(now)
            
            # Clean old attempts
            self.password_attempts[ip] = [t for t in self.password_attempts[ip] 
                                        if now - t < 300]  # 5 minute window
            
            # Check for too many attempts
            if len(self.password_attempts[ip]) >= 5:
                self.blocked_until[ip] = now + 900  # 15 minute lockout
                return False
                
            return True
    
    def generate_session_token(self, ip: str) -> str:
        """Generate a unique session token"""
        token = secrets.token_urlsafe(32)
        with self.security_lock:
            self.session_tokens[ip] = token
            self.last_activity[ip] = time.time()
        return token
    
    def validate_session(self, ip: str, token: str) -> bool:
        """Validate a session token"""
        with self.security_lock:
            if ip not in self.session_tokens:
                return False
            if self.session_tokens[ip] != token:
                return False
            # Check for session timeout (30 minutes)
            if time.time() - self.last_activity[ip] > 1800:
                del self.session_tokens[ip]
                return False
            self.last_activity[ip] = time.time()
            return True
            
    def invalidate_session(self, ip: str):
        """Invalidate a session"""
        with self.security_lock:
            if ip in self.session_tokens:
                del self.session_tokens[ip]

def initialize_security():
    global secure_config, secure_comm, integrity_verifier, security_manager, security_enhancements
    
    try:
        security_enhancements = SecurityEnhancements()
        # Initialize secure config first
        secure_config = SecureConfig(os.path.join(CONFIG_DIR, "secure_config.enc"))
        secure_config.initialize(args.auth if args.auth else None)
        
        # Initialize security components with proper key
        secure_comm = SecureComm(secure_config._key)
        integrity_verifier = IntegrityVerifier()
        integrity_verifier.initialize(secure_config._key)
        
        # Initialize security manager last
        security_manager = SecurityManager(secure_config._key)
        
        # Verify critical files
        critical_files = [__file__, USER_CMDS_FILE]
        for filepath in critical_files:
            if os.path.exists(filepath):
                if not integrity_verifier.verify_file(filepath):
                    raise SecurityError("Critical file integrity check failed!")
    except Exception as e:
        logging.error(f"Security initialization error: {e}")
        raise

class AccessController:
    """Handles access control and rate limiting"""
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = set()
        self.lock = threading.Lock()

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
        # Check if certificate files exist before loading them
        if not os.path.exists(TLS_CERT) or not os.path.exists(TLS_KEY):
            logging.warning("TLS certificate files not found. Disabling TLS.")
            USE_TLS = False
        else:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            # Force TLS 1.2+ by disabling older versions
            ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
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

# Mesh and Pool Configuration
mesh_config = {
    "enabled": True,
    "pool_name": "default",
    "pool_key": None,  # Will be generated if None
    "trusted_pools": {},  # {pool_name: pool_key}
    "mesh_peers": {},  # {node_ip: {"pool": pool_name, "last_seen": timestamp}}
    "max_hops": 3,  # Maximum number of mesh hops for message propagation
    "collaborate": False  # Whether to allow cross-pool task collaboration
}

parser = argparse.ArgumentParser(
    description="SCP (SuperComputer Project) - Version: 5.4b\n"
                "On-run arguments:\n"
                "  --gui                : Launch in GUI mode (for master nodes)\n"
                "  --color <color>      : Set UI text color (e.g. 'blue')\n"
                "  --auth <token>       : Set the authentication token\n"
                "  --role <master|worker>: Set the node role in the cluster\n"
                "  --bind-ip <ip>       : Bind server sockets to the specified IP address (for dedicated interface)"
)
parser.add_argument("--gui", action="store_true", help="Launch in GUI mode")
parser.add_argument("--color", type=str, help="UI text color (e.g. 'blue')")
parser.add_argument("--auth", type=str, help="Authentication token")
parser.add_argument("--role", type=str, choices=["master", "worker"], help="Set node role (master/worker)")
parser.add_argument("--bind-ip", type=str, help="IP address to bind incoming server sockets to", default="127.0.0.1")
parser.add_argument("--pool-name", type=str, help="Node pool name", default="default")
parser.add_argument("--pool-key", type=str, help="Node pool authentication key")
parser.add_argument("--collaborate", action="store_true", help="Allow cross-pool task collaboration")
parser.add_argument("--mesh", action="store_true", help="Enable mesh networking")
args = parser.parse_args()
BIND_IP = args.bind_ip  # New global for binding sockets

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
quarantine_list = {}
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
    """Perform comprehensive node self-check and diagnostics"""
    try:
        # System Status
        uptime = time.time() - start_time
        import platform, psutil
        
        system_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_usage": psutil.cpu_percent(interval=1),
        }
        
        # Memory Status
        memory = psutil.virtual_memory()
        memory_info = {
            "total": memory.total,
            "available": memory.available,
            "percent_used": memory.percent,
            "swap_used": psutil.swap_memory().percent
        }
        
        # Network Status
        network_info = {
            "interfaces": get_network_interfaces(),
            "connections": len(psutil.net_connections()),
            "discovered_nodes": len(discovered_nodes),
            "mesh_enabled": mesh_config["enabled"],
            "mesh_peers": len(mesh_config["mesh_peers"]) if "mesh_peers" in mesh_config else 0
        }
        
        # Security Status
        security_info = {
            "tls_enabled": USE_TLS,
            "quarantine_mode": quarantine_mode,
            "quarantined_ips": len(quarantine_list),
            "rate_limiting": bool(RATE_LIMIT_COUNT)
        }
        
        # Component Status
        with current_tasks_lock:
            active_tasks = list(current_tasks)
        
        components_info = {
            "role": config["role"],
            "session_id": session_id,
            "ui_mode": config["ui_mode"],
            "active_tasks": len(active_tasks),
            "modules_loaded": len(user_commands),
            "essential_threads": check_threads_status()  # Changed from self_check_threads()
        }
        
        # Diagnostics Results
        diagnostics = run_diagnostics()
        
        return {
            "timestamp": time.time(),
            "uptime_seconds": round(uptime, 2),
            "system": system_info,
            "memory": memory_info,
            "network": network_info,
            "security": security_info,
            "components": components_info,
            "diagnostics": diagnostics,
            "status": "healthy" if all(diagnostics.values()) else "issues_detected"
        }
    except Exception as e:
        logging.error(f"Error in node self-check: {e}")
        return {"error": str(e), "status": "check_failed"}

def check_threads_status() -> dict:  # Renamed from self_check_threads
    """Check status of essential threads"""
    essential_threads = {
        "Node Cleanup": False,
        "TCP Server": False,
        "Discovery Broadcast": False,
        "Discovery Listener": False,
        "Connection Cleanup": False,
        "Quarantine Cleanup": False,
        "Handshake Refresh": False
    }
    
    for thread in threading.enumerate():
        if thread.name in essential_threads:
            essential_threads[thread.name] = thread.is_alive()
    
    return essential_threads

def run_diagnostics() -> dict:
    """Run system diagnostics"""
    diagnostics = {}
    
    # Check disk space
    try:
        import psutil  # Move import to function scope
        disk = psutil.disk_usage('/')
        diagnostics["disk_space"] = disk.percent < 90
    except:
        diagnostics["disk_space"] = None
    
    # Check memory
    try:
        import psutil  # Move import to function scope
        mem = psutil.virtual_memory()
        diagnostics["memory_available"] = mem.available > 500 * 1024 * 1024  # 500MB
    except:
        diagnostics["memory_available"] = None
    
    # Check network connectivity
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        diagnostics["network_connectivity"] = True
    except:
        diagnostics["network_connectivity"] = False
    
    # Check file permissions
    try:
        diagnostics["config_writeable"] = os.access(CONFIG_DIR, os.W_OK)
    except:
        diagnostics["config_writeable"] = False
    
    return diagnostics

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
        s.settimeout(10)
        if USE_TLS:
            s = ssl_context.wrap_socket(s, server_hostname=ip)
        s.connect((ip, TCP_TASK_PORT))
        s.sendall(json.dumps(task_obj).encode('utf-8'))
        resp_data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_data += chunk
            except socket.timeout:
                logging.warning("Socket timeout receiving from %s", ip)
                break
        s.close()
        if resp_data:
            try:
                return json.loads(resp_data.decode('utf-8'))
            except json.JSONDecodeError:
                return {"error": "Invalid JSON response"}
        else:
            return {"error": "No response or timeout"}
    except socket.timeout:
        return {"error": "Connection timeout"}
    except Exception as e:
        return {"error": str(e)}

###############################################################################
# TCP Server for Distributed Tasks
###############################################################################
def tcp_task_server() -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # Bind only to the specified interface instead of all interfaces
        server_sock.bind((BIND_IP, TCP_TASK_PORT))
        server_sock.listen(5)
        logging.info("TCP task server started on %s:%d", BIND_IP, TCP_TASK_PORT)
    except Exception as e:
        logging.critical("Failed to bind TCP task server socket: %s", e)
        print(f"Critical error: Failed to bind TCP task server socket: {e}")
        return
        
    while True:
        try:
            conn, addr = server_sock.accept()
            if USE_TLS:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except Exception as e:
                    logging.error("TLS wrap failed for %s: %s", addr, e)
                    conn.close()
                    continue
            threading.Thread(target=handle_task_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error("Error accepting connection: %s", e)
            # Small delay to prevent CPU spin
            time.sleep(0.1)

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
            connection_times[client_ip] = times
            return False
        times.append(now)
        connection_times[client_ip] = times
    return True

def cleanup_connection_times():
    while True:
        try:
            now = time.time()
            with rate_limit_lock:
                for ip in list(connection_times.keys()):
                    times = [t for t in times if now - t < RATE_LIMIT_WINDOW]
                    if times:
                        connection_times[ip] = times
                    else:
                        del connection_times[ip]
        except Exception as e:
            logging.error("Error in cleanup_connection_times: %s", e)
        time.sleep(60)

task_validator = TaskValidator()

def handle_task_connection(conn: socket.socket, addr) -> None:
    global quarantine_mode

    client_ip = addr[0]
    if is_quarantined(client_ip):
        logging.warning("Connection attempt from quarantined IP: %s", client_ip)
        conn.close()
        return
    
    try:
        conn.settimeout(5)
        data = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                logging.warning("Socket timeout receiving from %s", addr)
                break
        if not data:
            return
        
        # Validate JSON before parsing
        try:
            msg = json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            logging.warning("Invalid JSON received from %s", addr)
            conn.sendall(json.dumps({"error": "Invalid JSON format"}).encode('utf-8'))
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
        try:
            conn.close()
        except:
            pass

###############################################################################
# Network Interface Configuration
###############################################################################
def get_network_interfaces():
    """Get a list of available network interfaces with their IP addresses."""
    interfaces = {}
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if (netifaces.AF_INET in addrs):
                for addr in addrs[netifaces.AF_INET]:
                    interfaces[iface] = addr['addr']
    except ImportError:
        logging.warning("netifaces module not available, using fallback method")
        import socket
        import subprocess
        import re
        
        try:
            if os.name == 'nt':  # Windows
                output = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if 'IPv4 Address' in line:
                        ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line).group(1)
                        interfaces["eth"] = ip
            elif os.name != 'nt':  # Linux/Unix
                output = subprocess.check_output("ifconfig", shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if 'inet ' in line:
                        ip = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line).group(1)
                        if ip != '127.0.0.1':
                            interfaces["eth"] = ip
        except:
            # Last resort: get hostname
            interfaces["default"] = socket.gethostbyname(socket.gethostname())
    
    return interfaces

def interfaces_cmd(args):
    """List available network interfaces."""
    interfaces = get_network_interfaces()
    if not interfaces:
        return "No network interfaces detected."
    
    result = "Available network interfaces:\n"
    for iface, ip in interfaces.items():
        result += f" - {iface}: {ip}\n"
    return result

###############################################################################
# Node Discovery & Cleanup with HMAC for UDP Discovery
###############################################################################
def broadcast_discovery() -> None:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((BIND_IP, 0))
        
        while True:
            try:
                discovery_data = {
                    "msg": DISCOVERY_MESSAGE,
                    "node_id": session_id,
                    "timestamp": time.time()
                }
                
                encrypted_data = secure_comm.encrypt_message(
                    discovery_data, 
                    "broadcast"
                )
                
                sock.sendto(encrypted_data, 
                          ('255.255.255.255', UDP_DISCOVERY_PORT))
                
                # Handle responses securely
                start_time = time.time()
                while time.time() - start_time < 2:
                    ready = select.select([sock], [], [], 0.1)
                    if ready[0]:
                        try:
                            resp, addr = sock.recvfrom(4096)
                            decrypted = secure_comm.decrypt_message(
                                resp, 
                                addr[0]
                            )
                            if decrypted and decrypted.get("msg") == RESPONSE_MESSAGE:
                                with discovered_nodes_lock:
                                    discovered_nodes[addr[0]] = {
                                        "timestamp": time.time(),
                                        "node_id": decrypted.get("node_id"),
                                        "public_key": decrypted.get("public_key")
                                    }
                        except Exception as e:
                            logging.warning(f"Secure discovery error: {e}")
            except Exception as e:
                logging.error(f"Broadcast error: {e}")
            time.sleep(5)
    finally:
        if sock:
            sock.close()

def listen_for_discovery() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Set socket options for reuse
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND_IP, UDP_DISCOVERY_PORT))
        logging.info("UDP discovery listener started on %s:%d", BIND_IP, UDP_DISCOVERY_PORT)
    except Exception as e:
        logging.error("Failed to bind UDP discovery socket: %s", e)
        return
        
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            client_ip = addr[0]
            
            # Check if the IP is quarantined
            if is_quarantined(client_ip):
                logging.warning("Discovery message from quarantined IP: %s", client_ip)
                continue
            try:
                discovery_msg = json.loads(data.decode('utf-8'))
                msg = discovery_msg.get("msg", "")
                received_mac = discovery_msg.get("hmac", "")
                expected_mac = hmac.new(SHARED_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
                if msg == DISCOVERY_MESSAGE and received_mac == expected_mac:
                    resp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        resp_sock.sendto(RESPONSE_MESSAGE.encode('utf-8'), addr)
                    except Exception as ex:
                        logging.error("Error sending discovery response: %s", ex)
                    finally:
                        resp_sock.close()
                else:
                    logging.warning("Invalid discovery message from %s", addr)
            except json.JSONDecodeError:
                logging.warning("Received invalid JSON from %s", addr)
            except Exception as ex:
                logging.error("Error parsing discovery message: %s", ex)
        except Exception as e:
            logging.error("Discovery listener error: %s", e)
            time.sleep(1)  # Small delay to prevent CPU spin

def cleanup_nodes() -> None:
    while True:
        try:
            now = time.time()
            # More efficient lock usage
            to_delete = []
            with discovered_nodes_lock:
                for ip, timestamp in discovered_nodes.items():
                    if now - timestamp > 15:
                        to_delete.append(ip)
                for ip in to_delete:
                    del discovered_nodes[ip]
            time.sleep(5)
        except Exception as e:
            logging.error("Error in cleanup_nodes: %s", e)
            time.sleep(5)

###############################################################################
# Quarantine Management
###############################################################################
quarantine_list = {}  # IP address -> { "timestamp": when_added, "reason": why_added }
quarantine_list_lock = threading.Lock()

def add_to_quarantine(ip, reason="Unspecified"):
    with quarantine_list_lock:
        quarantine_list[ip] = {
            "timestamp": time.time(),
            "reason": reason
        }
    logging.info("Added %s to quarantine: %s", ip, reason)

def remove_from_quarantine(ip):
    with quarantine_list_lock:
        if ip in quarantine_list:
            del quarantine_list[ip]
            logging.info("Removed %s from quarantine", ip)
            return True
        return False

def is_quarantined(ip):
    with quarantine_list_lock:
        return ip in quarantine_list

def list_quarantined():
    with quarantine_list_lock:
        return dict(quarantine_list)

def quarantine_list_cmd(args):
    if not args:
        # List all quarantined IPs
        quarantined = list_quarantined()
        if not quarantined:
            return "No IPs in quarantine list."
        result = "Quarantined IPs:\n"
        for ip, data in quarantined.items():
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data["timestamp"]))
            result += f" - {ip}: Added {timestamp}, Reason: {data['reason']}\n"
        return result
    
    action = args[0].lower()
    if action == "add":
        if len(args) < 2:
            return "Usage: quarantine_list add <ip> [reason]"
        ip = args[1]
        reason = " ".join(args[2:]) if len(args) > 2 else "Manually added"
        add_to_quarantine(ip, reason)
        return f"Added {ip} to quarantine list: {reason}"
    
    elif action == "remove":
        if len(args) < 2:
            return "Usage: quarantine_list remove <ip>"
        ip = args[1]
        if remove_from_quarantine(ip):
            return f"Removed {ip} from quarantine list."
        else:
            return f"IP {ip} not found in quarantine list."
    
    else:
        return "Usage: quarantine_list [add|remove] [ip] [reason]"

def cleanup_quarantine():
    # Default expiration time is 7 days
    QUARANTINE_EXPIRY = 7 * 24 * 60 * 60
    
    while True:
        time.sleep(3600)
        now = time.time()
        expired = []
        with quarantine_list_lock:
            for ip, data in quarantine_list.items():
                if now - data["timestamp"] > QUARANTINE_EXPIRY:
                    expired.append(ip)
            for ip in expired:
                logging.info("Quarantine expired for %s", ip)
                del quarantine_list[ip]

###############################################################################
# Command Dispatcher and External Command Persistence
###############################################################################
# External commands stored as: command name -> {"code": <lambda code>, "approved": <bool>}
user_commands = {}

def load_user_commands():
    """Load and validate user commands/modules"""
    global user_commands
    try:
        if not os.path.exists(USER_CMDS_FILE):
            logging.info("No user commands file found. Creating new one.")
            user_commands = {}
            save_user_commands()
            return

        with open(USER_CMDS_FILE, "r") as f:
            try:
                user_commands = json.load(f)
            except json.JSONDecodeError:
                logging.error("Corrupted user commands file. Creating backup and starting fresh.")
                os.rename(USER_CMDS_FILE, f"{USER_CMDS_FILE}.backup")
                user_commands = {}
                save_user_commands()
                return
            
            # Process each module without interactive prompts
            for cmd_name, cmd_data in list(user_commands.items()):
                try:
                    # Skip unapproved modules
                    if not cmd_data.get("approved", False):
                        continue

                    # Load approved modules
                    if cmd_data.get("type") == "module":
                        try:
                            module_code = compile(cmd_data["code"], cmd_name, 'exec')
                            module_globals = {
                                '__name__': cmd_name,
                                'logging': logging,
                                'safe_eval': safe_eval
                            }
                            exec(module_code, module_globals)
                            
                            if 'register_commands' in module_globals:
                                new_commands = module_globals['register_commands']()
                                for new_cmd, (func, desc) in new_commands.items():
                                    commands[new_cmd] = (func, desc)
                                logging.info(f"Successfully loaded module '{cmd_name}'")
                        except Exception as e:
                            logging.error(f"Error loading module {cmd_name}: {e}")
                            del user_commands[cmd_name]
                except Exception as e:
                    logging.error(f"Error processing module {cmd_name}: {e}")
                    del user_commands[cmd_name]
            
            save_user_commands()
    except Exception as e:
        logging.error(f"Error loading user commands: {e}")

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
    """Perform and display node self-check"""
    try:
        check_result = node_self_check()
        if "error" in check_result:
            return f"Self-check failed: {check_result['error']}"
        
        # Format the results for display
        output = [
            "Node Self Check Results:",
            f"Status: {check_result['status'].upper()}",
            f"Uptime: {int(check_result['uptime_seconds']//3600)}h {int((check_result['uptime_seconds']%3600)//60)}m",
            "",
            "System Information:",
            f"  Platform: {check_result['system']['platform']}",
            f"  CPU Usage: {check_result['system']['cpu_usage']}%",
            f"  CPU Cores: {check_result['system']['cpu_count']}",
            "",
            "Memory Status:",
            f"  Used: {check_result['memory']['percent_used']}%",
            f"  Available: {check_result['memory']['available'] // (1024*1024)} MB",
            f"  Swap Used: {check_result['memory']['swap_used']}%",
            "",
            "Network Status:",
            f"  Discovered Nodes: {check_result['network']['discovered_nodes']}",
            f"  Active Connections: {check_result['network']['connections']}",
            f"  Mesh Enabled: {check_result['network']['mesh_enabled']}",
            f"  Mesh Peers: {check_result['network']['mesh_peers']}",
            "",
            "Security Status:",
            f"  TLS Enabled: {check_result['security']['tls_enabled']}",
            f"  Quarantine Mode: {check_result['security']['quarantine_mode']}",
            f"  Quarantined IPs: {check_result['security']['quarantined_ips']}",
            "",
            "Component Status:",
            f"  Role: {check_result['components']['role']}",
            f"  UI Mode: {check_result['components']['ui_mode']}",
            f"  Active Tasks: {check_result['components']['active_tasks']}",
            f"  Loaded Modules: {check_result['components']['modules_loaded']}",
            "",
            "Diagnostics:",
        ]
        
        # Add diagnostics results
        for test, result in check_result['diagnostics'].items():
            status = "✓" if result else "✗" if result is False else "?"
            output.append(f"  {test}: {status}")
        
        # Add thread status
        output.extend([
            "",
            "Thread Status:"
        ])
        for thread, alive in check_result['components']['essential_threads'].items():
            status = "✓" if alive else "✗"
            output.append(f"  {thread}: {status}")
        
        return "\n".join(output)
        
    except Exception as e:
        logging.error(f"Error in nsc command: {e}")
        return f"Error performing self-check: {e}"

def nsc_all_cmd(args):
    """Get system status from all nodes"""
    results = dispatch_nsc_all()
    if not results:
        return "No nodes found to check."
    
    output = ["Node Status Report:", "-" * 20]
    
    for ip, result in results.items():
        output.append(f"\nNode: {ip}")
        output.append("-" * 20)
        
        if isinstance(result, dict):
            if "error" in result:
                output.append(f"Check failed: {result['error']}")
                continue
                
            status = result.get('status', 'unknown').upper()
            output.append(f"Status: {status}")
            
            # Add key metrics
            if 'system' in result:
                output.append(f"CPU Usage: {result['system']['cpu_usage']}%")
            if 'memory' in result:
                output.append(f"Memory Used: {result['memory']['percent_used']}%")
            if 'network' in result:
                output.append(f"Connected Nodes: {result['network']['discovered_nodes']}")
            if 'security' in result:
                output.append(f"Quarantine: {result['security']['quarantine_mode']}")
            
            # Add diagnostics summary
            if 'diagnostics' in result:
                failed = [k for k, v in result['diagnostics'].items() if v is False]
                if failed:
                    output.append(f"Failed Checks: {', '.join(failed)}")
        else:
            output.append("Invalid response format")
    
    return "\n".join(output)

def nodes_cmd(args):
    with discovered_nodes_lock:
        if discovered_nodes:
            return "\n".join(f" - {ip}" for ip in discovered_nodes.keys())
        else:
            return "No discovered nodes."

def status_all_cmd(args):
    return str(dispatch_status_all())

def clear_cmd(args):
    """Clear the terminal screen"""
    if config["ui_mode"] == "gui":
        return "<CLEAR_SCREEN>"
    elif config["ui_mode"] == "cui":
        return "<CLEAR_SCREEN>"
    else:
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""

def quarantine_cmd(args):
    """Handle quarantine commands without interactive prompts"""
    if not args:
        return "Usage: quarantine <on|off> [target]"
    mode = args[0].lower()
    if mode not in ("on", "off"):
        return "Usage: quarantine <on|off> [target]"
        
    if len(args) > 1:
        target = args[1]
        try:
            socket.inet_aton(target)
        except socket.error:
            pass
    else:
        # Instead of interactive prompt, require explicit confirmation
        return ("To set quarantine mode for ALL nodes, use:\n"
                f"quarantine {mode} all_confirm")
    
    if args[-1] == "all_confirm":
        with discovered_nodes_lock:
            nodes = list(discovered_nodes.keys())
        if not nodes:
            return "No remote nodes to send command to."
            
        results = {}
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

def cal_cmd(args):
    if not args:
        return "Usage: cal <expression>\nSupported operations: +, -, *, /, ^, sqrt, sin, cos, tan, log, exp"
    
    expr = " ".join(args)
    try:
        # Add support for common mathematical constants
        if "pi" in expr.lower():
            expr = expr.lower().replace("pi", str(math.pi))
        if "e" in expr.lower():
            expr = expr.lower().replace("e", str(math.e))
            
        result = safe_eval(expr)
        if isinstance(result, float):
            # Format result to avoid excessive decimal places
            return f"Result: {result:.10g}"
        return f"Result: {result}"
    except ZeroDivisionError:
        return "Error: Division by zero"
    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error in calculation: {e}"

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

def modules_cmd(args):
    """List, load, or manage modules."""
    if not args:
        return ("Module Management Commands:\n"
                "  modules list              - List loaded modules\n"
                "  modules load <path>       - Load module from file\n"
                "  modules unload <name>     - Unload module\n"
                "  modules reload <name>     - Reload module\n"
                "  modules info <name>       - Show module details\n"
                "  modules approve <name>    - Approve a pending module")
    
    action = args[0].lower()
    if action == "list":
        if not user_commands:
            return "No modules loaded."
        result = ["Loaded modules:"]
        for name, data in user_commands.items():
            status = "Approved" if data.get("approved", False) else "Pending approval"
            mtype = data.get("type", "command")
            result.append(f"  - {name} ({status}) [{mtype}]")
        return "\n".join(result)
    
    elif action == "info":
        if len(args) < 2:
            return "Usage: modules info <name>"
        name = args[1]
        if name not in user_commands:
            return f"Module '{name}' not found."
        data = user_commands[name]
        return (f"Module: {name}\n"
                f"Status: {'Approved' if data.get('approved') else 'Pending approval'}\n"
                f"Type: {data.get('type', 'command')}\n"
                f"Path: {data.get('path', 'N/A')}\n"
                f"Loaded: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('loaded_time', 0)))}")
    
    elif action == "approve":
        if len(args) < 2:
            return "Usage: modules approve <name>"
        name = args[1]
        if name not in user_commands:
            return f"Module '{name}' not found."
        if user_commands[name].get("approved", False):
            return f"Module '{name}' is already approved."
        
        # Show preview without asking for input
        code = user_commands[name].get("code", "")
        preview = code[:200] + "..." if len(code) > 200 else code
        return (f"Module '{name}' preview:\n"
                f"{'-' * 40}\n"
                f"{preview}\n"
                f"{'-' * 40}\n"
                f"Use 'modules approve_confirm {name}' to approve this module.")
    
    elif action == "approve_confirm":
        if len(args) < 2:
            return "Usage: modules approve_confirm <name>"
        name = args[1]
        if name not in user_commands:
            return f"Module '{name}' not found."
        
        user_commands[name]["approved"] = True
        save_user_commands()
        
        # Reload commands safely
        try:
            load_user_commands()
            return f"Module '{name}' approved and loaded successfully."
        except Exception as e:
            logging.error(f"Error loading approved module {name}: {e}")
            return (f"Module approved but failed to load: {e}")
    
    elif action == "load":
        if len(args) < 2:
            return "Usage: modules load <path>"
        try:
            path = args[1]
            with open(path, 'r') as f:
                code = f.read()
            module_name = os.path.splitext(os.path.basename(path))[0]
            
            # Store module safely
            user_commands[module_name] = {
                "code": code,
                "approved": False,
                "type": "module",
                "path": path,
                "loaded_time": time.time()
            }
            save_user_commands()
            
            # Return preview without interactive prompt
            preview = code[:200] + "..." if len(code) > 200 else code
            return (f"Module '{module_name}' loaded but requires approval.\n"
                   f"Preview:\n{'-' * 40}\n{preview}\n{'-' * 40}\n"
                   f"Use 'modules approve {module_name}' to review and approve.")
        except Exception as e:
            return f"Error loading module: {e}"
    
    elif action == "unload":
        if len(args) < 2:
            return "Usage: modules unload <name>"
        name = args[1]
        if name not in user_commands:
            return f"Module '{name}' not found."
        
        del user_commands[name]
        save_user_commands()
        return f"Module '{name}' unloaded."
    
    return f"Unknown modules command: {action}"

def quarantine_cmd(args):
    """Handle quarantine commands without interactive prompts"""
    if not args:
        return "Usage: quarantine <on|off> [target]"
    mode = args[0].lower()
    if mode not in ("on", "off"):
        return "Usage: quarantine <on|off> [target]"
        
    if len(args) > 1:
        target = args[1]
        try:
            socket.inet_aton(target)
        except socket.error:
            pass
    else:
        # Instead of interactive prompt, require explicit confirmation
        return ("To set quarantine mode for ALL nodes, use:\n"
                f"quarantine {mode} all_confirm")
    
    if args[-1] == "all_confirm":
        with discovered_nodes_lock:
            nodes = list(discovered_nodes.keys())
        if not nodes:
            return "No remote nodes to send command to."
            
        results = {}
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

def status_cmd(args):
    """Get system status"""
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        with current_tasks_lock:
            task_count = len(current_tasks)
            
        with discovered_nodes_lock:
            node_count = len(discovered_nodes)
            
        uptime = time.time() - start_time
        
        status = [
            "System Status:",
            f"Uptime: {int(uptime//3600)}h {int((uptime%3600)//60)}m {int(uptime%60)}s",
            f"CPU Usage: {cpu_percent}%",
            f"Memory: {memory.percent}% used ({memory.used//1024//1024}MB / {memory.total//1024//1024}MB)",
            f"Disk: {disk.percent}% used",
            f"Active Tasks: {task_count}",
            f"Connected Nodes: {node_count}",
            f"Quarantine Mode: {'Enabled' if quarantine_mode else 'Disabled'}",
            f"Role: {config['role']}",
            f"UI Mode: {config['ui_mode']}",
            f"Mesh Network: {'Enabled' if mesh_config['enabled'] else 'Disabled'}"
        ]
        return "\n".join(status)
    except ImportError:
        return "Status command requires psutil package. Install with: pip install psutil"
    except Exception as e:
        return f"Error getting system status: {e}"

def mesh_cmd(args):
    """Manage mesh network settings and connections"""
    if not args:
        return ("Mesh Network Commands:\n"
                "  mesh status         - Show mesh network status\n"
                "  mesh enable         - Enable mesh networking\n"
                "  mesh disable        - Disable mesh networking\n"
                "  mesh peers          - List connected peers\n"
                "  mesh pool <name>    - Set pool name\n"
                "  mesh collaborate <on|off> - Toggle cross-pool collaboration")
    
    action = args[0].lower()
    
    if action == "status":
        status = [
            "Mesh Network Status:",
            f"Enabled: {mesh_config['enabled']}",
            f"Pool Name: {mesh_config['pool_name']}",
            f"Collaboration: {mesh_config['collaborate']}",
            f"Max Hops: {mesh_config['max_hops']}",
            f"Trusted Pools: {len(mesh_config['trusted_pools'])}",
            f"Active Peers: {len(mesh_config['mesh_peers'])}"
        ]
        return "\n".join(status)
        
    elif action == "enable":
        mesh_config["enabled"] = True
        return "Mesh networking enabled"
        
    elif action == "disable":
        mesh_config["enabled"] = False
        return "Mesh networking disabled"
        
    elif action == "peers":
        if not mesh_config["mesh_peers"]:
            return "No active mesh peers"
        peers = ["Active Mesh Peers:"]
        for ip, data in mesh_config["mesh_peers"].items():
            last_seen = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(data["last_seen"]))
            peers.append(f"  {ip} (Pool: {data['pool']}, Last seen: {last_seen})")
        return "\n".join(peers)
        
    elif action == "pool":
        if len(args) < 2:
            return "Usage: mesh pool <name>"
        mesh_config["pool_name"] = args[1]
        return f"Pool name set to: {args[1]}"
        
    elif action == "collaborate":
        if len(args) < 2 or args[1].lower() not in ("on", "off"):
            return "Usage: mesh collaborate <on|off>"
        mesh_config["collaborate"] = (args[1].lower() == "on")
        return f"Cross-pool collaboration: {'enabled' if mesh_config['collaborate'] else 'disabled'}"
    
    return f"Unknown mesh command: {action}"

# Global command dispatcher dictionary.
commands = {
    "help": (help_cmd, "Display this help message"),
    "exit": (exit_cmd, "Exit the command prompt"),
    "status": (status_cmd, "Show system status"),
    "nodes": (nodes_cmd, "List discovered nodes"),
    "mesh": (mesh_cmd, "Manage mesh networking"),
    "cal": (cal_cmd, "Calculator with advanced operations"),
    "interfaces": (interfaces_cmd, "List available network interfaces"),
    "quarantine": (quarantine_cmd, "Toggle quarantine mode"),
    "quarantine_list": (quarantine_list_cmd, "Manage quarantined IPs"),
    "modules": (modules_cmd, "Manage loadable modules"),
    "nsc": (nsc_cmd, "Perform Node Self Check diagnostics"),
    "nsc_all": (nsc_all_cmd, "Run Node Self Check on all connected nodes"),
    "clear": (clear_cmd, "Clear the terminal screen")
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
    
    try:
        if cmd in commands:
            result = commands[cmd][0](args)
            # Ensure we always return a string
            if result is None:
                return ""
            return str(result)
        else:
            return f"Unknown command: {cmd}. Type 'help' for a list of commands."
    except Exception as e:
        logging.error(f"Error executing command '{cmd}': {e}")
        return f"Error executing command '{cmd}': {e}"

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
# Curses UI
###############################################################################
def main_cui(stdscr):
    def handle_resize():
        nonlocal max_y, max_x, crd_height, input_height, output_height
        max_y, max_x = stdscr.getmaxyx()
        output_height = max_y - crd_height - input_height
        crd_win.resize(crd_height, max_x)
        output_win.resize(output_height, max_x)
        output_win.mvwin(crd_height, 0)
        input_win.resize(input_height, max_x)
        input_win.mvwin(crd_height + output_height, 0)
        # Redraw borders
        crd_win.border(0)
        input_win.border(0)
        # Refresh all windows
        crd_win.refresh()
        output_win.refresh()
        input_win.refresh()

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
curses.KEY_RESIZE = curses.KEY_RESIZE if hasattr(curses, 'KEY_RESIZE') else 410

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
    root.title("SuperComputer Project - Version 5.4b")
    root.resizable(True, True)
    header_label = tk.Label(root, text="SCP - Version 5.4b", font=("Helvetica", 14))
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

def generate_secure_token():
    """Generate a cryptographically secure token."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

###############################################################################
# Handshake Refresh
###############################################################################
def handshake_refresh():
    global config, SHARED_SECRET
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
        SHARED_SECRET = new_token
        old_token = new_token
        logging.info("Auth token refreshed.")

###############################################################################
# Mesh Networking
###############################################################################
def setup_mesh_network():
    """Initialize mesh networking configuration."""
    global mesh_config
    
    if args.pool_name:
        mesh_config["pool_name"] = args.pool_name
        logging.info(f"Setting mesh pool name to: {args.pool_name}")
    
    try:
        if args.pool_key:
            mesh_config["pool_key"] = args.pool_key
        elif mesh_config["pool_key"] is None:
            mesh_config["pool_key"] = generate_secure_token()
            logging.info("Generated new mesh network key")
            
        mesh_config["collaborate"] = args.collaborate
        mesh_config["enabled"] = args.mesh
        
        # Initialize peer tracking
        if "mesh_peers" not in mesh_config:
            mesh_config["mesh_peers"] = {}
            
        logging.info(f"Mesh network initialized: Pool={mesh_config['pool_name']}, " + 
                    f"Collaborate={mesh_config['collaborate']}, Enabled={mesh_config['enabled']}")
        return True
    except Exception as e:
        logging.error(f"Mesh network initialization failed: {e}")
        mesh_config["enabled"] = False
        return False

def propagate_mesh_message(message: dict, seen_nodes: set, hops: int = 0):
    """Propagate a message through the mesh network."""
    if hops >= mesh_config["max_hops"]:
        return
        
    with discovered_nodes_lock:
        targets = [ip for ip in discovered_nodes.keys() if ip not in seen_nodes]
    
    for target in targets:
        try:
            if target in mesh_config["mesh_peers"]:
                peer_info = mesh_config["mesh_peers"][target]
                # Only propagate to nodes in same pool or if collaboration is enabled
                if (peer_info["pool"] == mesh_config["pool_name"] or 
                    (mesh_config["collaborate"] and peer_info["pool"] in mesh_config["trusted_pools"])):
                    message["mesh_hops"] = hops + 1
                    send_task_to_node(target, message)
                    seen_nodes.add(target)
        except Exception as e:
            logging.error(f"Mesh propagation error to {target}: {e}")

###############################################################################
# Mesh Networking Managment
###############################################################################
class MeshNetwork:
    def __init__(self, config: dict):
        self.config = config
        self.peers = {}
        self.messages = deque(maxlen=1000)  # Message history
        self.message_lock = threading.Lock()
        
    def add_peer(self, peer_info: dict) -> None:
        peer_id = peer_info["node_id"]
        with self.message_lock:
            self.peers[peer_id] = {
                "info": peer_info,
                "last_seen": time.time(),
                "status": "active"
            }
            
    def broadcast(self, message: dict) -> None:
        """Broadcast message to all peers in the mesh."""
        message_id = str(uuid.uuid4())
        message["mesh_id"] = message_id
        
        with self.message_lock:
            self.messages.append({
                "id": message_id,
                "time": time.time(),
                "content": message
            })
            
        seen = {session_id}  # Don't send to self
        self.propagate_message(message, seen)
        
    def handle_message(self, message: dict, sender: str) -> None:
        """Handle incoming mesh message."""
        if not self._validate_message(message):
            logging.warning(f"Invalid mesh message from {sender}")
            return
            
        message_id = message.get("mesh_id")
        if self._is_duplicate(message_id):
            return
            
        # Process message based on type
        msg_type = message.get("type")
        if msg_type == "discovery":
            self._handle_discovery(message, sender)
        elif msg_type == "task":
            self._handle_task(message, sender)
        elif msg_type == "status":
            self._handle_status(message, sender)

###############################################################################
# Task Management
###############################################################################
class TaskManager:
    def __init__(self):
        self.tasks = {}
        self.task_lock = threading.Lock()
        self.max_concurrent = 5
        
    def add_task(self, task: dict) -> str:
        """Add a new task to the manager."""
        task_id = str(uuid.uuid4())
        with self.task_lock:
            if len(self.tasks) >= self.max_concurrent:
                return None
                
            self.tasks[task_id] = {
                "info": task,
                "status": "pending",
                "start_time": time.time(),
                "result": None
            }
        return task_id
        
    def get_task_status(self, task_id: str) -> dict:
        """Get the current status of a task."""
        with self.task_lock:
            return self.tasks.get(task_id, {}).copy()
            
    def update_task(self, task_id: str, status: str, result: any = None) -> bool:
        """Update task status and result."""
        with self.task_lock:
            if task_id not in self.tasks:
                return False
            self.tasks[task_id].update({
                "status": status,
                "result": result,
                "update_time": time.time()
            })
        return True
        
    def cleanup_tasks(self) -> None:
        """Remove completed tasks older than 1 hour."""
        cutoff = time.time() - 3600
        with self.task_lock:
            for task_id in list(self.tasks.keys()):
                task = self.tasks[task_id]
                if (task["status"] in ["completed", "failed"] and 
                    task["start_time"] < cutoff):
                    del self.tasks[task_id]

###############################################################################
# Performance Monitoring
###############################################################################
class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            "cpu_usage": deque(maxlen=60),
            "memory_usage": deque(maxlen=60),
            "network_io": deque(maxlen=60),
            "task_throughput": deque(maxlen=60)
        }
        self.start_time = time.time()
        
    def update_metrics(self) -> None:
        """Update system performance metrics."""
        try:
            import psutil
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            net_io = psutil.net_io_counters()
            
            self.metrics["cpu_usage"].append((time.time(), cpu))
            self.metrics["memory_usage"].append((time.time(), mem))
            self.metrics["network_io"].append((time.time(), net_io))
        except ImportError:
            logging.warning("psutil not available for performance monitoring")
            
    def get_metrics(self) -> dict:
        """Get current performance metrics."""
        return {
            "uptime": time.time() - self.start_time,
            "current": {
                "cpu": self.metrics["cpu_usage"][-1][1] if self.metrics["cpu_usage"] else None,
                "memory": self.metrics["memory_usage"][-1][1] if self.metrics["memory_usage"] else None
            },
            "history": {k: list(v) for k, v in self.metrics.items()}
        }

###############################################################################
# Module Management
###############################################################################
class ModuleManager:
    """Manages loadable modules and their lifecycles"""
    def __init__(self):
        self.modules = {}
        self.module_lock = threading.Lock()
        
    def load_module(self, name: str, code: str) -> bool:
        """Load a new module"""
        try:
            with self.module_lock:
                if name in self.modules:
                    return False
                self.modules[name] = {
                    "code": code,
                    "loaded_time": time.time(),
                    "status": "loaded"
                }
            return True
        except Exception as e:
            logging.error(f"Failed to load module {name}: {e}")
            return False
            
    def unload_module(self, name: str) -> bool:
        """Unload a module"""
        with self.module_lock:
            if name not in self.modules:
                return False
            del self.modules[name]
            return True
            
    def get_module_info(self, name: str) -> dict:
        """Get information about a loaded module"""
        with self.module_lock:
            return self.modules.get(name, {}).copy()

###############################################################################
# Main Entry Point
###############################################################################
def validate_config(config: dict) -> bool:
    """Validate configuration security settings"""
    required_settings = {
        "auth_token": str,
        "role": str,
        "ui_mode": str
    }
    
    security_settings = {
        "USE_TLS": bool,
        "RATE_LIMIT_COUNT": int,
        "RATE_LIMIT_WINDOW": int
    }
    
    try:
        # Check required settings
        for setting, expected_type in required_settings.items():
            if setting not in config:
                logging.error(f"Missing required setting: {setting}")
                return False
            if not isinstance(config[setting], expected_type):
                logging.error(f"Invalid type for setting {setting}")
                return False
                
        # Validate security settings
        for setting, expected_type in security_settings.items():
            if setting in globals():
                if not isinstance(globals()[setting], expected_type):
                    logging.error(f"Invalid type for security setting {setting}")
                    return False
                    
        return True
    except Exception as e:
        logging.error(f"Configuration validation error: {e}")
        return False

def graceful_shutdown(error=None, emergency=False):
    """Perform graceful shutdown with multiple fallback levels"""
    global should_cancel
    
    def log_shutdown(message):
        """Log shutdown message safely"""
        try:
            logging.info(message)
            print(message)
        except:
            pass

    try:
        # Level 1: Stop new operations
        should_cancel = True
        log_shutdown("Starting graceful shutdown...")

        # Level 2: Save critical data
        if not emergency:
            try:
                if 'secure_config' in globals():
                    secure_config.save()
                if 'integrity_verifier' in globals():
                    integrity_verifier._save_hashes()
                save_user_commands()
                log_shutdown("Configuration and data saved")
            except Exception as e:
                logging.error(f"Error saving data during shutdown: {e}")

        # Level 3: Stop non-essential services
        try:
            if 'mesh_config' in globals():
                mesh_config["enabled"] = False
            if 'task_manager' in globals():
                task_manager.max_concurrent = 0
            log_shutdown("Non-essential services stopped")
        except Exception as e:
            logging.error(f"Error stopping services: {e}")

        # Level 4: Close network connections
        try:
            for thread in threading.enumerate():
                if thread != threading.current_thread():
                    if hasattr(thread, 'socket'):
                        thread.socket.close()
            log_shutdown("Network connections closed")
        except Exception as e:
            logging.error(f"Error closing network connections: {e}")

        # Level 5: Clean up resources
        try:
            if 'secure_comm' in globals():
                secure_comm.nonce_cache.clear()
            if 'security_enhancements' in globals():
                security_enhancements.session_tokens.clear()
            log_shutdown("Resources cleaned up")
        except Exception as e:
            logging.error(f"Error cleaning up resources: {e}")

        # Level 6: Final logging
        try:
            if error:
                logging.critical(f"Shutdown triggered by error: {error}")
            else:
                logging.info("Clean shutdown completed")
        except:
            pass

    except Exception as e:
        print(f"Error during shutdown: {e}")
    finally:
        if emergency:
            os._exit(1)
        else:
            sys.exit(1 if error else 0)

def initialize_components():
    global module_manager, mesh_network, task_manager, performance_monitor
    
    module_manager = ModuleManager()
    mesh_network = MeshNetwork(mesh_config)
    task_manager = TaskManager()
    performance_monitor = PerformanceMonitor()
    
    def monitoring_loop():
        while True:
            performance_monitor.update_metrics()
            time.sleep(1)
    
    threading.Thread(target=monitoring_loop, daemon=True).start()

def main():
    try:
        # Initialize security first
        try:
            initialize_security()
        except Exception as sec_error:
            logging.error(f"Security initialization failed: {sec_error}")
            print("Attempting to start with minimal security...")
            try:
                # Generate temporary key for basic operation
                temp_key = base64.urlsafe_b64encode(os.urandom(32))
                secure_comm = SecureComm(temp_key)
                secure_config = SecureConfig(os.path.join(CONFIG_DIR, "secure_config.enc"))
            except Exception as e:
                logging.critical(f"Failed to initialize minimal security: {e}")
                graceful_shutdown(e, emergency=True)

        # Validate configuration
        if not validate_config(config):
            logging.critical("Invalid configuration detected")
            graceful_shutdown(SecurityError("Invalid configuration"), emergency=False)

        # Initialize components
        try:
            initialize_components()
        except Exception as comp_error:
            logging.error(f"Component initialization error: {comp_error}")
            print("Starting with essential components only...")

        # Start threads with proper error handling
        essential_threads = [
            (cleanup_nodes, "Node Cleanup"),
            (tcp_task_server, "TCP Server")
        ]
        
        optional_threads = [
            (broadcast_discovery, "Discovery Broadcast"),
            (listen_for_discovery, "Discovery Listener"),
            (cleanup_connection_times, "Connection Cleanup"),
            (cleanup_quarantine, "Quarantine Cleanup"),
            (handshake_refresh, "Handshake Refresh")
        ]

        # Start essential threads
        for thread_func, thread_name in essential_threads:
            try:
                t = threading.Thread(target=thread_func, daemon=True, name=thread_name)
                t.start()
            except Exception as e:
                logging.critical(f"Failed to start essential thread {thread_name}: {e}")
                graceful_shutdown(e)

        # Start optional threads
        for thread_func, thread_name in optional_threads:
            try:
                t = threading.Thread(target=thread_func, daemon=True, name=thread_name)
                t.start()
            except Exception as e:
                logging.warning(f"Optional thread {thread_name} failed to start: {e}")

        # UI initialization with fallbacks
        if config["role"] == "master":
            ui_success = False
            for ui_mode in [config["ui_mode"], "cui", "prompt"]:
                try:
                    if ui_mode == "gui" and tk is not None:
                        main_gui()
                        ui_success = True
                        break
                    elif ui_mode == "cui" and curses is not None:
                        curses.wrapper(main_cui)
                        ui_success = True
                        break
                    elif ui_mode == "prompt":
                        modular_prompt()
                        ui_success = True
                        break
                except Exception as e:
                    logging.error(f"{ui_mode} UI failed: {e}")
                    print(f"Failed to start {ui_mode} interface: {e}")
                    continue

            if not ui_success:
                print("All UI modes failed. Starting minimal command prompt...")
                try:
                    modular_prompt()
                except Exception as e:
                    logging.critical(f"Fatal error in minimal prompt: {e}")
                    graceful_shutdown(e)
        else:
            modular_prompt()

    except KeyboardInterrupt:
        print("\nReceived shutdown signal...")
        graceful_shutdown()
    except Exception as critical_error:
        print(f"Critical error occurred: {critical_error}")
        print("Attempting recovery...")
        graceful_shutdown(critical_error)

if __name__ == "__main__":
    main()

def secure_password_hash(password: str, salt: bytes = None) -> tuple[str, bytes]:
    """Generate secure password hash"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.b64encode(kdf.derive(password.encode())).decode('utf-8')
    return key, salt

class SecureMessageSigner:
    """Sign and verify messages"""
    def __init__(self, key: bytes):
        self.key = key
        
    def sign_message(self, message: dict) -> str:
        """Sign a message with HMAC"""
        message_bytes = json.dumps(message, sort_keys=True).encode()
        signature = hmac.new(self.key, message_bytes, hashlib.sha256).hexdigest()
        return signature
        
    def verify_message(self, message: dict, signature: str) -> bool:
        """Verify message signature"""
        expected_sig = self.sign_message(message)
        return hmac.compare_digest(signature, expected_sig)
