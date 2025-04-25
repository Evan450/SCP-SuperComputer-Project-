"""
SCP File Synchronization Module
------------------------------
Enables secure file transfer between nodes.

Commands:
- pushfile <target_node> <localpath> <remotepath>
- listfiles
"""

import os
import base64
import hashlib
from pathlib import Path

# Constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
ALLOWED_EXTENSIONS = {'.txt', '.json', '.log', '.py', '.cfg', '.ini'}
SYNC_DIR = os.path.join("SCP_config", "sync_files")

def get_module_info():
    return {
        "name": "filesync",
        "version": "1.0",
        "author": "Discover Interactive",
        "description": "Secure file synchronization between nodes",
        "commands": {
            "pushfile": "Send file to another node securely",
            "listfiles": "List synchronized files"
        }
    }

def validate_path(path):
    """Validate file path for security"""
    try:
        path = os.path.abspath(path)
        if not any(path.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            return False, "File type not allowed"
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return False, "File too large"
        return True, path
    except Exception as e:
        return False, f"Path validation error: {e}"

def push_file(target, local_path, remote_path):
    """Prepare file for secure transfer"""
    try:
        valid, result = validate_path(local_path)
        if not valid:
            return f"Local file error: {result}"
        
        if not os.path.exists(local_path):
            return "Local file not found"
            
        # Read and encode file
        with open(local_path, 'rb') as f:
            content = f.read()
            
        # Calculate hash for integrity
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Prepare transfer package
        transfer_data = {
            "auth_token": config["auth_token"],
            "origin": session_id,
            "query_id": str(uuid.uuid4()),
            "task_type": "file_transfer",
            "filename": os.path.basename(remote_path),
            "content": base64.b64encode(content).decode('utf-8'),
            "hash": file_hash,
            "size": len(content)
        }
        
        # Send to target node
        result = send_task_to_node(target, transfer_data)
        if result.get("status") == "success":
            return f"File transferred successfully to {target}"
        else:
            return f"Transfer failed: {result.get('error', 'Unknown error')}"
            
    except Exception as e:
        return f"File push error: {e}"

def list_files():
    """List synchronized files"""
    try:
        if not os.path.exists(SYNC_DIR):
            return "No synchronized files found"
            
        files = []
        for root, _, filenames in os.walk(SYNC_DIR):
            for filename in filenames:
                path = os.path.join(root, filename)
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
                files.append({
                    "name": filename,
                    "size": size,
                    "modified": mtime
                })
                
        if not files:
            return "No synchronized files found"
            
        output = ["Synchronized Files:"]
        for f in files:
            size_str = f"{f['size'] / 1024:.1f}KB"
            date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f['modified']))
            output.append(f"  {f['name']} ({size_str}, modified: {date_str})")
            
        return "\n".join(output)
        
    except Exception as e:
        return f"Error listing files: {e}"

def initialize():
    """Initialize module"""
    try:
        if not os.path.exists(SYNC_DIR):
            os.makedirs(SYNC_DIR)
        return True
    except Exception as e:
        logging.error(f"Filesync initialization error: {e}")
        return False

def register_commands():
    """Register module commands"""
    return {
        "pushfile": (
            lambda args: push_file(args[0], args[1], args[2]) if len(args) == 3 
            else "Usage: pushfile <target_node> <localpath> <remotepath>",
            "Send file to another node securely"
        ),
        "listfiles": (
            lambda args: list_files(),
            "List synchronized files"
        )
    }