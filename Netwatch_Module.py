"""
SCP Network Watch Module
-----------------------
Monitors network connections and alerts on suspicious activity.

Commands:
- netwatch_start
- netwatch_stop
- netwatch_list
"""

import psutil
import threading
import time
from collections import defaultdict
import logging


discovered_nodes_lock = threading.Lock()

discovered_nodes = {}

class NetworkMonitor:
    def __init__(self):
        self.active = False
        self.monitor_thread = None
        self.connections = defaultdict(lambda: {
            "first_seen": time.time(),
            "last_seen": time.time(),
            "connection_count": 0,
            "status": "unknown"
        })
        self.known_nodes = set()
        self.lock = threading.Lock()
        
    def start(self):
        """Start network monitoring"""
        if self.active:
            return "Network monitoring is already running"
            
        self.active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="Network Monitor"
        )
        self.monitor_thread.start()
        return "Network monitoring started"
        
    def stop(self):
        """Stop network monitoring"""
        if not self.active:
            return "Network monitoring is not running"
            
        self.active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        return "Network monitoring stopped"
        
    def list_connections(self):
        """List monitored connections"""
        with self.lock:
            if not self.connections:
                return "No connections monitored yet"
                
            output = ["Monitored Connections:"]
            for ip, data in self.connections.items():
                status = data["status"]
                count = data["connection_count"]
                first = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(data["first_seen"]))
                last = time.strftime('%Y-%m-%d %H:%M:%S', 
                                   time.localtime(data["last_seen"]))
                output.append(
                    f"IP: {ip}\n"
                    f"  Status: {status}\n"
                    f"  Connections: {count}\n"
                    f"  First seen: {first}\n"
                    f"  Last seen: {last}\n"
                )
            return "\n".join(output)
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.active:
            try:
                # Update known nodes
                with discovered_nodes_lock:
                    self.known_nodes = set(discovered_nodes.keys())
                
                # Get current connections
                connections = psutil.net_connections()
                current_time = time.time()
                
                with self.lock:
                    for conn in connections:
                        if not conn.raddr:  # Skip connections with no remote address
                            continue
                            
                        ip = conn.raddr.ip
                        if ip not in self.connections:
                            # New connection
                            self.connections[ip]["first_seen"] = current_time
                            self.connections[ip]["status"] = (
                                "cluster" if ip in self.known_nodes else "unknown"
                            )
                            
                        self.connections[ip]["last_seen"] = current_time
                        self.connections[ip]["connection_count"] += 1
                        
                        # Alert on unknown IPs
                        if (self.connections[ip]["status"] == "unknown" and 
                            ip not in self.known_nodes):
                            logging.warning(
                                f"Connection from unknown IP detected: {ip}"
                            )
                
                # Clean old entries
                self._cleanup_old_entries()
                
            except Exception as e:
                logging.error(f"Network monitoring error: {e}")
                
            time.sleep(5)  # Check every 5 seconds
            
    def _cleanup_old_entries(self):
        """Remove old entries"""
        current_time = time.time()
        with self.lock:
            for ip in list(self.connections.keys()):
                if current_time - self.connections[ip]["last_seen"] > 3600:  # 1 hour
                    del self.connections[ip]

# Create global monitor instance
network_monitor = NetworkMonitor()

def get_module_info():
    return {
        "name": "netwatch",
        "version": "1.1",
        "author": "Discover Interactive",
        "description": "Network connection monitoring and alerting",
        "commands": {
            "netwatch_start": "Start network monitoring",
            "netwatch_stop": "Stop network monitoring",
            "netwatch_list": "List monitored connections"
        }
    }

def register_commands():
    return {
        "netwatch_start": (
            lambda args: network_monitor.start(),
            "Start network monitoring"
        ),
        "netwatch_stop": (
            lambda args: network_monitor.stop(),
            "Stop network monitoring"
        ),
        "netwatch_list": (
            lambda args: network_monitor.list_connections(),
            "List monitored connections"
        )
    }

def initialize():
    """Initialize module"""
    try:
        if not psutil:
            return False
        return True
    except Exception as e:
        logging.error(f"Netwatch initialization error: {e}")
        return False