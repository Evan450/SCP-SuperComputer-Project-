"""
SCP System Monitor Module
------------------------
Provides system monitoring and statistics commands.
Requires psutil package for full functionality.

Installation:
1. Save this file to SCP_config folder
2. Run: pip install psutil
3. In SCP, use: modules load system_monitor.py
"""

import time
from datetime import datetime
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Some features will be limited.")

def get_module_info():
    """Return module metadata"""
    return {
        "name": "system_monitor",
        "version": "1.0",
        "author": "Discover Interactive",
        "description": "System monitoring and statistics commands",
        "commands": {
            "sysinfo": "Show system information summary",
            "proclist": "List running processes",
            "diskinfo": "Show disk usage information",
            "netstat": "Show network statistics",
            "meminfo": "Show memory usage details"
        }
    }

def format_bytes(bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024

def sysinfo_cmd(args):
    """Display system information summary"""
    if not PSUTIL_AVAILABLE:
        return "Error: psutil package required for system monitoring"
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        
        return (
            "System Information:\n"
            f"CPU Usage: {cpu_percent}%\n"
            f"Memory: {memory.percent}% used ({format_bytes(memory.used)} / {format_bytes(memory.total)})\n"
            f"Disk: {disk.percent}% used ({format_bytes(disk.used)} / {format_bytes(disk.total)})\n"
            f"Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Platform: {psutil.Process().name()}"
        )
    except Exception as e:
        return f"Error getting system info: {e}"

def proclist_cmd(args):
    """List top processes by memory usage"""
    if not PSUTIL_AVAILABLE:
        return "Error: psutil package required for process listing"
    
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by memory usage
        processes.sort(key=lambda x: x['memory_percent'] or 0, reverse=True)
        
        result = "Top Processes by Memory Usage:\n"
        result += "PID      CPU%    MEM%    NAME\n"
        result += "-" * 40 + "\n"
        
        for proc in processes[:10]:  # Show top 10
            result += f"{proc['pid']:<8} {proc['cpu_percent']:<7.1f} {proc['memory_percent']:<7.1f} {proc['name']}\n"
        
        return result
    except Exception as e:
        return f"Error listing processes: {e}"

def diskinfo_cmd(args):
    """Show disk usage information"""
    if not PSUTIL_AVAILABLE:
        return "Error: psutil package required for disk information"
    
    try:
        result = "Disk Usage Information:\n"
        result += "Device     Total      Used       Free    Use%    Mount\n"
        result += "-" * 60 + "\n"
        
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                result += (f"{partition.device[:10]:<10} {format_bytes(usage.total):<10} "
                          f"{format_bytes(usage.used):<10} {format_bytes(usage.free):<10} "
                          f"{usage.percent:>4}%    {partition.mountpoint}\n")
            except:
                continue
                
        return result
    except Exception as e:
        return f"Error getting disk info: {e}"

def netstat_cmd(args):
    """Show network statistics"""
    if not PSUTIL_AVAILABLE:
        return "Error: psutil package required for network statistics"
    
    try:
        io_counters = psutil.net_io_counters()
        connections = psutil.net_connections()
        
        result = "Network Statistics:\n\n"
        result += f"Bytes Sent: {format_bytes(io_counters.bytes_sent)}\n"
        result += f"Bytes Received: {format_bytes(io_counters.bytes_recv)}\n"
        result += f"Packets Sent: {io_counters.packets_sent}\n"
        result += f"Packets Received: {io_counters.packets_recv}\n\n"
        
        result += "Active Connections:\n"
        result += "Proto  Local Address           Remote Address          Status\n"
        result += "-" * 70 + "\n"
        
        for conn in connections[:10]:  # Show top 10
            try:
                local = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                result += f"{conn.type:<6} {local:<21} {remote:<21} {conn.status}\n"
            except:
                continue
                
        return result
    except Exception as e:
        return f"Error getting network stats: {e}"

def meminfo_cmd(args):
    """Show detailed memory usage"""
    if not PSUTIL_AVAILABLE:
        return "Error: psutil package required for memory information"
    
    try:
        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        result = "Memory Information:\n\n"
        result += "Virtual Memory:\n"
        result += f"Total: {format_bytes(virtual.total)}\n"
        result += f"Available: {format_bytes(virtual.available)}\n"
        result += f"Used: {format_bytes(virtual.used)} ({virtual.percent}%)\n"
        result += f"Free: {format_bytes(virtual.free)}\n\n"
        
        result += "Swap Memory:\n"
        result += f"Total: {format_bytes(swap.total)}\n"
        result += f"Used: {format_bytes(swap.used)} ({swap.percent}%)\n"
        result += f"Free: {format_bytes(swap.free)}\n"
        
        return result
    except Exception as e:
        return f"Error getting memory info: {e}"

def register_commands():
    """Register module commands with SCP"""
    return {
        "sysinfo": (sysinfo_cmd, "Show system information summary"),
        "proclist": (proclist_cmd, "List running processes"),
        "diskinfo": (diskinfo_cmd, "Show disk usage information"),
        "netstat": (netstat_cmd, "Show network statistics"),
        "meminfo": (meminfo_cmd, "Show memory usage details")
    }