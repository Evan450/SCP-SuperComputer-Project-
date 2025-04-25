"""
SCP Module Template
------------------
This is a template for creating modules for the SuperComputer Project (SCP).
Save your module in the SCP_config folder with a descriptive name.

Module Requirements:
1. Must include properly formatted docstrings
2. Must return valid command functions
3. Must use the provided safe_eval for calculations
4. Should avoid system-level operations without explicit permission
5. Should include error handling
"""

def get_module_info():
    """Return module metadata"""
    return {
        "name": "template_module",
        "version": "1.0",
        "author": "Your Name",
        "description": "Template module for SCP",
        "commands": {
            "template_cmd": "Example command that demonstrates module usage",
            "template_calc": "Example calculation using safe_eval"
        }
    }

def template_cmd(args):
    """
    Example command implementation
    
    Args:
        args (list): Command arguments passed from SCP
        
    Returns:
        str: Command output
    """
    try:
        if not args:
            return "Template command: No arguments provided"
        return f"Template command received: {' '.join(args)}"
    except Exception as e:
        return f"Template command error: {e}"

def template_calc(args):
    """
    Example calculation command using safe_eval
    
    Args:
        args (list): Mathematical expression components
        
    Returns:
        str: Calculation result or error message
    """
    try:
        if not args:
            return "Usage: template_calc <expression>"
        expression = " ".join(args)
        # Note: safe_eval is provided by SCP for secure calculations
        result = safe_eval(expression)
        return f"Calculation result: {result}"
    except Exception as e:
        return f"Calculation error: {e}"

# Module registration function (required)
def register_commands():
    """
    Register module commands with SCP
    
    Returns:
        dict: Command name to function mapping
    """
    return {
        "template_cmd": (template_cmd, "Example command implementation"),
        "template_calc": (template_calc, "Example calculation using safe_eval")
    }

# Optional initialization function
def initialize():
    """
    Optional initialization function
    Called when module is loaded
    
    Returns:
        bool: True if initialization successful, False otherwise
    """
    try:
        # Add any necessary initialization here
        return True
    except Exception as e:
        logging.error(f"Module initialization error: {e}")
        return False

# Example usage:
"""
To use this template:
1. Copy this file to SCP_config/your_module_name.py
2. Rename the functions and update the metadata
3. Implement your command logic
4. Load the module using: modules load your_module_name.py

Example implementation:
```python
def my_command(args):
    if not args:
        return "Usage: my_command <argument>"
    try:
        # Your command logic here
        result = process_args(args)
        return f"Command result: {result}"
    except Exception as e:
        return f"Error: {e}"

def register_commands():
    return {
        "my_command": (my_command, "Description of my command")
    }
```
"""