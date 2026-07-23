from .checks import analyze_command, scan_secrets, typosquat_check
from .registry import check_package
__all__ = ["analyze_command", "scan_secrets", "typosquat_check", "check_package"]
__version__ = "0.1.0"
