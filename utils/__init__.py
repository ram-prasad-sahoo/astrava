"""
Utility modules for Astrava AI Security Scanner
"""

# Import only modules that don't have circular dependencies
from .logger import setup_logger
from .banner import display_banner
from .risk_calculator import RiskCalculator

# ReportGenerator has circular dependency, import it only when needed
# from .report_generator import ReportGenerator

__all__ = [
    "setup_logger",
    "display_banner",
    "RiskCalculator",
    # "ReportGenerator"  # Commented out due to circular import
]
