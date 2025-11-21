"""
Astrava AI Security Scanner
Advanced AI-Powered Web Security Scanner with OWASP Top 10 Coverage

Author: RAM (Ram Prasad Sahoo)
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "RAM (Ram Prasad Sahoo)"
__email__ = "ramprasadsahoo42@gmail.com"
__license__ = "MIT"
__description__ = "Advanced AI-Powered Web Security Scanner with OWASP Top 10 Coverage"

from .core.scanner_engine import AtlasAIScanner
from .core.config import Config
from .core.ai_engine import AIEngine

__all__ = [
    "AtlasAIScanner",
    "Config", 
    "AIEngine",
    "__version__",
    "__author__",
    "__license__"
]