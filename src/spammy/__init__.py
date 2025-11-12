"""
Spamreporter package exposes helpers for parsing spam EML files
and generating multilingual abuse reports for local mail servers.
"""

from .analysis import analyze_message
from .reporting import ReportBuilder
from .version import __version__

__all__ = [
    "analyze_message",
    "ReportBuilder",
    "__version__",
]
