"""
Spamreporter package exposes helpers for parsing spam EML files
and generating multilingual abuse reports for local mail servers.
"""

from .analysis import analyze_message
from .reporting import ReportBuilder

__all__ = [
    "analyze_message",
    "ReportBuilder",
]

__version__ = "1762987066"
