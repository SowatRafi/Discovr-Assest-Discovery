"""
Azure package for Discovr

This package contains all Azure-specific discovery, reporting, and exporting
modules. It allows Discovr to keep core and CLI code clean while
delegating Azure cloud logic to this dedicated package.
"""

from .discovery import AzureDiscovery
from .exporter import AzureExporter
from .reporter import AzureReporter

__all__ = [
    "AzureDiscovery",
    "AzureExporter",
    "AzureReporter",
]
