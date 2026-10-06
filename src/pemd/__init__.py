"""Static-first hybrid Windows PE malware detection framework.

Defensive research prototype. It never executes samples itself; dynamic
analysis is delegated to an isolated CAPE sandbox when explicitly enabled.
"""

__version__ = "0.1.0"
