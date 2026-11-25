"""Web3 Security Radar — Personal Web3 security intelligence pipeline."""

import socket
import sys

# Configure UTF-8 encoding for Windows console to prevent UnicodeEncodeError
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# Prefer IPv4 over IPv6 on Windows to prevent WinError 10060 TCP timeouts to googleapis.com
_original_getaddrinfo = socket.getaddrinfo


def _ipv4_preferred_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        results = _original_getaddrinfo(host, port, family, type, proto, flags)
        v4 = [r for r in results if r[0] == socket.AF_INET]
        return v4 if v4 else results
    except Exception:
        return _original_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _ipv4_preferred_getaddrinfo

__version__ = "0.2.0"

