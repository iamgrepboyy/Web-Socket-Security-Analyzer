#!/usr/bin/env python3
"""Start the local WebSocket Security Scanner web UI."""

from websocket_security_scanner import serve


if __name__ == "__main__":
    serve("127.0.0.1", 8765)
