# WebSocket Security Analyzer

A local, browser-based security scanner for WebSocket endpoints. It performs protocol and configuration checks to help assess whether a WebSocket service is exposing common misconfigurations such as insecure transport, weak TLS setup, missing origin validation, unauthenticated access, suspicious subprotocol handling, malformed input exposure, and denial-of-service risks.

This project is intentionally focused on generic WebSocket security issues and does not attempt to prove application-specific business logic flaws, role bypasses, or tenant isolation problems without a real application context.

## Features

- Checks whether the endpoint uses `ws://` or `wss://`
- Validates TLS certificate and protocol negotiation
- Verifies RFC 6455 handshake behavior
- Tests Origin and CSWSH protections
- Checks for unauthenticated WebSocket acceptance
- Detects credentials or tokens in the WebSocket URL
- Evaluates subprotocol allowlist behavior
- Reviews compression negotiation and protocol downgrade risks
- Inspects header disclosure and malformed input handling
- Tests for injection-style payload responses and verbose error leakage
- Assesses large-message, rate-limit, connection-limit, and idle-timeout behavior
- Provides a local HTML UI and JSON API for scanning

## Project structure

- `index.html` — local web interface for running scans
- `run_scanner.py` — simple launcher that starts the local scanner server
- `websocket_security_scanner.py` — core scanner logic, HTTP/WebSocket probe engine, and REST API

## Requirements

- Python 3.8+
- Standard library only; no external dependencies are required

## Quick start

1. Clone the repository.
2. Navigate to the project folder.
3. Start the local scanner UI:

```bash
python3 run_scanner.py
```

Then open:

```text
http://127.0.0.1:8765/
```

The web UI will let you enter a WebSocket URL and run the scanner.

## Command-line usage

You can also scan a target directly from the command line:

```bash
python3 websocket_security_scanner.py --url ws://localhost:8080/socket
```

Disable TLS verification when necessary for testing and debugging local/self-signed endpoints:

```bash
python3 websocket_security_scanner.py --url wss://example.com/socket --no-verify-tls
```

Start the scanner in server mode explicitly:

```bash
python3 websocket_security_scanner.py --serve --host 127.0.0.1 --port 8765
```

## API

The local server exposes a JSON API at:

```text
POST /api/scan
```

Example request body:

```json
{
  "url": "wss://example.com/socket",
  "authorized": true,
  "verifyTls": true,
  "timeout": 7.0,
  "idleSeconds": 10
}
```

The response includes a summary plus detailed findings for each security check.

## Important usage note

This tool is intended for authorized security testing only. Do not scan systems you do not own or do not have explicit permission to test. The project is designed to help identify protocol and configuration weaknesses, but it is not a substitute for secure application design, debugging, or project-specific threat modeling.

## Disclaimer

The scanner focuses on generic WebSocket security checks such as transport security, protocol correctness, malformed input handling, connection abuse, and information disclosure. It does not verify application-specific vulnerabilities like insecure business logic, authorization flaws, or tenant isolation issues without a live application context and valid test accounts.

## License

This project does not currently declare a license. If you plan to reuse or redistribute it, check the repository settings or add an appropriate open-source license before publishing.
