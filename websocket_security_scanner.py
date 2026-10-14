#!/usr/bin/env python3
"""
Local WebSocket misconfiguration scanner.

This tool intentionally focuses on generic protocol and configuration checks.
It does not try to prove application-specific issues such as IDOR, tenant
isolation bypass, admin channel authorization, workflow bypass, or business
logic flaws, because those require real event names, roles, object IDs, and
multiple authorized accounts.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_TIMEOUT = 7.0
DEFAULT_IDLE_SECONDS = 10
MAX_REQUEST_BYTES = 64 * 1024


@dataclass
class ScanConfig:
    verify_tls: bool = True
    timeout: float = DEFAULT_TIMEOUT
    idle_seconds: int = DEFAULT_IDLE_SECONDS


class WebSocketError(Exception):
    pass


class Frame:
    def __init__(self, opcode: int, payload: bytes, fin: bool = True, close_code: Optional[int] = None):
        self.opcode = opcode
        self.payload = payload
        self.fin = fin
        self.close_code = close_code

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", "replace")


class RawWebSocket:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        origin: Optional[str] = None,
        protocols: Optional[List[str]] = None,
        extensions: Optional[str] = None,
        version: str = "13",
        verify_tls: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.origin = origin
        self.protocols = protocols or []
        self.extensions = extensions
        self.version = version
        self.verify_tls = verify_tls
        self.extra_headers = extra_headers or {}
        self.sock: Optional[socket.socket] = None
        self.response_status: Optional[int] = None
        self.response_reason = ""
        self.response_headers: Dict[str, str] = {}
        self.key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        self.expected_accept = base64.b64encode(hashlib.sha1((self.key + GUID).encode("ascii")).digest()).decode("ascii")
        self.selected_protocol = ""
        self.selected_extensions = ""

    def connect(self) -> "RawWebSocket":
        parsed = parse_ws_url(self.url)
        raw_sock: socket.socket = socket.create_connection((parsed["host"], parsed["port"]), self.timeout)
        raw_sock.settimeout(self.timeout)

        if parsed["scheme"] == "wss":
            if self.verify_tls:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_unverified_context()
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=parsed["host"])
        else:
            self.sock = raw_sock

        headers = [
            f"GET {parsed['path']} HTTP/1.1",
            f"Host: {parsed['host_header']}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {self.key}",
            f"Sec-WebSocket-Version: {self.version}",
        ]
        if self.origin is not None:
            headers.append(f"Origin: {self.origin}")
        if self.protocols:
            headers.append("Sec-WebSocket-Protocol: " + ", ".join(self.protocols))
        if self.extensions:
            headers.append("Sec-WebSocket-Extensions: " + self.extensions)
        for name, value in self.extra_headers.items():
            headers.append(f"{name}: {value}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii", "replace")
        self.sock.sendall(request)

        raw_response = self._read_until_headers()
        status, reason, headers_map = parse_http_response(raw_response)
        self.response_status = status
        self.response_reason = reason
        self.response_headers = headers_map
        self.selected_protocol = headers_map.get("sec-websocket-protocol", "")
        self.selected_extensions = headers_map.get("sec-websocket-extensions", "")

        if status != 101:
            self.close()
            raise WebSocketError(f"upgrade rejected with HTTP {status}")

        actual_accept = headers_map.get("sec-websocket-accept", "")
        if actual_accept != self.expected_accept:
            self.close()
            raise WebSocketError("invalid Sec-WebSocket-Accept value")

        return self

    def close(self) -> None:
        sock = self.sock
        self.sock = None
        if not sock:
            return
        with contextlib.suppress(Exception):
            sock.close()

    def send_text(self, text: str) -> None:
        self._send_frame(text.encode("utf-8", "replace"), opcode=0x1)

    def send_binary(self, payload: bytes) -> None:
        self._send_frame(payload, opcode=0x2)

    def send_close(self, code: int = 1000) -> None:
        self._send_frame(struct.pack("!H", code), opcode=0x8)

    def receive(self, timeout: Optional[float] = None) -> Optional[Frame]:
        if not self.sock:
            raise WebSocketError("socket is not connected")
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                first = self._recv_exact(2)
                if not first:
                    return None
                b1, b2 = first[0], first[1]
                fin = bool(b1 & 0x80)
                opcode = b1 & 0x0F
                masked = bool(b2 & 0x80)
                length = b2 & 0x7F
                if length == 126:
                    length = struct.unpack("!H", self._recv_exact(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", self._recv_exact(8))[0]
                mask_key = self._recv_exact(4) if masked else b""
                payload = self._recv_exact(length) if length else b""
                if masked:
                    payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))

                if opcode == 0x9:
                    self._send_frame(payload, opcode=0xA)
                    continue
                if opcode == 0xA:
                    continue
                if opcode == 0x8:
                    close_code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                    return Frame(opcode, payload, fin=fin, close_code=close_code)
                return Frame(opcode, payload, fin=fin)
        except socket.timeout:
            return None
        finally:
            if timeout is not None and self.sock:
                self.sock.settimeout(old_timeout)

    def _read_until_headers(self) -> bytes:
        if not self.sock:
            raise WebSocketError("socket is not connected")
        chunks = []
        total = 0
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            data = b"".join(chunks)
            if b"\r\n\r\n" in data:
                return data.split(b"\r\n\r\n", 1)[0]
            if total > MAX_REQUEST_BYTES:
                raise WebSocketError("handshake response too large")
        return b"".join(chunks)

    def _send_frame(self, payload: bytes, opcode: int) -> None:
        if not self.sock:
            raise WebSocketError("socket is not connected")
        first = 0x80 | opcode
        length = len(payload)
        mask_key = secrets.token_bytes(4)
        if length < 126:
            header = struct.pack("!BB", first, 0x80 | length)
        elif length < (1 << 16):
            header = struct.pack("!BBH", first, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, length)
        masked = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + mask_key + masked)

    def _recv_exact(self, length: int) -> bytes:
        if not self.sock:
            raise WebSocketError("socket is not connected")
        chunks = []
        remaining = length
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise WebSocketError("connection closed while reading frame")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def parse_ws_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("URL must start with ws:// or wss://")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.params:
        path += ";" + parsed.params
    if parsed.query:
        path += "?" + parsed.query
    default_port = 443 if parsed.scheme == "wss" else 80
    host_header = parsed.hostname if port == default_port else f"{parsed.hostname}:{port}"
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": port,
        "path": path,
        "host_header": host_header,
        "parsed": parsed,
    }


def parse_http_response(raw: bytes) -> Tuple[int, str, Dict[str, str]]:
    text = raw.decode("iso-8859-1", "replace")
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise WebSocketError("invalid HTTP response during upgrade")
    parts = lines[0].split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return status, reason, headers


def make_result(
    test_id: str,
    title: str,
    category: str,
    status: str,
    severity: str,
    summary: str,
    *,
    evidence: Optional[List[str]] = None,
    remediation: str = "",
) -> Dict[str, Any]:
    return {
        "id": test_id,
        "title": title,
        "category": category,
        "status": status,
        "severity": severity,
        "summary": summary,
        "evidence": evidence or [],
        "remediation": remediation,
    }


def connect_probe(
    url: str,
    config: ScanConfig,
    *,
    origin: Optional[str] = None,
    protocols: Optional[List[str]] = None,
    extensions: Optional[str] = None,
    version: str = "13",
) -> Tuple[bool, Dict[str, Any]]:
    ws = RawWebSocket(
        url,
        timeout=config.timeout,
        origin=origin,
        protocols=protocols,
        extensions=extensions,
        version=version,
        verify_tls=config.verify_tls,
    )
    try:
        ws.connect()
        info = {
            "status": ws.response_status,
            "headers": ws.response_headers,
            "protocol": ws.selected_protocol,
            "extensions": ws.selected_extensions,
            "expected_accept": ws.expected_accept,
        }
        ws.close()
        return True, info
    except Exception as exc:
        info = {
            "error": str(exc),
            "status": ws.response_status,
            "headers": ws.response_headers,
            "protocol": ws.selected_protocol,
            "extensions": ws.selected_extensions,
            "expected_accept": ws.expected_accept,
        }
        ws.close()
        return False, info


def try_send_receive(
    url: str,
    config: ScanConfig,
    payload: Any,
    *,
    binary: bool = False,
    receive_timeout: float = 2.5,
) -> Dict[str, Any]:
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    try:
        ws.connect()
        if binary:
            ws.send_binary(payload)
        else:
            ws.send_text(str(payload))
        frame = ws.receive(receive_timeout)
        ready = True
        if frame and frame.opcode == 0x8:
            ready = False
        response = None
        if frame and frame.opcode in {0x1, 0x2}:
            response = frame.text if frame.opcode == 0x1 else frame.payload.hex()[:160]
        ws.close()
        return {"connected": True, "open_after_send": ready, "response": response, "close_code": frame.close_code if frame else None}
    except Exception as exc:
        ws.close()
        return {"connected": False, "error": str(exc), "open_after_send": False, "response": None}


def test_transport(url: str, config: ScanConfig) -> Dict[str, Any]:
    del config
    try:
        parsed = parse_ws_url(url)
    except Exception as exc:
        return make_result("T01", "Transport encryption", "Transport", "error", "info", str(exc))
    if parsed["scheme"] == "wss":
        return make_result("T01", "Transport encryption", "Transport", "pass", "info", "The endpoint uses wss://.", evidence=["Traffic is protected by TLS in transit."])
    return make_result(
        "T01",
        "Transport encryption",
        "Transport",
        "fail",
        "critical",
        "The endpoint uses ws:// without TLS.",
        evidence=["Messages and credentials can be intercepted or modified on the network."],
        remediation="Use wss:// and reject plain ws:// upgrade requests in production.",
    )


def test_tls(url: str, config: ScanConfig) -> Dict[str, Any]:
    try:
        parsed = parse_ws_url(url)
    except Exception as exc:
        return make_result("T02", "TLS certificate and protocol", "Transport", "error", "info", str(exc))
    if parsed["scheme"] != "wss":
        return make_result("T02", "TLS certificate and protocol", "Transport", "info", "info", "TLS checks do not apply to ws:// endpoints.")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed["host"], parsed["port"]), config.timeout) as raw:
            raw.settimeout(config.timeout)
            with ctx.wrap_socket(raw, server_hostname=parsed["host"]) as tls:
                version = tls.version() or "unknown"
                cipher = tls.cipher()
                cert = tls.getpeercert()
    except ssl.SSLError as exc:
        return make_result(
            "T02",
            "TLS certificate and protocol",
            "Transport",
            "fail",
            "high",
            "TLS certificate validation failed.",
            evidence=[str(exc)],
            remediation="Use a publicly trusted certificate with a valid hostname and complete certificate chain.",
        )
    except Exception as exc:
        return make_result("T02", "TLS certificate and protocol", "Transport", "error", "info", "TLS probe failed.", evidence=[str(exc)])

    evidence = [f"TLS version: {version}"]
    if cipher:
        evidence.append(f"Cipher: {cipher[0]} ({cipher[1]}, {cipher[2]} bits)")
    not_after = cert.get("notAfter") if cert else None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days_left = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
        evidence.append(f"Certificate expires in {days_left} days: {expires.date().isoformat()}")
        if days_left < 0:
            return make_result("T02", "TLS certificate and protocol", "Transport", "fail", "high", "The TLS certificate is expired.", evidence=evidence)
        if days_left <= 30:
            return make_result("T02", "TLS certificate and protocol", "Transport", "warning", "medium", "The TLS certificate expires soon.", evidence=evidence)

    if version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        return make_result(
            "T02",
            "TLS certificate and protocol",
            "Transport",
            "fail",
            "high",
            "A deprecated TLS protocol was negotiated.",
            evidence=evidence,
            remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Prefer TLS 1.2 or TLS 1.3.",
        )
    return make_result("T02", "TLS certificate and protocol", "Transport", "pass", "info", "TLS certificate validation and protocol negotiation succeeded.", evidence=evidence)


def test_handshake(url: str, config: ScanConfig) -> Dict[str, Any]:
    ok, info = connect_probe(url, config)
    if ok:
        headers = info["headers"]
        evidence = [f"HTTP status: {info['status']}", f"Sec-WebSocket-Accept present: {'sec-websocket-accept' in headers}"]
        if info.get("protocol"):
            evidence.append(f"Subprotocol: {info['protocol']}")
        if info.get("extensions"):
            evidence.append(f"Extensions: {info['extensions']}")
        return make_result("T03", "RFC 6455 handshake", "Protocol", "pass", "info", "The WebSocket opening handshake completed correctly.", evidence=evidence)
    status = info.get("status")
    severity = "low" if status else "info"
    return make_result("T03", "RFC 6455 handshake", "Protocol", "fail", severity, "The WebSocket handshake did not complete.", evidence=[f"HTTP status: {status}", info.get("error", "")])


def test_origin(url: str, config: ScanConfig, origin: str, test_id: str, title: str, severity: str) -> Dict[str, Any]:
    ok, info = connect_probe(url, config, origin=origin)
    status = info.get("status")
    if ok:
        return make_result(
            test_id,
            title,
            "Origin / CSWSH",
            "fail",
            severity,
            f"The server accepted Origin: {origin}.",
            evidence=[f"HTTP status: {status}", "Browser cookie-based sessions may be exposed to CSWSH if this endpoint uses cookies."],
            remediation="Validate the Origin header during the WebSocket upgrade and allow only trusted HTTPS origins.",
        )
    if status in {400, 401, 403, 404, 426}:
        return make_result(test_id, title, "Origin / CSWSH", "pass", "info", f"The server rejected Origin: {origin}.", evidence=[f"HTTP status: {status}"])
    return make_result(test_id, title, "Origin / CSWSH", "info", "info", "Origin behavior was inconclusive.", evidence=[f"HTTP status: {status}", info.get("error", "")])


def test_unauthenticated(url: str, config: ScanConfig) -> Dict[str, Any]:
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    try:
        ws.connect()
        ws.send_text(json.dumps({"type": "ping", "source": "ws_security_scanner"}))
        frame = ws.receive(2.5)
        response = frame.text[:180] if frame and frame.opcode == 0x1 else None
        ws.close()
        evidence = ["The server completed a WebSocket upgrade without any Authorization header or cookie supplied by this scanner."]
        if response:
            evidence.append(f"Probe response: {response}")
            return make_result(
                "T07",
                "Unauthenticated connection",
                "Authentication",
                "warning",
                "medium",
                "The endpoint accepts unauthenticated WebSocket connections and responds to a probe.",
                evidence=evidence,
                remediation="Require authentication during upgrade or as the first message before any sensitive operation is available.",
            )
        return make_result(
            "T07",
            "Unauthenticated connection",
            "Authentication",
            "warning",
            "low",
            "The endpoint accepts unauthenticated WebSocket connections.",
            evidence=evidence,
            remediation="If this socket is not intentionally public, require authentication before accepting or processing messages.",
        )
    except Exception as exc:
        ws.close()
        return make_result("T07", "Unauthenticated connection", "Authentication", "pass", "info", "The endpoint did not accept a raw unauthenticated connection.", evidence=[str(exc)])


def test_url_secrets(url: str, config: ScanConfig) -> Dict[str, Any]:
    del config
    try:
        parsed = parse_ws_url(url)["parsed"]
    except Exception as exc:
        return make_result("T08", "Sensitive data in URL", "Authentication", "error", "info", str(exc))
    sensitive_names = {
        "access_token",
        "auth_token",
        "id_token",
        "refresh_token",
        "bearer",
        "api_key",
        "apikey",
        "api-key",
        "password",
        "passwd",
        "authorization",
        "credential",
        "credentials",
        "session",
        "session_id",
        "sessionid",
        "private_key",
        "client_secret",
        "jwt",
        "token",
        "secret",
        "sid",
    }
    evidence = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = name.lower()
        if lowered in sensitive_names or any(word in lowered for word in ["token", "secret", "pass", "auth", "key", "session"]):
            evidence.append(f"Query parameter '{name}' looks sensitive.")
        if re.match(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", value):
            evidence.append(f"Query parameter '{name}' appears to contain a JWT.")
        elif len(value) >= 32 and re.match(r"^[A-Za-z0-9+/=_-]+$", value):
            evidence.append(f"Query parameter '{name}' contains a long encoded value.")
    if evidence:
        return make_result(
            "T08",
            "Sensitive data in URL",
            "Authentication",
            "fail",
            "high",
            "The WebSocket URL appears to contain credentials or tokens.",
            evidence=evidence,
            remediation="Avoid credentials in URLs because they leak into logs, browser history, and proxy records. Use secure cookies or a short-lived one-time ticket.",
        )
    return make_result("T08", "Sensitive data in URL", "Authentication", "pass", "info", "No obvious secrets were found in the WebSocket URL query string.")


def test_subprotocol(url: str, config: ScanConfig) -> Dict[str, Any]:
    fake_protocols = ["admin", "superuser", "internal", "debug", "v2-admin"]
    ok, info = connect_probe(url, config, protocols=fake_protocols)
    chosen = info.get("protocol") or ""
    if ok and chosen in fake_protocols:
        return make_result(
            "T09",
            "Subprotocol allowlist",
            "Protocol",
            "fail",
            "high",
            f"The server accepted a suspicious client-supplied subprotocol: {chosen}.",
            evidence=[f"Offered protocols: {', '.join(fake_protocols)}"],
            remediation="Accept only known, intended subprotocols. Reject or ignore arbitrary client-supplied subprotocol names.",
        )
    evidence = [f"Connection with fake subprotocols accepted: {ok}", f"Selected protocol: {chosen or '(none)'}"]
    return make_result("T09", "Subprotocol allowlist", "Protocol", "pass", "info", "The server did not select any suspicious subprotocol.", evidence=evidence)


def test_compression(url: str, config: ScanConfig) -> Dict[str, Any]:
    ok, info = connect_probe(url, config, extensions="permessage-deflate; client_max_window_bits")
    if not ok:
        return make_result("T10", "Compression negotiation", "Protocol", "info", "info", "Compression could not be assessed because the handshake failed.", evidence=[info.get("error", "")])
    ext = info.get("extensions") or ""
    lowered = ext.lower()
    if "permessage-deflate" not in lowered:
        return make_result("T10", "Compression negotiation", "Protocol", "pass", "info", "permessage-deflate was not negotiated.", evidence=[f"Extensions: {ext or '(none)'}"])
    if "no_context_takeover" in lowered:
        return make_result("T10", "Compression negotiation", "Protocol", "pass", "info", "permessage-deflate is enabled with context takeover disabled.", evidence=[f"Extensions: {ext}"])
    return make_result(
        "T10",
        "Compression negotiation",
        "Protocol",
        "warning",
        "low",
        "permessage-deflate is enabled without no_context_takeover.",
        evidence=[f"Extensions: {ext}"],
        remediation="Enable client_no_context_takeover and server_no_context_takeover, and enforce a maximum decompressed message size.",
    )


def test_version_downgrade(url: str, config: ScanConfig) -> Dict[str, Any]:
    accepted = []
    evidence = []
    for version in ["8", "7", "0"]:
        ok, info = connect_probe(url, config, version=version)
        status = info.get("status")
        evidence.append(f"Version {version}: {'accepted' if ok else 'rejected'} (HTTP {status})")
        if ok:
            accepted.append(version)
    if accepted:
        return make_result(
            "T11",
            "Protocol version downgrade",
            "Protocol",
            "fail",
            "medium",
            "The server accepted an obsolete WebSocket protocol version.",
            evidence=evidence,
            remediation="Accept only RFC 6455 WebSocket version 13.",
        )
    return make_result("T11", "Protocol version downgrade", "Protocol", "pass", "info", "Obsolete WebSocket protocol versions were rejected.", evidence=evidence)


def test_header_disclosure(url: str, config: ScanConfig) -> Dict[str, Any]:
    ok, info = connect_probe(url, config)
    headers = info.get("headers") or {}
    interesting = []
    for name in ["server", "x-powered-by", "via", "x-aspnet-version", "x-runtime", "x-generator"]:
        if name in headers:
            interesting.append(f"{name}: {headers[name]}")
    version_leaks = [item for item in interesting if re.search(r"\d+\.\d+", item)]
    if version_leaks:
        return make_result(
            "T12",
            "Upgrade header disclosure",
            "Information disclosure",
            "warning",
            "low",
            "The upgrade response exposes server or framework version details.",
            evidence=interesting,
            remediation="Remove unnecessary version headers at the reverse proxy or application layer.",
        )
    if interesting:
        return make_result("T12", "Upgrade header disclosure", "Information disclosure", "info", "info", "The upgrade response exposes generic server headers.", evidence=interesting)
    if ok:
        return make_result("T12", "Upgrade header disclosure", "Information disclosure", "pass", "info", "No notable server disclosure headers were observed.")
    return make_result("T12", "Upgrade header disclosure", "Information disclosure", "info", "info", "Header disclosure could not be assessed because the handshake failed.", evidence=[info.get("error", "")])


SUSPICIOUS_PATTERNS = [
    (re.compile(r"at\s+\w+\s*\(", re.I), "JavaScript stack trace"),
    (re.compile(r"Traceback|File \".*\.py\"", re.I), "Python traceback"),
    (re.compile(r"java\.lang\.|NullPointerException", re.I), "Java exception"),
    (re.compile(r"SQL syntax|mysql|postgres|sqlite|database error", re.I), "database error"),
    (re.compile(r"/home/|/var/|C:\\Users\\", re.I), "filesystem path"),
    (re.compile(r"mongodb://|redis://|amqp://", re.I), "internal connection string"),
    (re.compile(r"password|secret|private_key|access_key", re.I), "secret keyword"),
    (re.compile(r"root:.*:0:0", re.I), "passwd file content"),
]


def find_suspicious_response(text: str) -> Optional[str]:
    for pattern, label in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            return label
    return None


def test_malformed(url: str, config: ScanConfig) -> Dict[str, Any]:
    payloads: List[Tuple[str, Any, bool]] = [
        ("empty string", "", False),
        ("incomplete JSON", '{"action": ', False),
        ("null bytes", "\x00\x00\x00", False),
        ("JSON array root", "[1,2,3]", False),
        ("unicode controls", "\x00\x01\x02\x1f", False),
        ("binary frame", bytes([0, 1, 2, 255, 254, 128, 127]), True),
    ]
    evidence = []
    suspicious = []
    for label, payload, binary in payloads:
        result = try_send_receive(url, config, payload, binary=binary, receive_timeout=2.0)
        if not result["connected"]:
            evidence.append(f"{label}: connection/probe failed ({result.get('error')})")
            continue
        response = result.get("response")
        if response:
            marker = find_suspicious_response(response)
            evidence.append(f"{label}: response '{response[:100]}'")
            if marker:
                suspicious.append(f"{label}: {marker}")
        elif result.get("open_after_send"):
            evidence.append(f"{label}: no response, connection stayed open")
        else:
            evidence.append(f"{label}: connection closed")
    if suspicious:
        return make_result(
            "T13",
            "Malformed data handling",
            "Input validation",
            "fail",
            "medium",
            "Malformed input triggered suspicious error disclosure.",
            evidence=evidence,
            remediation="Validate message schemas and return generic error responses. Do not expose parser exceptions or stack traces.",
        )
    return make_result("T13", "Malformed data handling", "Input validation", "pass", "info", "Malformed payloads did not trigger obvious sensitive error disclosure.", evidence=evidence)


def test_injection_responses(url: str, config: ScanConfig) -> Dict[str, Any]:
    payloads = [
        ("SQL injection", "' OR '1'='1'; DROP TABLE users;--"),
        ("Command injection", "$(id); `whoami`; | cat /etc/passwd"),
        ("NoSQL injection", json.dumps({"$where": "this.admin == true"})),
        ("Prototype pollution", json.dumps({"__proto__": {"admin": True}, "isAdmin": True})),
        ("Path traversal", "../../../../etc/passwd"),
        ("LDAP injection", "*)(uid=*))(|(uid=*"),
        ("XSS script", '<script>alert("xss")</script>'),
        ("Template injection", "{{7*7}}${7*7}<%= 7*7 %>"),
    ]
    evidence = []
    suspicious = []
    for label, payload in payloads:
        result = try_send_receive(url, config, payload, receive_timeout=2.5)
        response = result.get("response")
        if response:
            marker = find_suspicious_response(response)
            if marker or "49" in response and "Template" in label:
                suspicious.append(f"{label}: {marker or 'template expression behavior'}")
                evidence.append(f"{label}: suspicious response '{response[:120]}'")
            else:
                evidence.append(f"{label}: non-suspicious response")
        elif result.get("connected"):
            evidence.append(f"{label}: no response")
        else:
            evidence.append(f"{label}: probe failed ({result.get('error')})")
    if suspicious:
        return make_result(
            "T14",
            "Injection payload response",
            "Input validation",
            "fail",
            "high",
            "Injection-style payloads triggered suspicious responses.",
            evidence=evidence,
            remediation="Strictly validate WebSocket message schemas. Avoid passing message fields into SQL, shell commands, template engines, or object merge functions without safe APIs.",
        )
    return make_result("T14", "Injection payload response", "Input validation", "pass", "info", "Injection-style payloads did not produce obvious sensitive responses.", evidence=evidence)


def test_error_disclosure(url: str, config: ScanConfig) -> Dict[str, Any]:
    payloads = [
        json.dumps({"action": "__nonexistent_action_ws_scan__", "id": 99999}),
        json.dumps({"method": "INVALID", "params": {"null": None}}),
        "TRIGGER_ERROR_WS_SCAN_12345",
        json.dumps({"type": None, "extra": "\x00" * 20}),
    ]
    evidence = []
    hits = []
    for payload in payloads:
        result = try_send_receive(url, config, payload, receive_timeout=2.5)
        response = result.get("response")
        if response:
            marker = find_suspicious_response(response)
            evidence.append(f"Response: {response[:140]}")
            if marker:
                hits.append(marker)
        elif result.get("connected"):
            evidence.append("No response")
        else:
            evidence.append(f"Probe failed: {result.get('error')}")
    if hits:
        return make_result(
            "T15",
            "Verbose error disclosure",
            "Information disclosure",
            "fail",
            "medium",
            "Error probes exposed internal implementation details.",
            evidence=evidence,
            remediation="Catch all WebSocket handler exceptions and return generic structured errors without stack traces, file paths, or secrets.",
        )
    return make_result("T15", "Verbose error disclosure", "Information disclosure", "pass", "info", "Error probes did not expose obvious internal details.", evidence=evidence)


def test_large_payload(url: str, config: ScanConfig) -> Dict[str, Any]:
    sizes = [10 * 1024, 100 * 1024, 1024 * 1024]
    evidence = []
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    try:
        ws.connect()
        for size in sizes:
            label = f"{size // 1024} KB"
            try:
                ws.send_text("A" * size)
                frame = ws.receive(1.5)
                if frame and frame.opcode == 0x8:
                    evidence.append(f"{label}: server closed connection")
                    ws.close()
                    return make_result("T16", "Large message limit", "Denial of service", "pass", "info", "The server closed the connection during large payload testing.", evidence=evidence)
                if frame and frame.opcode in {0x1, 0x2}:
                    evidence.append(f"{label}: server responded")
                else:
                    evidence.append(f"{label}: no response, connection stayed open")
            except Exception as exc:
                evidence.append(f"{label}: send failed ({exc})")
                ws.close()
                return make_result("T16", "Large message limit", "Denial of service", "pass", "info", "The server rejected a large payload.", evidence=evidence)
        ws.close()
        return make_result(
            "T16",
            "Large message limit",
            "Denial of service",
            "warning",
            "medium",
            "No message size limit was observed up to 1 MB.",
            evidence=evidence,
            remediation="Set a maximum incoming message size appropriate for the application, often 64 KB to 1 MB.",
        )
    except Exception as exc:
        ws.close()
        return make_result("T16", "Large message limit", "Denial of service", "info", "info", "Large payload testing could not run because connection failed.", evidence=[str(exc)])


def test_rate_limit(url: str, config: ScanConfig) -> Dict[str, Any]:
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    count = 100
    try:
        ws.connect()
        sent = 0
        for index in range(count):
            try:
                ws.send_text(json.dumps({"type": "ping", "seq": index}))
                sent += 1
            except Exception:
                break
        received = 0
        deadline = time.time() + 3.0
        closed = False
        while time.time() < deadline:
            frame = ws.receive(0.25)
            if frame is None:
                continue
            if frame.opcode == 0x8:
                closed = True
                break
            if frame.opcode in {0x1, 0x2}:
                received += 1
        ws.close()
        evidence = [f"Sent messages: {sent}", f"Received responses: {received}", f"Connection closed by server: {closed}"]
        if closed:
            return make_result("T17", "Message flood handling", "Denial of service", "pass", "info", "The server closed the connection during rapid message testing.", evidence=evidence)
        if received > 0:
            return make_result(
                "T17",
                "Message flood handling",
                "Denial of service",
                "warning",
                "medium",
                "No observable rate limiting occurred during rapid message testing.",
                evidence=evidence,
                remediation="Add per-connection and per-user message rate limits with throttling or disconnect behavior.",
            )
        return make_result("T17", "Message flood handling", "Denial of service", "info", "info", "The server stayed open but did not respond, so rate limiting could not be confirmed from client behavior.", evidence=evidence)
    except Exception as exc:
        ws.close()
        return make_result("T17", "Message flood handling", "Denial of service", "info", "info", "Message flood testing could not run because connection failed.", evidence=[str(exc)])


def open_connection_for_limit(url: str, config: ScanConfig) -> Optional[RawWebSocket]:
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    try:
        ws.connect()
        return ws
    except Exception:
        ws.close()
        return None


def test_connection_limit(url: str, config: ScanConfig) -> Dict[str, Any]:
    attempts = 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=attempts) as pool:
        sockets = list(pool.map(lambda _: open_connection_for_limit(url, config), range(attempts)))
    opened = [ws for ws in sockets if ws is not None]
    for ws in opened:
        ws.close()
    evidence = [f"Successful simultaneous connections: {len(opened)} of {attempts}"]
    if len(opened) == attempts:
        return make_result(
            "T18",
            "Connection limit",
            "Denial of service",
            "warning",
            "medium",
            "The server accepted all simultaneous connection attempts.",
            evidence=evidence,
            remediation="Enforce per-IP and per-account WebSocket connection limits at the reverse proxy or application layer.",
        )
    if len(opened) >= attempts // 2:
        return make_result("T18", "Connection limit", "Denial of service", "warning", "low", "The server accepted many simultaneous connection attempts.", evidence=evidence)
    return make_result("T18", "Connection limit", "Denial of service", "pass", "info", "The server limited simultaneous connection attempts.", evidence=evidence)


def test_idle_timeout(url: str, config: ScanConfig) -> Dict[str, Any]:
    ws = RawWebSocket(url, timeout=config.timeout, verify_tls=config.verify_tls)
    try:
        ws.connect()
        frame = ws.receive(config.idle_seconds)
        ws.close()
        if frame and frame.opcode == 0x8:
            return make_result("T19", "Idle connection timeout", "Connection management", "pass", "info", "The server closed an idle connection during the test window.", evidence=[f"Close code: {frame.close_code}"])
        return make_result(
            "T19",
            "Idle connection timeout",
            "Connection management",
            "warning",
            "low",
            f"The server kept an idle connection open for {config.idle_seconds} seconds.",
            evidence=["Short test window only; production idle timeout may be longer."],
            remediation="Use ping/pong heartbeats and close idle or dead connections after a defined timeout.",
        )
    except Exception as exc:
        ws.close()
        return make_result("T19", "Idle connection timeout", "Connection management", "info", "info", "Idle timeout testing could not run because connection failed.", evidence=[str(exc)])


def test_replay_probe(url: str, config: ScanConfig) -> Dict[str, Any]:
    message = json.dumps({"type": "ping", "id": "replay_probe_ws_scan"})
    first = try_send_receive(url, config, message, receive_timeout=2.5)
    time.sleep(0.4)
    second = try_send_receive(url, config, message, receive_timeout=2.5)
    evidence = [
        f"First response: {str(first.get('response'))[:120] if first.get('response') else '(none)'}",
        f"Replay response: {str(second.get('response'))[:120] if second.get('response') else '(none)'}",
    ]
    if first.get("response") and second.get("response") and first.get("response") == second.get("response"):
        return make_result(
            "T20",
            "Generic replay probe",
            "Authentication",
            "info",
            "info",
            "The same generic message produced the same response across two connections.",
            evidence=evidence,
            remediation="For state-changing WebSocket operations, require nonces or sequence numbers and reject duplicates.",
        )
    return make_result("T20", "Generic replay probe", "Authentication", "info", "info", "Replay impact could not be determined with a generic probe.", evidence=evidence)


TESTS = [
    test_transport,
    test_tls,
    test_handshake,
    lambda url, config: test_origin(url, config, "https://evil-attacker.example", "T04", "CSWSH origin validation", "high"),
    lambda url, config: test_origin(url, config, "null", "T05", "Null origin handling", "medium"),
    lambda url, config: test_origin(url, config, suffix_origin(url), "T06", "Origin suffix bypass", "high"),
    test_unauthenticated,
    test_url_secrets,
    test_subprotocol,
    test_compression,
    test_version_downgrade,
    test_header_disclosure,
    test_malformed,
    test_injection_responses,
    test_error_disclosure,
    test_large_payload,
    test_rate_limit,
    test_connection_limit,
    test_idle_timeout,
    test_replay_probe,
]


def suffix_origin(url: str) -> str:
    try:
        host = parse_ws_url(url)["host"]
    except Exception:
        host = "target.example"
    return f"https://{host}.evil-attacker.example"


def run_scan(url: str, config: ScanConfig) -> Dict[str, Any]:
    start = time.time()
    results = []
    normalized = url.strip()
    try:
        parse_ws_url(normalized)
    except Exception as exc:
        return {
            "target": normalized,
            "durationSeconds": 0,
            "results": [make_result("T00", "URL validation", "Input", "error", "info", str(exc))],
            "summary": {"pass": 0, "fail": 0, "warning": 0, "info": 0, "error": 1},
            "excluded": excluded_checks(),
        }

    for test in TESTS:
        test_start = time.time()
        try:
            result = test(normalized, config)
        except Exception as exc:
            result = make_result("ERR", getattr(test, "__name__", "test"), "Scanner", "error", "info", "The scanner hit an unexpected error.", evidence=[str(exc)])
        result["durationMs"] = int((time.time() - test_start) * 1000)
        results.append(result)

    summary = {"pass": 0, "fail": 0, "warning": 0, "info": 0, "error": 0}
    for result in results:
        summary[result["status"]] = summary.get(result["status"], 0) + 1
    return {
        "target": normalized,
        "durationSeconds": round(time.time() - start, 2),
        "results": results,
        "summary": summary,
        "excluded": excluded_checks(),
    }


def excluded_checks() -> List[str]:
    return [
        "IDOR via application object identifiers",
        "Broken authorization for real actions, roles, channels, and tenants",
        "Tenant isolation bypass",
        "Unauthorized admin channel access",
        "Workflow bypass and business logic flaws",
        "Socket.IO namespace discovery that requires application context",
        "GraphQL subscription authorization and schema enumeration",
    ]


class ScannerRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "LocalWebSocketScanner/1.0"

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self.send_file("index.html", "text/html; charset=utf-8")
            return
        if self.path == "/health":
            self.send_json({"ok": True})
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self.send_error(404, "Not found")
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length > MAX_REQUEST_BYTES:
                self.send_error(413, "Request too large")
                return
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            url = str(payload.get("url", "")).strip()
            authorized = bool(payload.get("authorized"))
            if not authorized:
                self.send_json({"error": "Confirm that you are authorized to test this endpoint."}, status=400)
                return
            idle = int(payload.get("idleSeconds", DEFAULT_IDLE_SECONDS))
            idle = min(max(idle, 5), 30)
            config = ScanConfig(
                verify_tls=bool(payload.get("verifyTls", True)),
                timeout=float(payload.get("timeout", DEFAULT_TIMEOUT)),
                idle_seconds=idle,
            )
            self.send_json(run_scan(url, config))
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=500)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def send_file(self, filename: str, content_type: str) -> None:
        root = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(root, filename)
        if not os.path.exists(path):
            self.send_error(404, "File not found")
            return
        with open(path, "rb") as handle:
            data = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), ScannerRequestHandler)
    actual_host, actual_port = server.server_address
    print(f"WebSocket security scanner running at http://{actual_host}:{actual_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping scanner.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local WebSocket misconfiguration scanner")
    parser.add_argument("--serve", action="store_true", help="start the local HTML/API server")
    parser.add_argument("--host", default="127.0.0.1", help="server host")
    parser.add_argument("--port", type=int, default=8765, help="server port")
    parser.add_argument("--url", help="scan one WebSocket URL and print JSON")
    parser.add_argument("--no-verify-tls", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE_SECONDS, help="idle timeout test window")
    args = parser.parse_args()

    if args.serve or not args.url:
        serve(args.host, args.port)
        return

    config = ScanConfig(verify_tls=not args.no_verify_tls, idle_seconds=args.idle_seconds)
    print(json.dumps(run_scan(args.url, config), indent=2))


if __name__ == "__main__":
    main()
