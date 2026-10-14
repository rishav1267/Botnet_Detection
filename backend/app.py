"""
NETGUARD IoT Botnet Detection System — Modular Backend Application Server
Connects Configuration, Database, Modular Routes, Middleware, and Static UI.
"""

import os
import sys
import json
import time
import urllib.parse
from pathlib import Path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from http.server import HTTPServer, ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any

from backend.config.settings import settings
from backend.database.connection import db_manager
from backend.routes.api_router import ApiRouter
from backend.middleware.cors import apply_cors_headers
from backend.middleware.security import security_manager
from backend.middleware.logging_middleware import log_request
from backend.middleware.error_handler import handle_exception
from backend.utils.logger import logger


class NetGuardRequestHandler(SimpleHTTPRequestHandler):
    """Production Request Handler integrating API router, middleware, and static asset serving."""

    def __init__(self, *args, directory=None, **kwargs):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        super().__init__(*args, directory=base_dir, **kwargs)

    def _send_json_response(self, status_code: int, data: Any, extra_headers: Dict[str, str] = None):
        """Serialize and transmit JSON response with CORS and hardened security headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))

        # Harden with Security Headers
        sec_headers = security_manager.get_security_headers()
        for k, v in sec_headers.items():
            self.send_header(k, v)

        # Origin-controlled CORS
        cors_headers = {}
        security_manager.apply_cors(cors_headers, self.headers.get("Origin"))
        for k, v in cors_headers.items():
            self.send_header(k, v)

        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)

        self.end_headers()
        self.wfile.write(body)

    def _send_raw_response(self, status_code: int, raw_bytes: bytes, custom_headers: Dict[str, str]):
        """Transmit binary or raw document payload with security and CORS headers."""
        self.send_response(status_code)
        sec_headers = security_manager.get_security_headers()
        for k, v in sec_headers.items():
            self.send_header(k, v)

        cors_headers = {}
        security_manager.apply_cors(cors_headers, self.headers.get("Origin"))
        for k, v in cors_headers.items():
            self.send_header(k, v)

        for k, v in custom_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw_bytes)

    def _parse_body(self) -> Dict[str, Any]:
        """Safely parse incoming JSON request body and sanitize NoSQL operators."""
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            raw = self.rfile.read(content_len).decode("utf-8")
            try:
                parsed = json.loads(raw)
                return security_manager.sanitize_payload(parsed)
            except Exception:
                return {}
        return {}

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests with security headers."""
        self.send_response(204)
        sec_headers = security_manager.get_security_headers()
        for k, v in sec_headers.items():
            self.send_header(k, v)

        headers = {}
        security_manager.apply_cors(headers, self.headers.get("Origin"))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        start_time = time.time()
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Sliding-window rate limit check
        is_allowed, retry_after = security_manager.check_rate_limit(client_ip, path, headers=dict(self.headers))
        if not is_allowed:
            self._send_json_response(
                429,
                {"success": False, "error": "Too Many Requests: Rate limit exceeded. Please back off.", "error_code": "RATE_LIMIT_EXCEEDED", "retry_after": retry_after},
                extra_headers={"Retry-After": str(retry_after)}
            )
            log_request("GET", path, 429, (time.time() - start_time) * 1000, client_ip)
            return

        # Handle Real-time Server-Sent Events (SSE) Stream
        if path == "/api/stream/events":
            from backend.controllers.stream_controller import StreamController
            StreamController.handle_sse(self, query, dict(self.headers))
            return

        # Handle API routes
        if path.startswith("/api/"):
            try:
                status, data, custom_hdrs = ApiRouter.dispatch(
                    method="GET",
                    path=path,
                    query=query,
                    body={},
                    headers=dict(self.headers),
                    client_ip=client_ip
                )
                if custom_hdrs:
                    self._send_raw_response(status, data, custom_hdrs)
                else:
                    self._send_json_response(status, data)
                log_request("GET", path, status, (time.time() - start_time) * 1000, client_ip)
            except Exception as e:
                status, err_body = handle_exception(e)
                self._send_json_response(status, err_body)
                log_request("GET", path, status, (time.time() - start_time) * 1000, client_ip)
            return

        # Serve SPA index.html for root
        if path in ["/", "/index.html"]:
            self.path = "/index.html"
            super().do_GET()
            log_request("GET", path, 200, (time.time() - start_time) * 1000, client_ip)
            return

        # Serve static assets
        super().do_GET()

    def do_POST(self):
        start_time = time.time()
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Sliding-window rate limit check
        is_allowed, retry_after = security_manager.check_rate_limit(client_ip, path, headers=dict(self.headers))
        if not is_allowed:
            self._send_json_response(
                429,
                {"success": False, "error": "Too Many Requests: Rate limit exceeded. Please back off.", "error_code": "RATE_LIMIT_EXCEEDED", "retry_after": retry_after},
                extra_headers={"Retry-After": str(retry_after)}
            )
            log_request("POST", path, 429, (time.time() - start_time) * 1000, client_ip)
            return

        # 2. Request payload size limit check (pre-read inspection)
        content_len = int(self.headers.get("Content-Length", 0))
        size_err = security_manager.validate_request_size(content_len, path)
        if size_err:
            err_code, err_body = size_err
            self._send_json_response(err_code, err_body)
            log_request("POST", path, err_code, (time.time() - start_time) * 1000, client_ip)
            return

        body = self._parse_body()

        if path.startswith("/api/"):
            try:
                status, data, custom_hdrs = ApiRouter.dispatch(
                    method="POST",
                    path=path,
                    query=query,
                    body=body,
                    headers=dict(self.headers),
                    client_ip=client_ip
                )
                if custom_hdrs:
                    self._send_raw_response(status, data, custom_hdrs)
                else:
                    self._send_json_response(status, data)
                log_request("POST", path, status, (time.time() - start_time) * 1000, client_ip)
            except Exception as e:
                status, err_body = handle_exception(e)
                self._send_json_response(status, err_body)
                log_request("POST", path, status, (time.time() - start_time) * 1000, client_ip)
            return

        self._send_json_response(404, {"error": "Endpoint not found"})

    def do_PATCH(self):
        start_time = time.time()
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Sliding-window rate limit check
        is_allowed, retry_after = security_manager.check_rate_limit(client_ip, path, headers=dict(self.headers))
        if not is_allowed:
            self._send_json_response(
                429,
                {"success": False, "error": "Too Many Requests: Rate limit exceeded. Please back off.", "error_code": "RATE_LIMIT_EXCEEDED", "retry_after": retry_after},
                extra_headers={"Retry-After": str(retry_after)}
            )
            log_request("PATCH", path, 429, (time.time() - start_time) * 1000, client_ip)
            return

        # 2. Request payload size limit check
        content_len = int(self.headers.get("Content-Length", 0))
        size_err = security_manager.validate_request_size(content_len, path)
        if size_err:
            err_code, err_body = size_err
            self._send_json_response(err_code, err_body)
            log_request("PATCH", path, err_code, (time.time() - start_time) * 1000, client_ip)
            return

        body = self._parse_body()

        if path.startswith("/api/"):
            try:
                status, data, custom_hdrs = ApiRouter.dispatch(
                    method="PATCH",
                    path=path,
                    query=query,
                    body=body,
                    headers=dict(self.headers),
                    client_ip=client_ip
                )
                if custom_hdrs:
                    self._send_raw_response(status, data, custom_hdrs)
                else:
                    self._send_json_response(status, data)
                log_request("PATCH", path, status, (time.time() - start_time) * 1000, client_ip)
            except Exception as e:
                status, err_body = handle_exception(e)
                self._send_json_response(status, err_body)
                log_request("PATCH", path, status, (time.time() - start_time) * 1000, client_ip)
            return

        self._send_json_response(404, {"error": "Endpoint not found"})

    def do_DELETE(self):
        start_time = time.time()
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Sliding-window rate limit check
        is_allowed, retry_after = security_manager.check_rate_limit(client_ip, path, headers=dict(self.headers))
        if not is_allowed:
            self._send_json_response(
                429,
                {"success": False, "error": "Too Many Requests: Rate limit exceeded. Please back off.", "error_code": "RATE_LIMIT_EXCEEDED", "retry_after": retry_after},
                extra_headers={"Retry-After": str(retry_after)}
            )
            log_request("DELETE", path, 429, (time.time() - start_time) * 1000, client_ip)
            return

        body = self._parse_body()

        if path.startswith("/api/"):
            try:
                status, data, custom_hdrs = ApiRouter.dispatch(
                    method="DELETE",
                    path=path,
                    query=query,
                    body=body,
                    headers=dict(self.headers),
                    client_ip=client_ip
                )
                if custom_hdrs:
                    self._send_raw_response(status, data, custom_hdrs)
                else:
                    self._send_json_response(status, data)
                log_request("DELETE", path, status, (time.time() - start_time) * 1000, client_ip)
            except Exception as e:
                status, err_body = handle_exception(e)
                self._send_json_response(status, err_body)
                log_request("DELETE", path, status, (time.time() - start_time) * 1000, client_ip)
            return

        self._send_json_response(404, {"error": "Endpoint not found"})


class ThreadedNetGuardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def create_server(host: str = None, port: int = None) -> ThreadedNetGuardServer:
    """Initialize database and build production ThreadedNetGuardServer."""
    server_host = host or settings.HOST
    server_port = port or settings.PORT

    logger.info("=" * 68)
    logger.info(" NETGUARD IoT Botnet Detection & Cybersecurity System")
    logger.info(f" Environment : {settings.NODE_ENV.upper()}")
    logger.info(f" Host / Port : {server_host}:{server_port}")
    logger.info("=" * 68)

    # Initialize Database Connection
    db_manager.connect()

    server = ThreadedNetGuardServer((server_host, server_port), NetGuardRequestHandler)
    return server


def run_server(port: int = None):
    """Run server entry point with graceful shutdown."""
    target_port = port or settings.PORT
    server = create_server(port=target_port)
    logger.info(f"[Server] Operational and listening on http://{settings.HOST}:{target_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[Server] Shutting down gracefully...")
        db_manager.close()
        server.server_close()


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else settings.PORT
    run_server(p)
