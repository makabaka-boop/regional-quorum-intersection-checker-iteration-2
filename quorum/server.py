"""通过 HTTP 接收仲裁分析请求的 quorum 服务。"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .analyzer import ValidationError, analyze


def _json_response(
    handler: BaseHTTPRequestHandler,
    status: HTTPStatus,
    payload: dict[str, Any],
) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class QuorumHandler(BaseHTTPRequestHandler):
    server_version = "quorum-analyzer/1.0"

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        _json_response(self, status, {"error": message})

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path != "/health":
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        _json_response(self, HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        if self.path != "/analyze":
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise ValueError
        except ValueError:
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
            return

        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_error(HTTPStatus.BAD_REQUEST, "request body must be JSON")
            return

        try:
            result = analyze(payload)
        except ValidationError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        _json_response(self, HTTPStatus.OK, result)

    def log_message(self, format: str, *args: object) -> None:
        # 测试与容器日志中保留默认访问日志即可。
        super().log_message(format, *args)


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), QuorumHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the quorum analyzer HTTP service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    server = build_server(args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
