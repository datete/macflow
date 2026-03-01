"""Simple HTTP reverse proxy: runs on Windows, proxies to iStoreOS VM via WSL subprocess."""
import http.server
import subprocess
import sys
import json
import threading


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    ROUTES = {
        "/luci": ("8080", "/"),
        "/api": ("18080", "/api"),
    }

    def do_request(self):
        port = "18080"
        path = self.path

        if self.path.startswith("/luci"):
            port = "8080"
            path = self.path[5:] or "/"
        elif self.path.startswith("/api") or self.path.startswith("/assets"):
            port = "18080"

        if self.path == "/" or self.path == "":
            port = "18080"
            path = "/"

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        curl_cmd = f"curl -s -w '\\n%{{http_code}}' -X {self.command} "
        for h in ["Content-Type", "Accept"]:
            val = self.headers.get(h)
            if val:
                curl_cmd += f"-H '{h}: {val}' "
        if body:
            curl_cmd += f"-d '{body.decode()}' "
        curl_cmd += f"http://127.0.0.1:{port}{path}"

        try:
            result = subprocess.run(
                ["wsl", "-d", "Ubuntu", "--", "bash", "-c", curl_cmd],
                capture_output=True, timeout=15
            )
            output = result.stdout
            lines = output.rsplit(b"\n", 1)
            if len(lines) == 2:
                resp_body = lines[0]
                status = int(lines[1].strip()) if lines[1].strip().isdigit() else 200
            else:
                resp_body = output
                status = 200

            self.send_response(status)
            if resp_body.strip().startswith(b"{") or resp_body.strip().startswith(b"["):
                self.send_header("Content-Type", "application/json")
            elif b"<html" in resp_body.lower() or b"<!doctype" in resp_body.lower():
                self.send_header("Content-Type", "text/html; charset=utf-8")
            else:
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            self.send_response(502)
            msg = f"proxy error: {e}".encode()
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def do_GET(self):
        self.do_request()

    def do_POST(self):
        self.do_request()

    def do_PUT(self):
        self.do_request()

    def do_DELETE(self):
        self.do_request()

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  {args[0]}\n")


def main():
    port = 8888
    print(f"iStoreOS Proxy running on http://localhost:{port}")
    print(f"  /        -> macflow Panel")
    print(f"  /luci/   -> iStoreOS LuCI")
    print(f"  /api/    -> macflow API")
    print(f"  Ctrl+C to stop")

    server = http.server.HTTPServer(("127.0.0.1", port), ProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
        server.shutdown()


if __name__ == "__main__":
    main()
