"""LuCI proxy: Windows :9080 -> WSL curl -> QEMU :8080 -> iStoreOS :80"""
import http.server
import subprocess
import sys
import tempfile
import os

PORT = 9080
TARGET = "http://127.0.0.1:8080"


class Proxy(http.server.BaseHTTPRequestHandler):
    def _do(self):
        clen = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(clen) if clen > 0 else None

        curl = f"curl -s -i -X {self.command}"
        for k in self.headers:
            v = self.headers[k]
            if k.lower() not in ("host", "connection", "content-length",
                                  "transfer-encoding", "accept-encoding"):
                curl += f" -H '{k}: {v}'"

        if body:
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".dat")
            tf.write(body)
            tf.close()
            wpath = tf.name.replace("\\", "/")
            if len(wpath) > 2 and wpath[1] == ":":
                wpath = f"/mnt/{wpath[0].lower()}/{wpath[3:]}"
            curl += f" --data-binary @{wpath}"
        else:
            tf = None

        curl += f" '{TARGET}{self.path}'"

        try:
            r = subprocess.run(
                ["wsl", "-e", "bash", "-c", curl],
                capture_output=True, timeout=30
            )
            raw = r.stdout
        except Exception as e:
            self.send_error(502, str(e))
            return
        finally:
            if tf:
                try:
                    os.unlink(tf.name)
                except Exception:
                    pass

        sep = raw.find(b"\r\n\r\n")
        slen = 4
        if sep == -1:
            sep = raw.find(b"\n\n")
            slen = 2
        if sep == -1:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        hdr = raw[:sep].decode("utf-8", errors="replace")
        body_out = raw[sep + slen:]

        lines = hdr.split("\n")
        try:
            code = int(lines[0].split()[1])
        except Exception:
            code = 200

        self.send_response(code)
        for ln in lines[1:]:
            ln = ln.strip()
            if ":" not in ln or not ln:
                continue
            k, v = ln.split(":", 1)
            kl = k.strip().lower()
            if kl in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k.strip(), v.strip())
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_HEAD = _do

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"LuCI proxy: http://localhost:{PORT}")
    print(f"Target: {TARGET} (via WSL)")
    print("Login: root / password")
    s = http.server.HTTPServer(("127.0.0.1", PORT), Proxy)
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        s.shutdown()
